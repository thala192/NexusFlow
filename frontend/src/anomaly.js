
// Anomaly / threat heuristics, client-side, fed every packet — same shape as
// FlowTracker and DnsTracker (add(p) -> event|null, tick(now) -> events[]).
//
// Every detector here works off data the backend already sends (src/dst,
// ports, flags, dns_qname, smac/dmac) — nothing new from the wire. Detection
// is heuristic and meant for an analyst's eye, not a SOC alert pipeline:
// thresholds favor a low false-positive rate on demo/home traffic over
// catching the stealthiest real attacker.

const SCAN_WINDOW = 8;        // sec: distinct ports/hosts counted within this window
const SCAN_PORT_THRESHOLD = 4;   // distinct dst ports from one src -> port scan
const SCAN_HOST_THRESHOLD = 8;   // distinct dst hosts from one src on one port -> sweep
const SCAN_CAP = 400;          // tracked source IPs for scan detection

const BEACON_MIN_SAMPLES = 5;     // connections to a target before judging periodicity
const BEACON_MAX_JITTER = 0.12;   // stdev/mean ratio below this reads as "too regular"
const BEACON_MIN_INTERVAL = 5;    // sec: ignore chatty/keepalive-fast pairs
const BEACON_MAX_INTERVAL = 3600; // sec: ignore once-a-day-or-rarer pairs (too little signal)
const BEACON_CAP = 600;

const DNS_LEN_THRESHOLD = 45;    // chars: longer than typical hostnames
const DNS_ENTROPY_THRESHOLD = 3.6; // bits/char: random-looking subdomains tunnel data
const DNS_RATE_WINDOW = 20;      // sec
const DNS_RATE_THRESHOLD = 25;   // distinct subdomain queries to one apex domain in window
const DNS_CAP = 300;

const SYNFLOOD_WINDOW = 5;       // sec
const SYNFLOOD_SRC_THRESHOLD = 25;  // distinct source IPs SYNing one local target
const SYNFLOOD_PPS_THRESHOLD = 40;  // raw inbound SYN rate, regardless of src diversity

const ARP_CAP = 500;
const REPEAT_SUPPRESS = 25; // sec: don't re-fire the same kind+target repeatedly

/** First three octets of an IPv4 address ("a.b.c"), or null for anything
 *  else (IPv6, malformed) — used to scope sweep detection to one /24 so it
 *  can't fire on ordinary browsing across many unrelated public hosts. */
function subnetOf(ip) {
  if (typeof ip !== 'string') return null;
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  return parts.slice(0, 3).join('.');
}

function evictOldest(map, cap) {
  if (map.size >= cap) map.delete(map.keys().next().value);
}

/** Shannon entropy in bits/char — high for random/base32/hex-looking strings. */
function entropy(str) {
  if (!str) return 0;
  const counts = new Map();
  for (const ch of str) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  const n = str.length;
  let h = 0;
  for (const c of counts.values()) {
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Strip the registrable-ish suffix so we score the *label*, not the TLD. */
function leafLabel(qname) {
  if (!qname) return '';
  const parts = qname.split('.');
  return parts.length > 2 ? parts.slice(0, -2).join('.') : parts[0] ?? '';
}

function apexOf(qname) {
  if (!qname) return qname;
  const parts = qname.split('.');
  return parts.length > 2 ? parts.slice(-2).join('.') : qname;
}

export class AnomalyTracker {
  constructor() {
    this.log = [];                 // recent events for drill-down, newest last
    this.counts = {
      portscan: 0, sweep: 0, beacon: 0, dnstunnel: 0, synflood: 0, arpspoof: 0,
    };
    this._lastSuppress = new Map(); // `${kind}|${target}` -> ts of last fired event
    this.reset();
  }

  reset() {
    this.scanPorts = new Map();   // src -> {firstTs, ports:Set, hosts:Map<port,Set<dst>>}
    this.beaconHist = new Map();  // `${src}>${dst}:${dport}` -> {lastTs, intervals:[]}
    this.dnsHist = new Map();     // apex -> {firstTs, labels:Set, lastWarn}
    this.synSrcs = new Map();     // dst -> {firstTs, srcs:Set, count}
    this.arpSeen = new Map();     // ip -> {mac, ts}
    this._lastSuppress.clear();
    this.log.length = 0;
    this.counts = {
      portscan: 0, sweep: 0, beacon: 0, dnstunnel: 0, synflood: 0, arpspoof: 0,
    };
  }

  pushLog(kind, severity, target, extra = '') {
    this.log.push({ kind, severity, target, extra, ts: this._lastTs ?? 0 });
    if (this.log.length > 120) this.log.shift();
  }

  /** True if this kind+target fired recently — stops one ongoing pattern
   *  from spamming a new siren every single packet. */
  suppressed(kind, target, now) {
    const key = `${kind}|${target}`;
    const last = this._lastSuppress.get(key);
    if (last !== undefined && now - last < REPEAT_SUPPRESS) return true;
    this._lastSuppress.set(key, now);
    return false;
  }

  recent(kind) {
    const grouped = new Map();
    for (const e of this.log) {
      if (e.kind !== kind) continue;
      const g = grouped.get(e.target) ?? { target: e.target, extra: e.extra, count: 0, last: 0 };
      g.count++;
      if (e.ts > g.last) { g.last = e.ts; g.extra = e.extra || g.extra; }
      grouped.set(e.target, g);
    }
    return [...grouped.values()].sort((a, b) => b.last - a.last);
  }

  /** Feed every packet. Returns an array of fired anomaly events (usually empty). */
  add(p) {
    this._lastTs = p.ts;
    const out = [];
    const arp = this._checkArp(p);
    if (arp) out.push(arp);
    if (p.transport === 'TCP' && p.flags) {
      const scan = this._checkScan(p);
      if (scan) out.push(scan);
      const flood = this._checkSynFlood(p);
      if (flood) out.push(flood);
      const beacon = this._checkBeacon(p);
      if (beacon) out.push(beacon);
    }
    if (p.proto === 'DNS' && p.dns_qr === 0 && p.dns_qname) {
      const tunnel = this._checkDnsTunnel(p);
      if (tunnel) out.push(tunnel);
    }
    return out;
  }

  // ------------------------------------------------------------ port scan
  _checkScan(p) {
    const isSyn = p.flags.includes('S') && !p.flags.includes('A');
    if (!isSyn) return null;
    const src = p.src;
    if (!src) return null;
    let rec = this.scanPorts.get(src);
    if (!rec || p.ts - rec.firstTs > SCAN_WINDOW) {
      evictOldest(this.scanPorts, SCAN_CAP);
      // portsByHost: one destination probed on many ports -> vertical scan
      // hostsByPort: one port probed across many destinations -> sweep
      rec = { firstTs: p.ts, portsByHost: new Map(), hostsByPort: new Map() };
      this.scanPorts.set(src, rec);
    }
    let portSet = rec.portsByHost.get(p.dst);
    if (!portSet) { portSet = new Set(); rec.portsByHost.set(p.dst, portSet); }
    portSet.add(p.dport);
    let hostSet = rec.hostsByPort.get(p.dport);
    if (!hostSet) { hostSet = new Set(); rec.hostsByPort.set(p.dport, hostSet); }
    hostSet.add(p.dst);

    // vertical: many ports on ONE host -> port scan (ordinary browsing
    // touches many hosts each on their normal port, never one host on many)
    if (portSet.size >= SCAN_PORT_THRESHOLD && !this.suppressed('portscan', src, p.ts)) {
      this.counts.portscan++;
      const extra = `${portSet.size} ports on ${p.dst} in ${SCAN_WINDOW}s`;
      this.pushLog('portscan', 'high', src, extra);
      return { kind: 'portscan', severity: 'high', src, target: src, extra, pkt: p };
    }
    // horizontal: one port across many hosts ON THE SAME /24 -> network
    // sweep. Scoped to one subnet so it can't fire on ordinary browsing,
    // which touches many *unrelated* public hosts that happen to share a
    // common server port (443, 80) — that's normal, not a sweep.
    const subnet = subnetOf(p.dst);
    if (subnet) {
      const hs = rec.hostsByPort.get(p.dport);
      const sameSubnetCount = hs ? [...hs].filter((h) => subnetOf(h) === subnet).length : 0;
      if (sameSubnetCount >= SCAN_HOST_THRESHOLD && !this.suppressed('sweep', src, p.ts)) {
        this.counts.sweep++;
        const extra = `port ${p.dport} across ${sameSubnetCount} hosts on ${subnet}.0/24 in ${SCAN_WINDOW}s`;
        this.pushLog('sweep', 'high', src, extra);
        return { kind: 'sweep', severity: 'high', src, target: src, extra, pkt: p };
      }
    }
    return null;
  }

  // ------------------------------------------------------------ SYN flood
  _checkSynFlood(p) {
    const isSyn = p.flags.includes('S') && !p.flags.includes('A');
    if (!isSyn || p.dir !== 'in') return null; // only inbound SYNs at a local target matter here
    const dst = p.dst;
    if (!dst) return null;
    let rec = this.synSrcs.get(dst);
    if (!rec || p.ts - rec.firstTs > SYNFLOOD_WINDOW) {
      rec = { firstTs: p.ts, srcs: new Set(), count: 0 };
      this.synSrcs.set(dst, rec);
    }
    rec.srcs.add(p.src);
    rec.count++;
    const rate = rec.count / Math.max(p.ts - rec.firstTs, 0.5);
    const manySources = rec.srcs.size >= SYNFLOOD_SRC_THRESHOLD;
    const highRate = rate >= SYNFLOOD_PPS_THRESHOLD;
    if ((manySources || highRate) && !this.suppressed('synflood', dst, p.ts)) {
      this.counts.synflood++;
      const extra = manySources
        ? `${rec.srcs.size} distinct sources in ${SYNFLOOD_WINDOW}s`
        : `~${rate.toFixed(0)} SYN/s`;
      this.pushLog('synflood', 'high', dst, extra);
      return { kind: 'synflood', severity: 'high', src: p.src, target: dst, extra, pkt: p };
    }
    return null;
  }

  // ------------------------------------------------------------ beaconing
  _checkBeacon(p) {
    // Judge on the connection-opening SYN only — one sample per attempt,
    // regardless of how many data packets ride inside it.
    if (!(p.flags.includes('S') && !p.flags.includes('A'))) return null;
    if (p.dir !== 'out') return null; // beacons are call-outs from inside
    const key = `${p.src}>${p.dst}:${p.dport}`;
    let rec = this.beaconHist.get(key);
    if (!rec) {
      evictOldest(this.beaconHist, BEACON_CAP);
      rec = { lastTs: p.ts, intervals: [] };
      this.beaconHist.set(key, rec);
      return null;
    }
    const gap = p.ts - rec.lastTs;
    rec.lastTs = p.ts;
    if (gap < BEACON_MIN_INTERVAL || gap > BEACON_MAX_INTERVAL) {
      // one chatty/irregular gap doesn't disprove periodicity elsewhere in
      // the session, but it does mean THIS gap isn't useful evidence
      return null;
    }
    rec.intervals.push(gap);
    if (rec.intervals.length > 12) rec.intervals.shift();
    if (rec.intervals.length < BEACON_MIN_SAMPLES) return null;

    const xs = rec.intervals;
    const mean = xs.reduce((a, b) => a + b, 0) / xs.length;
    const variance = xs.reduce((a, b) => a + (b - mean) ** 2, 0) / xs.length;
    const stdev = Math.sqrt(variance);
    const jitter = mean > 0 ? stdev / mean : 1;
    if (jitter <= BEACON_MAX_JITTER && !this.suppressed('beacon', key, p.ts)) {
      this.counts.beacon++;
      const extra = `every ~${mean.toFixed(0)}s, ±${(jitter * 100).toFixed(0)}% jitter, ${xs.length} samples`;
      this.pushLog('beacon', 'medium', `${p.src} → ${p.dst}:${p.dport}`, extra);
      return { kind: 'beacon', severity: 'medium', src: p.src, target: `${p.dst}:${p.dport}`, extra, pkt: p };
    }
    return null;
  }

  // ------------------------------------------------------------ DNS tunneling
  _checkDnsTunnel(p) {
    const qname = p.dns_qname;
    const label = leafLabel(qname);
    const ent = entropy(label);
    const long = label.length >= DNS_LEN_THRESHOLD;
    const random = label.length >= 16 && ent >= DNS_ENTROPY_THRESHOLD;

    // rate signal: many distinct subdomain labels under one apex in a short
    // window reads as data being smuggled out one label at a time
    const apex = apexOf(qname);
    let rec = this.dnsHist.get(apex);
    if (!rec || p.ts - rec.firstTs > DNS_RATE_WINDOW) {
      evictOldest(this.dnsHist, DNS_CAP);
      rec = { firstTs: p.ts, labels: new Set() };
      this.dnsHist.set(apex, rec);
    }
    rec.labels.add(label);
    const burst = rec.labels.size >= DNS_RATE_THRESHOLD;

    if (!long && !random && !burst) return null;
    if (this.suppressed('dnstunnel', apex, p.ts)) return null;

    this.counts.dnstunnel++;
    const reasons = [];
    if (long) reasons.push(`${label.length}-char label`);
    if (random) reasons.push(`high entropy (${ent.toFixed(1)} bits/char)`);
    if (burst) reasons.push(`${rec.labels.size} distinct subdomains in ${DNS_RATE_WINDOW}s`);
    const extra = reasons.join(' · ');
    this.pushLog('dnstunnel', 'medium', apex || qname, extra);
    return { kind: 'dnstunnel', severity: 'medium', src: p.src, target: apex || qname, extra, pkt: p };
  }

  // ------------------------------------------------------------ ARP spoofing
  _checkArp(p) {
    if (p.transport !== 'ARP' || !p.src || !p.smac) return null;
    const prev = this.arpSeen.get(p.src);
    if (prev && prev.mac !== p.smac) {
      evictOldest(this.arpSeen, ARP_CAP);
      this.arpSeen.set(p.src, { mac: p.smac, ts: p.ts });
      if (this.suppressed('arpspoof', p.src, p.ts)) return null;
      this.counts.arpspoof++;
      const extra = `${prev.mac} → ${p.smac}`;
      this.pushLog('arpspoof', 'high', p.src, extra);
      return { kind: 'arpspoof', severity: 'high', src: p.src, target: p.src, extra, pkt: p };
    }
    evictOldest(this.arpSeen, ARP_CAP);
    this.arpSeen.set(p.src, { mac: p.smac, ts: p.ts });
    return null;
  }

  /** Time-based work: currently none of these detectors need expiry beyond
   *  their rolling windows (handled lazily on the next matching packet), but
   *  stale map entries are pruned here so idle sessions don't grow forever. */
  tick(now) {
    for (const [k, rec] of this.scanPorts) {
      if (now - rec.firstTs > SCAN_WINDOW * 4) this.scanPorts.delete(k);
    }
    for (const [k, rec] of this.synSrcs) {
      if (now - rec.firstTs > SYNFLOOD_WINDOW * 4) this.synSrcs.delete(k);
    }
    for (const [k, rec] of this.dnsHist) {
      if (now - rec.firstTs > DNS_RATE_WINDOW * 4) this.dnsHist.delete(k);
    }
    return [];
  }

  get totalCount() {
    const c = this.counts;
    return c.portscan + c.sweep + c.beacon + c.dnstunnel + c.synflood + c.arpspoof;
  }
}
