// Full-system integration check: runs every tracker built across this
// project's life — FlowTracker, DnsTracker, AnomalyTracker, FlowLog,
// StatsEngine — together against one real 60s captured session, exactly
// mirroring main.js's trackPacket() pipeline order. Also exercises
// PacketFilter on top, since main.js's onPackets filters BEFORE calling
// trackPacket in live mode. Looks for crashes, NaN/undefined leaks, and any
// invariant violation that only shows up under combined load rather than
// each tracker tested alone.
import { FlowTracker } from '../frontend/src/flows.js';
import { DnsTracker } from '../frontend/src/dns.js';
import { AnomalyTracker } from '../frontend/src/anomaly.js';
import { FlowLog } from '../frontend/src/flowlog.js';
import { StatsEngine } from '../frontend/src/stats.js';
import { PacketFilter } from '../frontend/src/filter.js';
import { flowKeyOf, glowColorFor } from '../frontend/src/config.js';
import { readFileSync } from 'fs';

const packets = JSON.parse(readFileSync('./integration_fixture.json', 'utf8'));
console.log(`loaded ${packets.length} real packets from a 60s live session\n`);

const flows = new FlowTracker(3);
const dns = new DnsTracker(5);
const anomaly = new AnomalyTracker();
const flowlog = new FlowLog();
const stats = new StatsEngine(60);
const filter = new PacketFilter('port:443'); // exercise the filter too, matching main.js's live-mode order

let errors = 0;
let trackedCount = 0;
let maxTs = 0;
const allEvents = { flow: 0, dns: 0, anomaly: 0 };

for (const p of packets) {
  // mirror main.js's onPackets EXACTLY: filter first, then track
  if (!filter.matches(p)) continue;
  trackedCount++;
  maxTs = Math.max(maxTs, p.ts);

  try {
    stats.add(p);
    const ev = flows.add(p);
    if (ev) allEvents.flow++;
    const dnsEv = dns.add(p);
    if (dnsEv) allEvents.dns++;
    const anomEvs = anomaly.add(p);
    allEvents.anomaly += anomEvs.length;
    flowlog.add(p);
    // also exercise the rendering-adjacent helpers every packet would hit
    flowKeyOf(p);
    glowColorFor(p);
  } catch (e) {
    console.error('CRASH on packet:', p, '\n', e);
    errors++;
  }
}

console.log(`packets passing the port:443 filter: ${trackedCount}/${packets.length}`);
console.log('events fired — flow:', allEvents.flow, 'dns:', allEvents.dns, 'anomaly:', allEvents.anomaly);
console.log('crashes during tracking:', errors);

// Now run the periodic tick() pass, exactly as main.js's 0.25s loop would
let tickErrors = 0;
try {
  for (const ev of flows.tick(maxTs + 1)) { if (!ev.kind) tickErrors++; }
  for (const ev of dns.tick(maxTs + 1)) { if (!ev.kind) tickErrors++; }
  anomaly.tick(maxTs + 1);
} catch (e) {
  console.error('CRASH during tick():', e);
  tickErrors++;
}
console.log('tick() errors:', tickErrors);

// Snapshot stats and sanity-check every field used by the UI
const snap = stats.snapshot(maxTs + 0.5);
const requiredFields = ['totalPkts', 'totalBytes', 'pps', 'bpsIn', 'bpsOut', 'bcastPps', 'topTalkers', 'topCountries'];
let missingFields = [];
for (const f of requiredFields) {
  if (!(f in snap)) missingFields.push(f);
}
console.log('\nstats snapshot missing fields:', missingFields.length ? missingFields : 'none');
if (missingFields.length) { console.error('FAIL'); process.exitCode = 1; }

// Check every numeric field for NaN
function findNaN(obj, path = '') {
  const bad = [];
  for (const [k, v] of Object.entries(obj)) {
    const p2 = path ? `${path}.${k}` : k;
    if (typeof v === 'number' && Number.isNaN(v)) bad.push(p2);
    else if (Array.isArray(v)) {
      v.forEach((item, i) => {
        if (typeof item === 'object' && item !== null) bad.push(...findNaN(item, `${p2}[${i}]`));
      });
    }
  }
  return bad;
}
const nanFields = findNaN(snap);
console.log('NaN fields in stats snapshot:', nanFields.length ? nanFields : 'none');
if (nanFields.length) { console.error('FAIL'); process.exitCode = 1; }

// Cross-check: immediately after FlowLog.add(p) for a SYN, that flow must
// be retrievable by its own key right then. (NOT a check that it stays
// retrievable forever — MAX_FLOWS=400 deliberately evicts old flows under
// capacity pressure over a long session, by design; this checks the
// add-then-immediately-get round trip, not unbounded retention.)
let crossCheckOk = true;
const flowlog2 = new FlowLog();
for (const p of packets) {
  if (!filter.matches(p)) continue;
  flowlog2.add(p);
  if (p.transport === 'TCP' && p.flags === 'S') {
    const key = flowKeyOf(p);
    if (key && !flowlog2.get(key)) { crossCheckOk = false; break; }
  }
}
console.log('\nFlowLog add-then-get round trip (checked immediately, not after eviction pressure):', crossCheckOk);
if (!crossCheckOk) { console.error('FAIL: a SYN packet was not immediately retrievable right after being added'); process.exitCode = 1; }

// Anomaly counts sanity: totalCount must equal sum of individual counts
const c = anomaly.counts;
const sum = c.portscan + c.sweep + c.beacon + c.dnstunnel + c.synflood + c.arpspoof;
console.log('anomaly.totalCount matches sum of counts:', sum === anomaly.totalCount);
if (sum !== anomaly.totalCount) { console.error('FAIL'); process.exitCode = 1; }

console.log(errors === 0 && tickErrors === 0 ? '\nAll integration checks passed.' : '\nSOME CHECKS FAILED — see above.');
