
import { flowKeyOf } from './config.js';

// Per-flow packet history for the "view conversation" detail panel.
// FlowTracker (flows.js) only retains enough state to detect SYN/RTT/RST
// transitions — it discards the actual packets once a transition is
// resolved. This module is a separate, deliberately small ring buffer that
// retains the real packets for the flows currently worth inspecting, so a
// click can open "everything that happened in this conversation" rather
// than just the one packet that was clicked.

const MAX_FLOWS = 400;          // distinct flows retained at once (oldest evicted)
const MAX_PKTS_PER_FLOW = 60;   // ring buffer size per flow — enough to read by eye,
                                 // not an exhaustive log of a long-lived connection

export class FlowLog {
  constructor() {
    this.flows = new Map(); // flowKey -> { pkts: [], bytesOut, bytesIn, firstTs, lastTs }
  }

  reset() {
    this.flows.clear();
  }

  /** Feed every packet. TCP and UDP only — ICMP/ARP/DNS-over-UDP packets
   *  still get attached to a flow key when they have ports (DNS does). */
  add(p) {
    if (p.sport == null || p.dport == null) return;
    const key = flowKeyOf(p);
    if (!key) return;
    let rec = this.flows.get(key);
    if (!rec) {
      if (this.flows.size >= MAX_FLOWS) this.flows.delete(this.flows.keys().next().value);
      rec = { pkts: [], bytesOut: 0, bytesIn: 0, firstTs: p.ts, lastTs: p.ts };
      this.flows.set(key, rec);
    } else {
      // re-insert to keep recently-active flows away from the eviction front
      this.flows.delete(key);
      this.flows.set(key, rec);
    }
    rec.pkts.push(p);
    if (rec.pkts.length > MAX_PKTS_PER_FLOW) rec.pkts.shift();
    if (p.dir === 'out') rec.bytesOut += p.size ?? 0; else rec.bytesIn += p.size ?? 0;
    rec.lastTs = p.ts;
  }

  /** The conversation for a flow key, or null if nothing's been retained
   *  (flow too old / evicted / never crossed paths with a port-bearing packet). */
  get(key) {
    if (!key) return null;
    const rec = this.flows.get(key);
    if (!rec || !rec.pkts.length) return null;
    return rec;
  }

  get flowCount() { return this.flows.size; }
}
