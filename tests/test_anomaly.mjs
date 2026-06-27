// Real integration test: imports the actual anomaly.js (not a copy) and
// feeds it real packets captured from the live demo backend. Run with:
//   node test_anomaly.mjs
import { AnomalyTracker } from '../frontend/src/anomaly.js';
import { readFileSync } from 'fs';

const packets = JSON.parse(readFileSync('./captured_packets.json', 'utf8'));
console.log(`loaded ${packets.length} real captured packets`);

const tracker = new AnomalyTracker();
const allEvents = [];
for (const p of packets) {
  const events = tracker.add(p);
  for (const e of events) allEvents.push(e);
  tracker.tick(p.ts);
}

console.log('\n--- counts ---');
console.log(tracker.counts);

console.log('\n--- events by kind ---');
const byKind = {};
for (const e of allEvents) {
  (byKind[e.kind] ??= []).push(e);
}
for (const [kind, evs] of Object.entries(byKind)) {
  console.log(`${kind}: ${evs.length} fired`);
  console.log('  first:', { target: evs[0].target, extra: evs[0].extra, severity: evs[0].severity });
}

console.log('\n--- recent() drill-down sanity check ---');
for (const kind of ['portscan', 'sweep', 'beacon', 'dnstunnel', 'synflood', 'arpspoof']) {
  const recent = tracker.recent(kind);
  console.log(`${kind}: recent() returns ${recent.length} grouped target(s)`);
}

// Sanity: total counts should match the number of distinct kinds tracked
const sumCounts = Object.values(tracker.counts).reduce((a, b) => a + b, 0);
console.log('\nsum of tracker.counts:', sumCounts, '| tracker.totalCount:', tracker.totalCount);
if (sumCounts !== tracker.totalCount) {
  console.error('MISMATCH: totalCount getter disagrees with summed counts!');
  process.exit(1);
}

// Sanity: every fired event's kind should be one of the six known kinds
const knownKinds = new Set(['portscan', 'sweep', 'beacon', 'dnstunnel', 'synflood', 'arpspoof']);
const badKind = allEvents.find((e) => !knownKinds.has(e.kind));
if (badKind) {
  console.error('UNKNOWN KIND FIRED:', badKind);
  process.exit(1);
}

console.log('\nAll sanity checks passed.');
