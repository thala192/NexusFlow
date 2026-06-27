// Targeted unit test: the demo backend has no same-subnet sweep generator,
// so this constructs one by hand to confirm _checkScan's sweep path still
// fires correctly after being rescoped to same-/24 targets.
import { AnomalyTracker } from '../frontend/src/anomaly.js';

function pkt(ts, src, dst, dport) {
  return { ts, src, dst, dport, sport: 51000 + Math.floor(Math.random() * 1000),
    transport: 'TCP', proto: 'OTHER', flags: 'S', dir: 'in', size: 60 };
}

const tracker = new AnomalyTracker();
const scanner = '10.0.0.99';
let t = 1000;
const events = [];

// scanner probes port 22 across 10.0.0.1 .. 10.0.0.10 (same /24), one host
// at a time, so no single host ever sees >1 port -> portscan must NOT fire
for (let i = 1; i <= 10; i++) {
  t += 0.1;
  events.push(...tracker.add(pkt(t, scanner, `10.0.0.${i}`, 22)));
}

console.log('events fired:', events.map((e) => ({ kind: e.kind, target: e.target, extra: e.extra })));
console.log('counts:', tracker.counts);

if (tracker.counts.sweep < 1) {
  console.error('FAIL: sweep did not fire for a genuine same-subnet sweep');
  process.exit(1);
}
if (tracker.counts.portscan > 0) {
  console.error('FAIL: portscan incorrectly fired (each host only saw 1 port)');
  process.exit(1);
}
console.log('\nPASS: sweep fires correctly on same-subnet scenario; portscan correctly silent');

// Second case: confirm portscan still fires when ports ARE concentrated on
// one host, even though that host happens to share a subnet with others
// the scanner also touched a little.
const tracker2 = new AnomalyTracker();
const events2 = [];
let t2 = 2000;
for (const port of [21, 22, 23, 80, 443]) {
  t2 += 0.1;
  events2.push(...tracker2.add(pkt(t2, '10.0.0.50', '10.0.0.5', port)));
}
console.log('\ncounts2:', tracker2.counts);
if (tracker2.counts.portscan < 1) {
  console.error('FAIL: portscan did not fire for a genuine single-host vertical scan');
  process.exit(1);
}
console.log('PASS: portscan fires correctly on single-host vertical scan');
