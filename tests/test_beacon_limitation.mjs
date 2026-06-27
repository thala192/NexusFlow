// Documents a real, structural finding (not a bug): the beacon detector in
// anomaly.js cannot distinguish malicious C2 check-ins from a legitimate,
// low-jitter heartbeat poller on connection timing alone — both produce
// jitter ratios well under BEACON_MAX_JITTER (0.12).
//
// This test generates a real sample pcap containing BOTH beacon_session
// (intended: malicious) and healthcheck_poll (intended: benign) via the
// actual backend generator, parses it back through the real nexsus.py
// parser, and feeds the real packets to the real AnomalyTracker. It expects
// the detector to fire on *both* — proving the ambiguity is real rather
// than assuming it. If this test ever shows the detector reliably skips
// healthcheck_poll while still catching beacon_session, that means the
// detector logic changed in a way that adds a real discriminating signal —
// worth knowing about, not a regression to "fix" back to firing on both.
//
// Run with: python3 -c "..." to generate the pcap (see below), then
// node test_beacon_limitation.mjs
//
// Usage:
//   cd .. && python3 -c "
//   import sys; sys.path.insert(0, '.')
//   from backend.synth import build_sample_pcap_bytes
//   from backend.nexsus import parse_pcap_bytes
//   import json
//   data = build_sample_pcap_bytes(duration=900.0, seed=42)
//   result = parse_pcap_bytes(data, limit=300000)
//   pkts = result['packets'] if isinstance(result, dict) else result
//   json.dump(pkts, open('tests/beacon_limitation_fixture.json', 'w'))
//   print('wrote', len(pkts), 'packets')
//   "
//   node tests/test_beacon_limitation.mjs
import { AnomalyTracker } from '../frontend/src/anomaly.js';
import { existsSync, readFileSync } from 'fs';

const fixturePath = './beacon_limitation_fixture.json';
if (!existsSync(fixturePath)) {
  console.log('Fixture not found. Generate it first — see the comment at the top of this file.');
  process.exit(0); // not a failure: this fixture is regenerated on demand, not shipped by default
}

const packets = JSON.parse(readFileSync(fixturePath, 'utf8'));
console.log(`loaded ${packets.length} packets from a 900s synthetic sample`);

const tracker = new AnomalyTracker();
const beaconEvents = [];
for (const p of packets) {
  for (const e of tracker.add(p)) {
    if (e.kind === 'beacon') beaconEvents.push(e);
  }
}

const c2Hits = beaconEvents.filter((e) => e.target.includes('203.0.113.1'));
const healthcheckHits = beaconEvents.filter((e) => e.target.includes('198.51.100.40'));

console.log(`\nbeacon events total: ${beaconEvents.length}`);
console.log(`  on synthetic C2 hosts (203.0.113.1xx):        ${c2Hits.length}`);
console.log(`  on the legitimate healthcheck host (.40):     ${healthcheckHits.length}`);

if (c2Hits.length === 0) {
  console.error('\nUNEXPECTED: the detector missed the intended C2 traffic entirely.');
  process.exit(1);
}
if (healthcheckHits.length === 0) {
  console.log('\nNOTE: the legitimate poller did NOT trigger this run. Either the random');
  console.log('seed didn\'t produce enough samples, or detector logic now discriminates');
  console.log('legitimate heartbeats from C2 — worth investigating, not assuming is a bug.');
} else {
  console.log('\nCONFIRMED (expected): the detector cannot tell C2 beaconing apart from a');
  console.log('legitimate heartbeat poller on timing alone. This is a known limitation,');
  console.log('documented in the beacon detail-panel hint text (ui.js / main.js) — the');
  console.log('panel tells the analyst to judge by destination recognition, not the alert.');
}
console.log('\nTest complete (informational — see notes above, not a pass/fail gate).');
