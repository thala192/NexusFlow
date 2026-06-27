# Anomaly detector tests

Plain Node, no dependencies — imports the real `frontend/src/anomaly.js` directly.

```
cd tests
node test_anomaly.mjs            # replays a real 90s capture from the live demo backend
node test_sweep_synthetic.mjs    # hand-built same-subnet sweep vs single-host scan
node test_beacon_limitation.mjs  # documents a real limitation — see below
```

### `test_beacon_limitation.mjs`

This one is informational, not pass/fail. It generates a longer synthetic sample
containing both `beacon_session` (intended malicious C2) and `healthcheck_poll`
(intended legitimate heartbeat) and confirms a real, structural finding: **the
beacon detector cannot tell them apart on connection timing alone** — both produce
the same low-jitter signature. That's not a bug to fix; it's the honest limit of a
timing-only heuristic, and it's why the detail-panel hint for `beacon` tells the
analyst to judge by whether they recognize the destination, not by the alert alone.

Its fixture isn't shipped (it's ~50k packets) — regenerate it with the Python
snippet in the comment at the top of the file, then run the test.

`captured_packets.json` is a real packet capture from `/ws/live?demo=1`, saved so the
test doesn't depend on a running server. To refresh it, start the backend
(`python3 run.py`) and re-capture from the WebSocket — see the capture snippet in
the `do next` step of the original build session, or just connect a WS client to
`ws://127.0.0.1:8000/ws/live?demo=1` and dump `{"type":"packets","items":[...]}`
messages to a JSON array.

`test_anomaly.mjs` doesn't assert specific counts (the demo data is random per
capture) — it asserts structural invariants: every fired event has a known `kind`,
`tracker.totalCount` agrees with the sum of `tracker.counts`, and `recent()` doesn't
throw. Re-run it after touching `anomaly.js` to catch crashes and shape regressions;
read the printed counts by eye to catch false-positive regressions like the
port-scan/sweep bug this caught originally (see CHANGES.md, round three).
