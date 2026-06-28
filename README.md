# NexusFlow

<div align="center">

### Real-Time 3D Network Intelligence & Traffic Visualization Platform

Visualize live network traffic in an immersive 3D environment powered by FastAPI, Scapy, WebSockets, and Three.js.

</div>

---

## Overview

NexusFlow is a real-time network observability platform that transforms packet-level network activity into an interactive 3D visualization experience.

Instead of analyzing traffic through traditional packet logs and dashboards, NexusFlow visualizes network flows as dynamic vehicles moving across a cyber-inspired highway. Users can monitor live traffic, replay packet captures, inspect protocol behavior, and explore network health through an immersive visual interface.

---

## 🌐 Live Demo
NexusFlow is live and accessible online:
🔗 https://nexusflow-3ogo.onrender.com

Experience real-time 3D network traffic visualization, packet analytics, PCAP replay, and protocol-aware monitoring directly from your browser.

> Note: this deployed instance reflects whatever version was last pushed to it —
> it may not include the threat detection, GeoIP, filter bar, or conversation view
> features described below until it's redeployed from the latest code.


## Features

### Real-Time Traffic Visualization
- Visualize live network packets in a 3D environment.
- Distinguish inbound and outbound traffic.
- Observe traffic density and communication patterns visually.
- Interactive camera controls and cinematic views.

### Protocol-Aware Analytics
Supports visualization and monitoring of:

- HTTP / HTTPS
- DNS
- SSH
- ICMP
- FTP
- SMTP / Mail
- VPN
- DHCP
- NTP
- SMB
- TCP / UDP
- ARP

### Threat Detection
Heuristic anomaly detection running client-side on every packet:

- Port scans and network sweeps (subnet-scoped, won't false-positive on ordinary multi-host browsing)
- Beaconing / possible C2 check-ins (regular-interval connections — flagged with an honest caveat that legitimate heartbeat traffic looks the same on timing alone)
- DNS tunneling (long, high-entropy, or high-volume subdomain queries)
- SYN floods
- ARP spoofing
- Detected threats spawn a dedicated alert vehicle on the road shoulder and surface in a dedicated THREAT DETECTION panel

### GeoIP Enrichment
- Country and ASN lookup for every public IP, via a bundled offline database (no API key, no account)
- Optional city-level upgrade (see `tools/fetch_city_geoip.py`)
- Per-packet location/network shown in the detail panel
- Top Countries breakdown alongside Top Talkers
- Toggleable ground-level underglow on the 3D highway, tinted by continent

### Interactive Dashboard
- Real-time bandwidth monitoring
- Protocol distribution analysis
- Top talkers and top countries identification
- Network health monitoring (TCP/DNS failure tracking, broadcast storm detection)
- Flow inspection panel
- Live display filter (`ip:`, `port:`, `proto:`, `sni:`, `flags:`, `dir:` — works in both live and PCAP mode, narrows what feeds the health/threat panels too, not just what's drawn)

### PCAP Replay Engine
- Upload `.pcap` and `.pcapng` files
- Timeline scrubbing
- Variable playback speed
- Historical traffic exploration

### Flow Inspection
Inspect:

- Source and destination IPs
- Ports
- Protocols
- TCP flags
- Packet sizes
- Timestamps
- GeoIP location and ASN
- Full conversation view — every retained packet in a flow, in sequence, one click away from any packet/flow/DNS detail panel

### Modern Visualization
- Three.js powered rendering
- GPU-accelerated graphics
- Bloom effects and dynamic lighting
- Interactive observability interface

---

## Tech Stack

### Backend
- Python
- FastAPI
- Scapy
- WebSockets

### Frontend
- HTML5
- CSS3
- JavaScript (ES Modules)
- Three.js

### Visualization
- WebGL
- GPU Instancing
- Post-Processing Effects
- Interactive 3D Rendering

---

## Project Structure

```text
NexusFlow
│
├── backend
│   ├── app.py
│   ├── geo.py
│   ├── live.py
│   ├── nexsus.py
│   ├── synth.py
│   ├── requirements.txt
│   └── __init__.py
│
├── frontend
│   ├── index.html
│   └── src
│       ├── anomaly.js
│       ├── config.js
│       ├── dns.js
│       ├── filter.js
│       ├── flowlog.js
│       ├── flows.js
│       ├── highway.js
│       ├── histogram.js
│       ├── main.js
│       ├── picking.js
│       ├── playback.js
│       ├── scene.js
│       ├── sources.js
│       ├── stats.js
│       ├── traffic.js
│       ├── ui.js
│       └── vehicles.js
│
├── tests
│   ├── README.md
│   ├── test_anomaly.mjs
│   ├── test_beacon_limitation.mjs
│   ├── test_full_integration.mjs
│   ├── test_sweep_synthetic.mjs
│   ├── captured_packets.json
│   └── integration_fixture.json
│
├── tools
│   └── fetch_city_geoip.py
│
├── run.py
├── CHANGES.md
└── README.md
```

`backend/geo.py` optionally loads a city-level GeoIP database if one is present
next to it (`geoip2fast-city-asn.dat.gz` or `geoip2fast-city.dat.gz`) — see
`tools/fetch_city_geoip.py` to download one. Without it, country + ASN data is
always available (bundled with the `geoip2fast` pip package, no extra download,
no API key).

---

## Quick Start

### Clone Repository

```bash
git clone https://github.com/thala192/NexusFlow.git
cd NexusFlow
```

### Create Virtual Environment

#### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

#### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

### Install Dependencies

```bash
pip install -r backend/requirements.txt
```

### Run NexusFlow

```bash
python run.py
```

or

```bash
python3 run.py
```

### Open in Browser

```
http://127.0.0.1:8000
```

---

## Live Monitoring Mode

1. Launch NexusFlow.
2. Select a network interface.
3. Click **START**.
4. Monitor traffic in real time.

> Administrator/root privileges may be required for packet capture.

### Linux

```bash
sudo python3 run.py
```

### macOS

```bash
sudo python3 run.py
```

### Windows

Run PowerShell or Command Prompt as Administrator.

---

## PCAP Replay Mode

1. Switch to **PCAP Mode**.
2. Upload a `.pcap` or `.pcapng` file.
3. Replay traffic through the timeline controls.
4. Inspect packets and flows interactively.

Available controls:

- Play / Pause
- Timeline Scrubbing
- Variable Playback Speed
- Packet Inspection
- Historical Analysis

---

## Keyboard Shortcuts

| Key | Action |
|------|---------|
| `1` | Overview Camera |
| `2` | Top-Down View |
| `3` | Gateway View |
| `4` | Chase Selected Flow |
| `5` | Cinematic Orbit |
| `Space` | Play / Pause |
| `←` | Seek Backward |
| `→` | Seek Forward |

---

## Performance

NexusFlow uses optimized rendering techniques to maintain smooth visualization performance.

### Optimizations

- GPU instancing
- Efficient packet aggregation
- WebGL rendering
- Real-time streaming
- Optimized Three.js scene management
- GeoIP lookups are cached and benchmark at ~4 microseconds each — negligible even under sustained live capture load

---

## Learning Outcomes

This project demonstrates:

- Computer Networking
- Packet Analysis
- Network Monitoring
- Real-Time Systems
- FastAPI Development
- WebSocket Communication
- Three.js Visualization
- Interactive Dashboard Design
- Performance Optimization

---

## Future Enhancements

- Traffic forecasting
- Session analytics
- Cloud deployment
- User authentication
- Saved filters & views
- AI-powered network insights
- Real-world calibration of the threat detectors against a known-malicious capture (the current heuristics are tuned against synthetic demo traffic — see `CHANGES.md`)

Already shipped: threat/anomaly detection, GeoIP mapping, live display filtering,
and full conversation/flow inspection — see `CHANGES.md` for the detailed history
of how each was built and validated.

---


## License

MIT License
