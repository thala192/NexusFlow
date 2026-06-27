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

### Interactive Dashboard
- Real-time bandwidth monitoring
- Protocol distribution analysis
- Top talkers identification
- Network health monitoring
- Flow inspection panel

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
│   ├── live.py
│   ├── nexsus.py
│   ├── synth.py
│   ├── requirements.txt
│   └── __init__.py
│
├── frontend
│   ├── index.html
│   └── src
│       ├── config.js
│       ├── dns.js
│       ├── filter.js
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
├── run.py
└── README.md
```

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

- Threat Detection
- Anomaly Detection
- GeoIP Mapping
- Traffic Forecasting
- Session Analytics
- Cloud Deployment
- User Authentication
- Saved Filters & Views
- AI-Powered Network Insights

---


## License

MIT License
