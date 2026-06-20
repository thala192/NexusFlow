
export const THEME = (() => {
  try {
    const q = new URLSearchParams(location.search).get('theme');
    return (q ?? localStorage.getItem('ph-theme')) === 'colorblind' ? 'colorblind' : 'night';
  } catch {
    return 'night';
  }
})();
const CB = THEME === 'colorblind';

export const PROTO_COLORS = CB ? {
 HTTPS:  0x00ff88, // Neon Green
  HTTP:   0xff6b00, // Neon Orange
  DNS:    0xffff00, // Electric Yellow
  ICMP:   0xffffff, // Pure White
  SSH:    0x00d4ff, // Neon Cyan
  RDP:    0x7c3aed, // Purple
  SNMP:   0x14f195, // Aqua Green
  DHCP:   0x84ff00, // Lime Neon
  NTP:    0x00ffff, // Cyan
  SYSLOG: 0xff00ff, // Magenta
  VPN:    0x8b5cf6, // Violet
  MAIL:   0x0099ff, // Bright Blue
  SMB:    0xff4d6d, // Neon Pink
  FTP:    0xff1744, // Red
  TCP:    0x94a3b8, // Silver Slate
  UDP:    0xb388ff, // Lavender
  ARP:    0xe5e7eb, // Light Gray
  OTHER:  0x64748b, // Dark Slate
} : {
HTTPS:  0x00FF41, // Matrix Green
HTTP:   0xFF9100, // Amber
DNS:    0xFFF700, // Neon Yellow
ICMP:   0xFFFFFF, // White
SSH:    0x00F5FF, // Laser Cyan
RDP:    0x651FFF, // Deep Neon Purple
SNMP:   0x1DE9B6, // Turquoise
DHCP:   0x76FF03, // Electric Lime
NTP:    0x40C4FF, // Sky Blue
SYSLOG: 0xEA00FF, // Neon Magenta
VPN:    0xAA00FF, // Ultra Violet
MAIL:   0x0091EA, // Deep Azure
SMB:    0xFF4081, // Neon Pink
FTP:    0xFF1744, // Red Alert
TCP:    0x64B5F6, // Cool Blue
UDP:    0xB388FF, // Soft Purple
ARP:    0xECEFF1, // Light Silver
OTHER:  0x78909C, // Metallic Gray
};

export const PROTO_CSS = Object.fromEntries(
  Object.entries(PROTO_COLORS).map(([k, v]) => [k, '#' + v.toString(16).padStart(6, '0')])
);

// TCP control car body colors (opening / accepted / closing / reset)
export const FLAG_COLORS = CB
  ? { S: 0xe69f00, SA: 0x56b4e9, F: 0xcc79a7, FA: 0xcc79a7, R: 0xd55e00, RA: 0xd55e00 }
  : { S: 0xfbbf24, SA: 0x4ade80, F: 0xc084fc, FA: 0xc084fc, R: 0xf87171, RA: 0xf87171 };

// Lane speed = world units/sec for EVERY vehicle in that lane (see header).
export const LANES = [
  { key: 'WEB',   label: 'WEB · 80/443',       speed: 46 },
  { key: 'DNS',   label: 'DNS · 53',           speed: 92 },
  { key: 'MGMT',  label: 'MGMT · 22/3389',     speed: 62 },
  { key: 'INFRA', label: 'INFRA · SNMP/NTP',   speed: 52 },
  { key: 'FILE',  label: 'FILE · 445/21',      speed: 46 },
  { key: 'OTHER', label: 'OTHER',              speed: 58 },
  { key: 'ICMP',  label: 'ICMP',               speed: 70 },
];
export const LANE_SPEED = Object.fromEntries(LANES.map((l) => [l.key, l.speed]));

export const PROTO_LANE = {
  HTTP: 'WEB', HTTPS: 'WEB',
  DNS: 'DNS',
  SSH: 'MGMT', RDP: 'MGMT',
  SNMP: 'INFRA', DHCP: 'INFRA', NTP: 'INFRA', SYSLOG: 'INFRA', VPN: 'INFRA', MAIL: 'INFRA',
  SMB: 'FILE', FTP: 'FILE',
  ICMP: 'ICMP',
};

export const HIGHWAY = {
  length: 620,
  laneWidth: 8.4,   // wide enough for two sub-lanes
  medianWidth: 11,
  shoulder: 8,
};
export const HALF_LEN = HIGHWAY.length / 2;

// Two sub-lanes per protocol lane absorb near-simultaneous arrivals.
export const SUBLANE_OFFSET = 2.1;

export function laneOffset(i) {
  return HIGHWAY.medianWidth / 2 + (i + 0.5) * HIGHWAY.laneWidth;
}

/** World X of a sub-lane center. dir 'in' drives on +X, 'out' on -X. */
export function sublaneX(laneCenterX, dir, sub) {
  const sign = dir === 'in' ? 1 : -1;
  return laneCenterX + (sub === 0 ? -1 : 1) * sign * SUBLANE_OFFSET;
}

export function laneFor(p) {
  if (p.transport === 'ICMP') return 'ICMP';
  return PROTO_LANE[p.proto] ?? 'OTHER';
}

/** TCP control packets (handshake/teardown) — flag MEMBERSHIP, not equality,
 *  so ECN-marked handshakes ("SEC"/"SAE") classify correctly. */
export function isControl(p) {
  if (p.transport !== 'TCP' || !p.flags || p.size > 120) return false;
  return p.flags.includes('S') || p.flags.includes('F') || p.flags.includes('R');
}

/** Canonical flow key for a packet (order-independent 4-tuple), or null. */
export function flowKeyOf(p) {
  if (!p || p.sport == null || p.dport == null) return null;
  const a = `${p.src}:${p.sport}`;
  const b = `${p.dst}:${p.dport}`;
  return a < b ? `${a}|${b}` : `${b}|${a}`;
}

// Vehicle metaphors:
//   motorcycle — DNS: small queries weaving through fast
//   van/truck  — payload carriers (web, file transfer), length scales w/ bytes
//   sedan      — generic / interactive TCP (SSH, RDP)
//   police     — ICMP: the network's patrol & diagnostics (red/blue strobes;
//                error messages like unreachable/TTL-exceeded ride red-bodied)
//   signal     — TCP control packets (SYN/SYN-ACK/FIN/RST), flag-colored strobe
//   drone      — UDP: connectionless, never touches the road
//   cart       — L2 housekeeping (ARP etc.): slow maintenance vehicle
//   convoy     — aggregate of a traffic burst (N packets as one road-train)
const VAN_PROTOS = new Set(['SMB', 'FTP', 'VPN', 'MAIL']);
export function vehicleTypeFor(p) {
  if (isControl(p)) return 'signal';
  if (p.transport === 'ICMP') return 'police';
  if (p.proto === 'DNS') return 'motorcycle';
  if (p.proto === 'HTTP' || p.proto === 'HTTPS') return p.size > 900 ? 'truck' : 'van';
  if (VAN_PROTOS.has(p.proto)) return 'van';
  if (p.transport === 'TCP') return 'sedan';
  if (p.transport === 'UDP') return 'drone';
  return 'cart';
}

// cap = instance pool size, len = visual length at scale 1 (for spacing math)
export const TYPE_SPECS = {
  motorcycle: { cap: 280, len: 3.2 },
  van:        { cap: 260, len: 5.6 },
  truck:      { cap: 160, len: 8.6 },
  sedan:      { cap: 320, len: 5.0 },
  police:     { cap: 140, len: 5.0 },
  signal:     { cap: 220, len: 3.8 },
  drone:      { cap: 200, len: 2.4 },
  cart:       { cap: 140, len: 3.2 },
  convoy:     { cap: 120, len: 11.0 },
};

export const FLAG_NAMES = {
  F: 'FIN', S: 'SYN', R: 'RST', P: 'PSH', A: 'ACK', U: 'URG', E: 'ECE', C: 'CWR',
};

// Failure tint shared by DNS-failure motorcycles, ICMP error cruisers,
// retransmissions, and shoulder wrecks. Vermillion under the CB theme.
export const FAIL_RED = CB ? 0xd55e00 : 0xef4444;

// Representative color per lane, for the stacked scrubber histogram.
export const LANE_REPR = {
  WEB: PROTO_COLORS.HTTPS, DNS: PROTO_COLORS.DNS, MGMT: PROTO_COLORS.SSH,
  INFRA: PROTO_COLORS.SNMP, FILE: PROTO_COLORS.SMB, OTHER: PROTO_COLORS.TCP,
  ICMP: PROTO_COLORS.ICMP,
};

/** Broadcast / multicast destination (L2 or L3). */
export function isBroadcast(p) {
  if (p.dmac === 'ff:ff:ff:ff:ff:ff') return true;
  const d = p.dst ?? '';
  if (d === '255.255.255.255') return true;
  const first = parseInt(d, 10);
  if (first >= 224 && first <= 239) return true;
  return d.includes(':') && d.toLowerCase().startsWith('ff');
}

// Rows for the auto-generated legend (color always = PROTO_COLORS).
export const LEGEND = [
  { proto: 'DNS',   text: 'DNS — motorcycles (fast lane)' },
  { proto: 'HTTPS', text: 'HTTPS/QUIC — vans/trucks · length = bytes' },
  { proto: 'HTTP',  text: 'HTTP (cleartext) — vans/trucks' },
  { proto: 'ICMP',  text: 'ICMP — police cars (errors ride red)' },
  { proto: 'SSH',   text: 'SSH — sedans (MGMT lane)' },
  { proto: 'RDP',   text: 'RDP — sedans (MGMT lane)' },
  { proto: 'SMB',   text: 'SMB/FTP — cargo vans (FILE lane)' },
  { proto: 'SNMP',  text: 'SNMP — drones (INFRA lane)' },
  { proto: 'DHCP',  text: 'DHCP · NTP · syslog — drones' },
  { proto: 'UDP',   text: 'Other UDP — drones (airborne)' },
  { proto: 'TCP',   text: 'Other TCP — sedans' },
  { proto: 'ARP',   text: 'ARP/L2 — maintenance carts' },
  { css: '#ef4444', text: 'Red bodies = failures (NXDOMAIN/SERVFAIL bikes, ICMP errors)' },
];
