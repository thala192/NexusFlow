
export class PacketFilter {
  constructor(filterStr = '') {
    this.filterStr = filterStr.trim();
    this.conditions = [];
    this.parse();
  }

  parse() {
    if (!this.filterStr) return;

    const parts = this.filterStr.split(/\s+/);
    for (const part of parts) {
      if (!part) continue;

      if (part.includes(':')) {
        const [key, ...valueParts] = part.split(':');
        const value = valueParts.join(':').toLowerCase();
        const lowerKey = key.toLowerCase();

        if (lowerKey === 'ip') {
          this.conditions.push({ type: 'ip', value });
        } else if (lowerKey === 'port') {
          const portNum = parseInt(value, 10);
          if (!isNaN(portNum)) {
            this.conditions.push({ type: 'port', value: portNum });
          }
        } else if (lowerKey === 'proto') {
          this.conditions.push({ type: 'proto', value });
        } else if (lowerKey === 'sni') {
          this.conditions.push({ type: 'sni', value });
        } else if (lowerKey === 'flags') {
          this.conditions.push({ type: 'flags', value });
        } else if (lowerKey === 'dir') {
          if (value === 'in' || value === 'out') {
            this.conditions.push({ type: 'dir', value });
          }
        }
      } else {
        // free-text search (IP, domain, or any text)
        this.conditions.push({ type: 'text', value: part.toLowerCase() });
      }
    }
  }

  /** Match a packet against all conditions (AND logic). */
  matches(pkt) {
    if (!this.conditions.length) return true;

    for (const cond of this.conditions) {
      if (!this.matchCondition(pkt, cond)) return false;
    }
    return true;
  }

  matchCondition(pkt, cond) {
    switch (cond.type) {
      case 'ip': {
        const src = pkt.src ?? '';
        const dst = pkt.dst ?? '';
        return src.toLowerCase().includes(cond.value) || dst.toLowerCase().includes(cond.value);
      }
      case 'port': {
        return pkt.sport === cond.value || pkt.dport === cond.value;
      }
      case 'proto': {
        return (pkt.proto ?? '').toLowerCase() === cond.value;
      }
      case 'sni': {
        return (pkt.sni ?? '').toLowerCase().includes(cond.value);
      }
      case 'flags': {
        return (pkt.flags ?? '').includes(cond.value.toUpperCase());
      }
      case 'dir': {
        return pkt.dir === cond.value;
      }
      case 'text': {
        const src = (pkt.src ?? '').toLowerCase();
        const dst = (pkt.dst ?? '').toLowerCase();
        const sni = (pkt.sni ?? '').toLowerCase();
        const dns = (pkt.dns_qname ?? '').toLowerCase();
        return src.includes(cond.value) || dst.includes(cond.value)
            || sni.includes(cond.value) || dns.includes(cond.value);
      }
      default:
        return true;
    }
  }

  isEmpty() {
    return this.conditions.length === 0;
  }
}
