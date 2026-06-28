"""GeoIP enrichment: country + ASN (always available, bundled with the
geoip2fast pip package — no API key, no account, no extra download), with an
optional upgrade to city-level detail if a city .dat.gz is dropped in next to
this file.

geoip2fast's own update_all()/update_file() helpers fetch city data from
GitHub release assets at a URL this project's own sandboxed CI/dev network
may not be able to reach (release-assets.githubusercontent.com, not
github.com itself, despite what the redirect chain implies) — so the city
upgrade is opt-in and manual: download geoip2fast-city.dat.gz (or
geoip2fast-city-asn.dat.gz for ASN too) from
https://github.com/rabuchaim/geoip2fast/releases/latest and place it in this
backend/ directory. If present at startup, it's used automatically; if not,
country+ASN (bundled, always present) is used and nothing breaks.
"""
from __future__ import annotations

import logging
import os
import threading

log = logging.getLogger("packet-highway")

_CITY_FILENAMES = ("geoip2fast-city-asn.dat.gz", "geoip2fast-city.dat.gz")
_LOOKUP_CACHE_CAP = 4096

_geo = None          # the loaded GeoIP2Fast instance, or None if unavailable
_has_city = False
_cache: dict[str, dict | None] = {}
_cache_lock = threading.Lock()  # on_packet() runs in scapy's sniffer thread,
                                 # _pump_demo() runs on the asyncio loop — both
                                 # touch this cache, so it needs real locking
                                 # rather than relying on GIL atomicity of any
                                 # single dict op (the cap-evict-then-set
                                 # sequence below is not atomic as a whole).


def _find_city_file() -> str | None:
    here = os.path.dirname(os.path.abspath(__file__))
    for name in _CITY_FILENAMES:
        path = os.path.join(here, name)
        if os.path.isfile(path):
            return path
    return None


def init() -> None:
    """Load the GeoIP database once at startup. Safe to call multiple
    times; safe to call even if geoip2fast isn't installed (degrades to
    every lookup returning None rather than crashing the server)."""
    global _geo, _has_city
    if _geo is not None:
        return
    try:
        from geoip2fast import GeoIP2Fast
    except ImportError:
        log.warning("geoip2fast not installed — GeoIP enrichment disabled "
                     "(install it with: pip install geoip2fast)")
        return
    city_path = _find_city_file()
    try:
        if city_path:
            _geo = GeoIP2Fast(geoip2fast_data_file=city_path, verbose=False)
            _has_city = True
            log.info("GeoIP: loaded city-level database from %s", city_path)
        else:
            import geoip2fast
            asn_path = os.path.join(os.path.dirname(geoip2fast.__file__), "geoip2fast-asn.dat.gz")
            _geo = GeoIP2Fast(geoip2fast_data_file=asn_path, verbose=False)
            log.info("GeoIP: loaded bundled country+ASN database (no city "
                      "file found — see geo.py's module docstring to add one)")
    except Exception:
        log.exception("GeoIP: failed to load database — enrichment disabled")
        _geo = None


def lookup(ip: str | None) -> dict | None:
    """Country/ASN (and city, if the optional upgrade is present) for one
    IP. Returns None for private/reserved/unallocated addresses, malformed
    input, or if GeoIP wasn't loaded — callers should treat None as "no geo
    data available" rather than an error."""
    if not ip or _geo is None:
        return None
    with _cache_lock:
        if ip in _cache:
            return _cache[ip]
    try:
        r = _geo.lookup(ip)
    except Exception:
        r = None
    out = None
    if r is not None and r.country_code and r.country_code != "--":
        out = {
            "country_code": r.country_code,
            "country_name": r.country_name,
            "asn_name": (getattr(r, "asn_name", "") or None),
        }
        if _has_city:
            city = getattr(r, "city_name", "") or None
            if city:
                out["city_name"] = city
    with _cache_lock:
        if len(_cache) >= _LOOKUP_CACHE_CAP:
            _cache.pop(next(iter(_cache)), None)
        _cache[ip] = out
    return out


def enrich(p: dict) -> dict:
    """Attach geo_src/geo_dst to a packet dict in place. No-op (and cheap —
    one dict lookup) if GeoIP isn't loaded. Private-network packets are
    extremely common (every LAN broadcast, every internal hop) so the None
    result for them is the normal case, not a failure to log or worry about."""
    if _geo is None:
        return p
    p["geo_src"] = lookup(p.get("src"))
    p["geo_dst"] = lookup(p.get("dst"))
    return p
