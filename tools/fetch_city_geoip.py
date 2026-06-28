#!/usr/bin/env python3
"""
Run this once, locally, from anywhere geoip2fast itself isn't network-blocked
(this sandbox's bash tool couldn't reach the download — see CHANGES.md round
eight — but your own machine almost certainly can).

Downloads geoip2fast-city-asn.dat.gz (13.5 MB, city + ASN + country, IPv4) and
places it directly in backend/, where geo.py already checks for it at startup.
No code changes needed afterward — just restart the server.

Usage:
    cd NexusFlow
    pip install geoip2fast --break-system-packages   # if not already installed
    python3 tools/fetch_city_geoip.py
"""
import os
import sys

TARGET_FILENAME = "geoip2fast-city-asn.dat.gz"


def main():
    try:
        from geoip2fast import GeoIP2Fast
    except ImportError:
        print("geoip2fast isn't installed. Run:\n  pip install geoip2fast --break-system-packages")
        sys.exit(1)

    backend_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend")
    dest_path = os.path.normpath(os.path.join(backend_dir, TARGET_FILENAME))

    print(f"Downloading {TARGET_FILENAME} from the geoip2fast GitHub releases…")
    print(f"Destination: {dest_path}\n")

    g = GeoIP2Fast(verbose=False)
    result = g.update_file(TARGET_FILENAME, dest_path, verbose=True)

    if result.get("error"):
        print(f"\nDownload failed: {result['error']}")
        print("If this is a network restriction, you can also download the file")
        print("manually from https://github.com/rabuchaim/geoip2fast/releases/latest")
        print(f"and place it at: {dest_path}")
        sys.exit(1)

    print(f"\nDone. {dest_path} is in place.")
    print("Restart the NexusFlow server (python3 run.py) — geo.py will pick it up")
    print("automatically and log 'GeoIP: loaded city-level database' at startup.")


if __name__ == "__main__":
    main()
