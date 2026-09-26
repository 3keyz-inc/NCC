"""Surprise addition: background watcher daemon.

    python3 router_watch.py watch --interval 600

Every interval it re-runs a lightweight audit (ARP table + spoof diff vs
baseline + new-host detection), appends findings to watch.log, and prints an
ALERT line when something CRITICAL/WARN appears — so you get notified the day
an unknown device joins, instead of manually remembering to scan.
Ctrl-C to stop. Uses only the same passive checks as `audit`.
"""
from __future__ import annotations

import time
from datetime import datetime

from . import baseline as bl
from . import hosts as H
from . import spoof


def _one_pass() -> list[spoof.Finding]:
    gw, iface = H.default_gateway()
    arp = H.arp_table()
    base = bl.load_baseline()
    gmac = next((h.mac for h in arp if h.ip == gw), "")
    findings = spoof.check_spoofing(arp, base, gmac)
    if base:
        findings += bl.diff_hosts(arp, base)
    return [f for f in findings if f.severity in ("CRITICAL", "WARN")]


def run(interval: int = 600, log_path: str = "watch.log") -> None:
    print(f"[*] Watching every {interval}s -> {log_path}. Ctrl-C to stop.")
    while True:
        bad = _one_pass()
        stamp = datetime.now().isoformat(timespec="seconds")
        with open(log_path, "a") as f:
            f.write(f"{stamp} pass ok ({len(bad)} alerts)\n")
            for b in bad:
                f.write(f"{stamp} {b.severity}: {b.title} :: {b.detail}\n")
        if bad:
            print(f"\a[{stamp}] *** ALERT ***")
            for b in bad:
                print(f"  [{b.severity}] {b.title}: {b.detail}")
        else:
            print(f"[{stamp}] quiet ✓")
        time.sleep(interval)
