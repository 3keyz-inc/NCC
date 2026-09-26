"""Baseline storage & diffing.

The single most useful intrusion signal at home is CHANGE: a device you've
never seen, a MAC that swapped, a port that opened. We snapshot each audit to
JSON and compare against the previous one.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from .spoof import Finding

DEFAULT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                            ".router_watch_baseline.json")


def save_baseline(hosts, gateway: str, gateway_mac: str, path: str = DEFAULT_PATH):
    data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "gateway": gateway,
        "gateway_mac": gateway_mac.lower() if gateway_mac else "",
        "ip_mac": {h.ip: h.mac.lower() for h in hosts if h.mac},
        "hosts": [{"ip": h.ip, "mac": h.mac, "hostname": h.hostname} for h in hosts],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


def load_baseline(path: str = DEFAULT_PATH) -> dict | None:
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def diff_hosts(current_hosts, baseline: dict) -> list[Finding]:
    findings: list[Finding] = []
    base_ips = set(baseline.get("ip_mac", {}))
    cur_ips = {h.ip for h in current_hosts}
    gone = sorted(base_ips - cur_ips)
    new = sorted(cur_ips - base_ips)
    if new:
        findings.append(Finding("WARN", "New hosts appeared since baseline",
                                f"{new} — confirm each is yours (guests, new "
                                f"phones, smart-home plugs count)."))
    if gone:
        findings.append(Finding("INFO", "Hosts no longer seen",
                                f"{gone} — usually just powered off."))
    return findings
