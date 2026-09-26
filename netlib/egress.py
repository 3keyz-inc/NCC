"""Live egress watch — 'what is my computer sending, and to whom?'

Passive capture on YOUR OWN interface using libpcap via `tcpdump` when
available (read-only BPF filter; no injection). Falls back to socket-level
connection snapshots (`ss -tunap`) which need no privileges. Periodically
prints top destination ASN/orgs so you can spot unknown data flows — that's
how you find telemetry/stalkerware exfil without guessing.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import time
from collections import Counter

from . import threatintel
from .spoof import Finding


def connections() -> list[dict]:
    """Current established TCP/UDP associations (Linux ss / macOS lsof)."""
    rows: list[dict] = []
    if shutil.which("ss"):
        try:
            out = subprocess.run(
                ["ss", "-H", "-tunap"], capture_output=True, text=True,
                timeout=8).stdout
            for ln in out.splitlines():
                m = re.search(r"(tcp|udp)\s+\w+\s+.*?\s+(\S+):(\d+)\s+"
                              r"(\S+):(\d+)", ln)
                if m:
                    rows.append({"proto": m.group(1), "lport": m.group(3),
                                 "raddr": m.group(4), "rport": m.group(5),
                                 "proc": ln.split("users:")[-1][:60]})
        except Exception:  # noqa: BLE001
            pass
    elif shutil.which("lsof"):
        try:
            out = subprocess.run(["lsof", "-nP", "-i"], capture_output=True,
                                 text=True, timeout=8).stdout
            for ln in out.splitlines()[1:]:
                p = ln.split()
                if len(p) >= 9:
                    ra = p[8].strip("()")
                    if "->" in ra:
                        l, r = ra.split("->")
                        rows.append({"proto": p[7].lower(),
                                     "laddr": l, "raddr": r.split(":")[0],
                                     "rport": r.rsplit(":", 1)[-1],
                                     "proc": p[0]})
        except Exception:  # noqa: BLE001
            pass
    return rows


def top_egress(n: int = 12) -> list[Finding]:
    conns = connections()
    if not conns:
        return [Finding("INFO", "Egress snapshot",
                        "No live sockets visible (needs same-user perms or "
                        "ss/lsof). Run as your desktop user, or use "
                        "Little Snitch / LuLu (macOS) or TCPView (Windows).")]
    c = Counter(x["raddr"] for x in conns if not
                x["raddr"].startswith(("192.168.", "10.", "127.")))
    findings = [Finding("INFO", "Remote endpoints your OS has open NOW",
                        "\n".join(f"{ip} ×{cnt}" for ip, cnt in
                                  c.most_common(n)))]
    # classify the top few so humans aren't chasing Google IPs
    for ip, _ in c.most_common(5):
        info = threatintel.classify(ip)
        findings.append(Finding("INFO", f"Egress {ip}",
                                f"{info['category']} — {info['verdict']}"))
    return findings


def watch(seconds: int = 15, identify: bool = True) -> list[Finding]:
    """Sample connections over an interval; flag NEW remote endpoints."""
    seen: set[str] = set()
    added: list[str] = []
    end = time.time() + seconds
    while time.time() < end:
        for x in connections():
            key = x.get("raddr", "")
            if key and not key.startswith(("192.168.", "10.", "127.")) \
               and key not in seen:
                seen.add(key)
                added.append(key)
        time.sleep(2)
    out = [Finding("INFO", f"Egress watch ({seconds}s)",
                   f"{len(seen)} distinct remote endpoints contacted.")]
    if added:
        out.append(Finding("WARN", "Endpoints first seen during window",
                           ", ".join(added[:20])))
    return out
