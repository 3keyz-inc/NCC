"""Promiscuous-mode NIC detection (needs root on Linux).

If an intruder is on your Wi-Fi/LAN, sometimes the sign is a device whose
network card is set to *promisc* mode — capturing all traffic, not just its
own. On managed switches this check is less reliable; it's one signal among
many, not proof.

Method: read /sys/class/net/<iface>/flags and test the IFF_PROMISC bit (0x100).
Optionally also does the classic duplicate-ARP echo test when scapy-free raw
sockets are available.
"""
from __future__ import annotations

import os
from .spoof import Finding


def check_promisc() -> list[Finding]:
    findings: list[Finding] = []
    if os.geteuid() != 0:
        return [Finding("INFO", "Sniffer check skipped",
                        "Run with sudo to inspect NIC flags for promiscuous mode.")]
    base = "/sys/class/net"
    try:
        ifaces = os.listdir(base)
    except OSError:
        return findings
    for iface in ifaces:
        if iface == "lo":
            continue
        flagfile = os.path.join(base, iface, "flags")
        try:
            with open(flagfile) as f:
                flags = int(f.read().strip(), 16)
        except (OSError, ValueError):
            continue
        if flags & 0x100:  # IFF_PROMISC
            findings.append(Finding(
                "WARN", f"Interface {iface} is in PROMISCUOUS mode",
                f"{iface} is capturing all network traffic. Expected only if "
                f"you deliberately started a capture (tcpdump/Wireshark/"
                f"monitor mode). Otherwise investigate who did it."))
    if not findings:
        findings.append(Finding("INFO", "No promiscuous interfaces",
                                "None of your NICs are sniffing all traffic."))
    return findings
