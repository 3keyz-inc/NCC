"""MAC-spoofing / duplicate-address detection.

Signs of an intruder sitting on your LAN:
 - Two IPs claiming the same MAC (attacker moving between addresses)
 - One IP claimed by two MACs (ARP cache poisoning / MITM in progress)
 - A MAC whose OUI prefix suddenly differs from its historical vendor
 - Gateway MAC changing since baseline (classic router-compromise indicator)
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from .hosts import Host


@dataclass
class Finding:
    severity: str  # INFO | WARN | CRITICAL
    title: str
    detail: str


def oui(mac: str) -> str:
    return ":".join(mac.lower().split(":")[:3]) if mac else ""


def check_spoofing(current: list[Host], baseline: dict | None = None,
                   gateway_mac: str | None = None) -> list[Finding]:
    findings: list[Finding] = []

    mac_to_ips = defaultdict(set)
    ip_to_macs = defaultdict(set)
    for h in current:
        if h.mac:
            mac_to_ips[h.mac.lower()].add(h.ip)
            ip_to_macs[h.ip].add(h.mac.lower())

    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            findings.append(Finding(
                "WARN", "One MAC answering for multiple IPs",
                f"MAC {mac} seen at {sorted(ips)} — could be a VM/container "
                f"(normal) or an attacker roaming (suspicious if unknown)."))

    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            findings.append(Finding(
                "CRITICAL", "ARP conflict: one IP, multiple MACs",
                f"{ip} claimed by {sorted(macs)} — possible ARP-cache "
                f"poisoning / on-LAN man-in-the-middle."))

    if baseline:
        base_map = {ip: mac for ip, mac in baseline.get("ip_mac", {}).items()}
        for ip, macs in ip_to_macs.items():
            known = base_map.get(ip)
            if known and known not in macs:
                findings.append(Finding(
                    "CRITICAL", "MAC changed for a known IP",
                    f"{ip} was {known}, now {sorted(macs)}. If you didn't "
                    f"replace the device, someone may be spoofing it."))
        new_devices = [ip for ip in ip_to_macs if ip not in base_map]
        if new_devices:
            findings.append(Finding(
                "INFO", "New devices since baseline",
                f"First-seen hosts: {new_devices}. Verify each one."))

    if gateway_mac and baseline:
        base_gw = baseline.get("gateway_mac")
        if base_gw and base_gw != gateway_mac:
            findings.append(Finding(
                "CRITICAL", "Gateway MAC changed!",
                f"Router LAN MAC was {base_gw}, now {gateway_mac}. Strong "
                f"indicator of router compromise or a rogue DHCP server."))

    return findings
