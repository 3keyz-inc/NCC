"""Router port exposure check.

Probes ONLY your own gateway IP for ports that should never be reachable from
the LAN/Internet on a home router: remote admin (8443/8080/10000), Telnet (23),
old HTTP admin (80), UPnP-related, SSH backdoors etc. A connect() probe is
harmless — it's the same thing your browser does.
"""
from __future__ import annotations

import socket
from .spoof import Finding

COMMON = {
    21: "FTP (cleartext file access)",
    23: "Telnet (cleartext admin — common router backdoor!)",
    22: "SSH",
    53: "DNS",
    80: "HTTP admin panel",
    443: "HTTPS admin panel",
    445: "SMB (file sharing — should never face WAN)",
    1723: "PPTP VPN",
    1900: "SSDP / UPnP",
    32400: "Synology DSM",
    8080: "Alt HTTP / admin",
    8443: "Alt HTTPS / admin",
    10000: "Webmin/Virtualmin admin",
    5060: "VoIP SIP",
}


def check_router_ports(gateway: str, timeout: float = 0.5) -> list[Finding]:
    findings: list[Finding] = []
    open_ports = []
    for port, desc in sorted(COMMON.items()):
        s = socket.socket()
        s.settimeout(timeout)
        try:
            if s.connect_ex((gateway, port)) == 0:
                open_ports.append((port, desc))
        except OSError:
            pass
        finally:
            s.close()

    risky = {23, 21, 80, 8080, 8443, 10000, 445}
    for port, desc in open_ports:
        sev = "CRITICAL" if port in (23, 21) else ("WARN" if port in risky else "INFO")
        findings.append(Finding(sev, f"Router port {port} open ({desc})",
                                "Telnet/FTP open on a router is a known intrusion "
                                "path. Disable remote/cleartext admin in firmware."))
    if not open_ports:
        findings.append(Finding("INFO", "No risky ports detected on gateway",
                                "Only probed well-known admin ports; see README."))
    return findings


def check_wan_exposure(gateway: str) -> list[Finding]:
    """Best-effort: ask whether the router answers on its public side.

    We can't port-scan the WAN from inside reliably, so we resolve our public
    endpoint via the router's own UPnP info if present. Kept simple + safe:
    we just report what the LAN-side sees and recommend an external scan.
    """
    return [Finding("INFO", "External exposure not tested",
                    "Scan from OUTSIDE your network (e.g. shieldfme.com or "
                    "GRC ShieldsUp!) — LAN-side probes can't see WAN filters.")]
