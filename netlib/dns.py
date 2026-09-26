"""DNS hijack check.

A very common intrusion result: malware/router config swaps your DNS resolver
so all your lookups route through the attacker's server (then they can send
you to fake bank/phishing pages). We compare the system resolver against
known-good public resolvers using raw DNS queries built with struct (no deps).
"""
from __future__ import annotations

import re
import socket
import struct

from .spoof import Finding

TRUSTED = {
    "1.1.1.1": "Cloudflare",
    "8.8.8.8": "Google",
    "9.9.9.9": "Quad9",
}

# A benign domain used as a canary — we only compare returned IPs between
# resolvers, never trust any single answer.
CANARY = "example.com"


def build_dns_query(name: str) -> bytes:
    tid = 0xBEEF
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN


def _skip_name(data: bytes, idx: int) -> int:
    """Advance past an encoded DNS name (handles compression pointers)."""
    while idx < len(data):
        length = data[idx]
        if length == 0:
            return idx + 1
        if length >= 192:  # compression pointer: 2 bytes total
            return idx + 2
        idx += length + 1
    raise IndexError("truncated DNS message")


def dns_a(name: str, server: str, timeout: float = 2.0) -> list[str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(build_dns_query(name), (server, 53))
        data, _ = sock.recvfrom(2048)
    except (socket.timeout, OSError):
        return []
    finally:
        sock.close()
    if len(data) < 12:
        return []
    qd, an = struct.unpack(">HH", data[4:8])
    ips: list[str] = []
    try:
        idx = 12
        for _ in range(qd):  # skip question section
            idx = _skip_name(data, idx) + 4
        for _ in range(an):
            idx = _skip_name(data, idx)
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[idx:idx + 10])
            idx += 10
            if rtype == 1 and rdlen == 4:
                ips.append(".".join(str(b) for b in data[idx:idx + 4]))
            idx += rdlen
    except (IndexError, struct.error):
        pass
    return ips


def system_dns_servers() -> list[str]:
    servers = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                m = re.match(r"nameserver\s+(\S+)", line)
                if m:
                    servers.append(m.group(1))
    except OSError:
        pass
    return servers


def check_dns() -> list[Finding]:
    findings: list[Finding] = []
    sys_servers = [s for s in system_dns_servers()
                   if not s.startswith("127.") and not s.startswith("::1")]
    trusted_answers = {}
    for ip, org in TRUSTED.items():
        ans = dns_a(CANARY, ip)
        if ans:
            trusted_answers[frozenset(ans)] = f"{org} ({ip})"

    if not trusted_answers:
        return [Finding("INFO", "DNS check inconclusive",
                        "Could not reach public resolvers to compare against.")]

    baseline_answer = next(iter(trusted_answers.items()))
    for s in sys_servers:
        ans = dns_a(CANARY, s)
        if not ans:
            findings.append(Finding("WARN", f"System resolver {s} unresponsive",
                                    "Your configured DNS server didn't answer."))
            continue
        got = frozenset(ans)
        if got not in trusted_answers:
            findings.append(Finding(
                "CRITICAL", f"Suspicious DNS divergence from {s}",
                f"{s} resolved {CANARY} to {sorted(got)}, but trusted "
                f"resolvers say {sorted(baseline_answer[0])}. Possible DNS "
                f"hijacking — check your router's DHCP/DNS settings NOW."))
        else:
            findings.append(Finding("INFO", f"Resolver {s} consistent", "OK"))
    unknown = [s for s in sys_servers if s not in TRUSTED and
               not s.startswith(("192.168.", "10.", "172."))]
    for s in unknown:
        findings.append(Finding("WARN", f"Unknown DNS server configured: {s}",
                                "Not your router, not a known public resolver. "
                                "Who put this in resolv.conf or DHCP?"))
    return findings
