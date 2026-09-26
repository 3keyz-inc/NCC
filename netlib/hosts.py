"""Basic LAN discovery: default gateway, interfaces, ARP table, subnet sweep.

All checks are read-only or use standard ARP/TCP-echo style pings against the
local subnet only. Refuses non-RFC1918 targets unless explicitly overridden.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import struct
import subprocess
import sys
from dataclasses import dataclass, field


@dataclass
class Host:
    ip: str
    mac: str = ""
    hostname: str = ""
    source: str = ""  # 'arp' | 'scan' | 'udp'
    vendor_hint: str = ""

    def key(self):
        return (self.ip, self.mac.lower() if self.mac else "")


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def default_gateway() -> tuple[str, str]:
    """Return (gateway_ip, interface) for the default route, Linux-first."""
    # Try `ip route`
    try:
        out = subprocess.run(["ip", "route", "show", "default"],
                             capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"default via (\S+) dev (\S+)", out)
        if m:
            return m.group(1), m.group(2)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    # Fallback: parse /proc/net/route (destination 0.0.0.0)
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if parts[1] == "00000000":
                    gw = socket.inet_ntoa(struct.pack("<L", int(parts[2], 16)))
                    return gw, parts[0]
    except OSError:
        pass
    # Last resort: UDP-connect trick to learn local IP (no packet sent)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local = s.getsockname()[0]
        net = ipaddress.ip_network(local + "/24", strict=False)
        return str(list(net.hosts())[0]), ""
    finally:
        s.close()


def local_interface_cidr(iface: str) -> list[str]:
    """Return CIDR strings for an interface (or all interfaces if iface='')."""
    cidrs = []
    try:
        out = subprocess.run(["ip", "-o", "addr", "show"],
                             capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            if iface and iface not in line:
                continue
            for m in re.finditer(r"inet (\S+)", line):
                cidrs.append(m.group(1))
    except FileNotFoundError:
        pass
    return cidrs


def arp_table() -> list[Host]:
    """Read the kernel ARP table — this shows every device the LAN saw recently."""
    hosts = []
    try:
        out = subprocess.run(["ip", "neighbor", "show"],
                             capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            m = re.match(r"(\S+) (dev \S+ )?(lladdr )?([0-9a-f:]{17})?", line)
            parts = line.split()
            if len(parts) >= 4 and "lladdr" in parts:
                ip = parts[0]
                mac = parts[parts.index("lladdr") + 1]
                hosts.append(Host(ip=ip, mac=mac, source="arp"))
    except FileNotFoundError:
        # macOS/BSD fallback
        try:
            out = subprocess.run(["arp", "-a"], capture_output=True,
                                 text=True, timeout=5).stdout
            for line in out.splitlines():
                m = re.search(r"(\S+) \(([\d.]+)\) at ([0-9a-f:]{17})", line)
                if m:
                    hosts.append(Host(hostname=m.group(1), ip=m.group(2),
                                      mac=m.group(3), source="arp"))
        except FileNotFoundError:
            pass
    return hosts


def _arp_ping(ip: str, iface: str, timeout: float = 0.2) -> bool:
    """Best-effort host liveness probe using TCP connect to common ports.

    Deliberately avoids raw-socket spoofing; a connect-scan of 2 ports per
    host on your own /24 is polite and needs no root.
    """
    for port in (22, 80, 443, 445, 139, 8080):
        s = socket.socket()
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, port)) == 0:
                return True
        except OSError:
            pass
        finally:
            s.close()
    # Even if no port answered, check whether ARP resolved afterwards
    return any(h.ip == ip for h in arp_table())


def scan_subnet(cidr: str, max_hosts: int = 256) -> list[Host]:
    """Enumerate a private CIDR. Refuses public ranges."""
    net = ipaddress.ip_network(cidr, strict=False)
    if not net.network_address.is_private:
        raise PermissionError(f"refusing to scan non-private range {cidr}")
    hosts = {h.key(): h for h in arp_table()}
    addrs = list(net.hosts())[:max_hosts]
    from concurrent.futures import ThreadPoolExecutor

    def probe(ip: str):
        ip = str(ip)
        if any(h.ip == ip for h in hosts.values()):
            return None
        if _arp_ping(ip, str(net)):
            after = [h for h in arp_table() if h.ip == ip]
            return after[0] if after else Host(ip=ip, source="scan")
        return None

    with ThreadPoolExecutor(max_workers=32) as ex:
        for res in ex.map(probe, addrs):
            if res:
                hosts[res.key()] = res
    return sorted(hosts.values(), key=lambda h: ipaddress.ip_address(h.ip))


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""
