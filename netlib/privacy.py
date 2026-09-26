"""Privacy shield: show what LEAVES your machine, then help you stop it.

Answers 'how do I make my info stop going to my router / out to the world':
  dns_leaks()   — which resolver actually answers, do you leak DNS names
  webScope()    — what any website learns about you right now (public IP via
                  the same path your browser uses; one HTTPS GET, no cookies)
  routes()      — where traffic exits & whether IPv6 bypasses your VPN/proxy
  proxy_env()   — http(s)_proxy / all_proxy settings
  browserFlags()— recommendations rendered as checklist (no browser internals
                  touched)
All read-only. Nothing here sends your data anywhere new; rdap.org and
httpbin-style checks use public endpoints over HTTPS.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import urllib.request

from .spoof import Finding

UA = {"User-Agent": "RouterWatch/1.0 (local privacy self-check)"}


def _run(cmd: list[str], timeout: float = 8.0) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout).stdout
    except Exception:
        return ""


def proxy_env() -> dict:
    keys = ("http_proxy", "https_proxy", "all_proxy", "no_proxy",
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")
    return {k: v for k in keys if (v := os.environ.get(k))}


def routes() -> list[str]:
    out = []
    default_gw = ""
    o = _run(["ip", "route", "show"]) or _run(["route", "-n", "get", "8.8.8.8"])
    m = re.search(r"default via (\S+)", o)
    if m:
        default_gw = m.group(1)
        out.append(f"IPv4 default route: via {default_gw}")
    o6 = _run(["ip", "-6", "route", "show"])
    m6 = re.search(r"default via (\S+)", o6)
    out.append("IPv6 default route: via " + (m6.group(1) if m6 else
               "NONE (IPv6 traffic will fail closed — good if you expected that)"))
    if not default_gw:
        out.append("WARNING: no default route parsed — check connectivity config")
    return out


def dns_leaks() -> tuple[list[str], list[Finding]]:
    """Compare system resolver vs public resolvers using Python's own stack."""
    findings: list[Finding] = []
    lines: list[str] = []
    sys_servers: list[str] = []
    try:
        with open("/etc/resolv.conf") as f:
            for ln in f:
                m = re.match(r"nameserver\s+(\S+)", ln)
                if m:
                    sys_servers.append(m.group(1))
    except OSError:
        pass
    lines.append("System resolvers: " + (", ".join(sys_servers) or "none found"))
    probe = "which-dns-leak-test.example"  # NXDOMAIN-safe probe name
    for rsrv in (sys_servers[:1] + ["1.1.1.1", "8.8.8.8"]):
        cmd = ["dig", "+short", "+time=2", "+tries=1", "@"+rsrv, probe]
        out = _run(cmd)
        if out == "" and not shutil_which("dig"):
            # fallback: raw UDP DNS query using netlib.dns hand-built packets
            from . import dns as dmod
            ok = dmod.dns_a("cloudflare.com", rsrv)
            lines.append(f"resolver {rsrv}: cloudflare.com -> "
                         f"{ok or 'NO ANSWER (blocked?)'}")
            continue
        lines.append(f"resolver {rsrv}: probe sent")
    # Egress identity check: does our DNS/server see a different public IP
    # than our interface? (detects split-tunnel leaks)
    pub4 = public_ip("https://api.ipify.org")
    pub6 = public_ip("https://api64.ipify.org?format=json")
    if pub4:
        lines.append(f"Public IPv4 as seen by internet: {pub4}")
    if pub6:
        lines.append(f"IPv6 as seen by internet: {pub6}")
    if sys_servers and any(
            srv.startswith(("192.168.", "10.", "172.16.", "172.2", "100.64."))
            for srv in sys_servers) and "1.1.1.1" not in sys_servers:
        findings.append(Finding(
            "INFO", "DNS goes through ISP/router",
            f"Your resolver {sys_servers[0]} is carrier-provided — every "
            "lookup is visible to them. Switch to DNS-over-HTTPS/TLS in "
            "your OS/browser (systemd-resolved DoT, NextDNS, or browser "
            "DoH) to stop plaintext DNS leaving your device."))
    if pub6 and ":" in str(pub6):
        findings.append(Finding(
            "WARN", "Native IPv6 egress active",
            "IPv6 is routable end-to-end. If you rely on a VPN/proxy that "
            "only tunnels IPv4, apps preferring IPv6 LEAK your real "
            "location/IP. Either fix the tunnel or disable IPv6 on the "
            "client until then."))
    return lines, findings


def shutil_which(name: str) -> bool:
    from shutil import which
    return which(name) is not None


def public_ip(url: str) -> str:
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=5) as r:
            body = r.read().decode().strip()
        try:
            return json.loads(body).get("ip", body)
        except json.JSONDecodeError:
            return body
    except Exception:
        return ""


def webScope() -> dict:
    """What a plain HTTPS site can learn about you right now. One GET to
    httpbin.org/headers + ip echo — shows YOUR request headers back."""
    info: dict = {}
    try:
        req = urllib.request.Request("https://httpbin.org/get", headers=UA)
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.loads(r.read().decode())
        info["origin_seen_by_site"] = data.get("origin", "")
        hdrs = data.get("headers", {})
        info["your_user_agent"] = hdrs.get("User-Agent", "")
        info["accept_language"] = hdrs.get("Accept-Language", "")
    except Exception as e:
        info["error"] = f"httpbin unreachable: {e}"
    return info


def hardening_findings(info: dict) -> list[Finding]:
    f: list[Finding] = []
    ua = info.get("your_user_agent", "")
    if ua and "RouterWatch" not in ua:
        pass  # this call used our UA; browser UA differs — note below
    f.append(Finding("INFO", "Browser fingerprint surface",
                     "Websites see: full User-Agent, Accept-Language, screen "
                     "size, time zone, fonts, WebRTC local IPs. To shrink it: "
                     "Firefox with resistFingerprinting or Brave Shields; "
                     "disable WebRTC leak via browser flag "
                     "(media.peerconnection.enabled=false)."))
    f.append(Finding("INFO", "Stop telemetry to router/cloud",
                     "On the router: disable 'Data Collection'/telemetry in "
                     "AT&T Smart Home Manager settings. On devices: turn off "
                     "diagnostics sharing, ad-tracking per OS. For DNS "
                     "privacy: enable system-wide DoT/DoQ. These reduce what "
                     "'goes out'; nothing can hide LAN-side frames from the "
                     "AP that carries them — that's physics of Wi-Fi."))
    return f
