"""Passive identification: WHOIS + reverse DNS + ownership heuristics.

Read-only lookups about an IP using public registry data (the same info
anyone can query). Never scans or touches the subject IP itself.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import subprocess
import urllib.request

CACHE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                          ".threatintel_cache.json")
UA = {"User-Agent": "Mozilla/5.0 (Router-Watch; passive-owner-lookup)"}

ORG_PATTERNS = [
    ("amazon", "Amazon/AWS (CloudFront, EC2)"),
    ("apple", "Apple (iCloud/Private Relay)"),
    ("google", "Google (GCP/YouTube services)"),
    ("akamai", "Akamai CDN"),
    ("microsoft", "Microsoft/Azure"),
    ("cloudflare", "Cloudflare"),
    ("fastly", "Fastly CDN"),
    ("twilio", "Twilio (voice/messaging)"),
    ("meta", "Meta/Facebook"),
    ("oracle", "Oracle Cloud"),
]


def _load_cache() -> dict:
    try:
        with open(CACHE_PATH) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(c: dict) -> None:
    try:
        with open(CACHE_PATH, "w") as f:
            json.dump(c, f, indent=2)
    except OSError:
        pass


def rdns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def whois_org(ip: str, timeout: float = 6.0) -> dict:
    """Best-effort org lookup: RDAP over HTTPS (no raw sockets needed)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return {}
    cache = _load_cache()
    if ip in cache:
        return cache[ip]
    url = (f"https://rdap.org/ip/{ip}" if isinstance(a, ipaddress.IPv4Address)
           else f"https://rdap.org/ip/{ip}")
    result: dict = {}
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        name = ""
        for ent in data.get("entities", []):
            for e in ent.get("entities", []) or []:
                for v in e.get("vcardArray", [None, []])[1] or []:
                    if v[0] == "fn":
                        name = name or v[3]
            for v in ent.get("vcardArray", [None, []])[1] or []:
                if v[0] == "fn" and not name:
                    name = v[3]
        result = {
            "handle": data.get("handle", ""),
            "name": data.get("name", "") or "",
            "org": name,
            "country": (data.get("country") or "").upper(),
        }
    except Exception:
        # fall back to `whois` CLI if present
        try:
            out = subprocess.run(["whois", ip], capture_output=True,
                                 text=True, timeout=timeout + 4).stdout
            m = re.search(r"(?im)^org:\s*(.+)$", out)
            c = re.search(r"(?im)^country:\s*(.+)$", out)
            result = {"org": m.group(1).strip() if m else "",
                      "country": c.group(1).strip().upper() if c else "",
                      "name": ""}
        except Exception:
            result = {}
    cache[ip] = result
    _save_cache(cache)
    return result


def classify(ip: str) -> dict:
    """Return {'ip','rdns','org','country','category','verdict'} for display."""
    rd = rdns(ip)
    w = whois_org(ip)
    hay = f"{rd} {w.get('org','')} {w.get('name','')}"
    category = "unknown"
    for needle, label in ORG_PATTERNS:
        if needle in hay.lower():
            category = label
            break
    if category == "unknown" and re.search(r"cloudfront|edge|cdn", hay, re.I):
        category = "CDN edge node"
    try:
        a = ipaddress.ip_address(ip)
        if a.is_private:
            category = "private/LAN address"
    except ValueError:
        pass
    if category == "unknown":
        verdict = ("unidentified — inspect further; NOT automatically "
                   "malicious (dropped inbound packets are normal)")
    elif "private" in category:
        verdict = "local device"
    else:
        verdict = "known service provider traffic (benign background noise)"
    return {"ip": ip, "rdns": rd, "org": w.get("org", ""),
            "name": w.get("name", ""), "country": w.get("country", ""),
            "category": category, "verdict": verdict}
