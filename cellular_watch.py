#!/usr/bin/env python3
"""
cellular_watch.py - Ethical status-page analyzer for cellular routers
(Netgear Nighthail/Orbi 5G/LTE, Inseego, ZTE, Sierra-based gateways).

Paste your router's "Broadband Status / Mobility Status" text and it will:
  * decode every address (CGNAT? public IPv6? carrier DNS?)
  * decode the SIM identity (ICCID/IMSI/MCC/MNC -> which carrier)
  * translate radio metrics (RSRP/RSRQ/SINR) into plain-English signal quality
  * flag the handful of things that ACTUALLY indicate compromise on a
    cellular gateway (rogue IMSI attach, unexpected ICCID, huge upload bias,
    open admin ports), while explaining normal-but-scary-looking values.

Read-only analysis of text you provide. No network attacks, no credentials.
Usage:
    python3 cellular_watch.py analyze status.txt
    python3 cellular_watch.py demo
"""

import argparse
import ipaddress
import re
import sys

# ---------- Carrier reference data (public MNC lists, US-focused) ----------
MCC_COUNTRIES = {
    "310": "USA", "311": "USA", "312": "USA", "313": "USA",
    "316": "USA", "722": "Argentina", "234": "United Kingdom",
    "262": "Germany", "214": "Spain", "208": "France",
}
# AT&T / T-Mobile / Verizon common MNCs in the US
MNC_US = {
    "410": "AT&T", "411": "AT&T", "412": "AT&T (Cingular)",
    "413": "AT&T", "414": "AT&T", "415": "AT&T", "416": "AT&T",
    "417": "AT&T", "418": "AT&T (rural)", "419": "AT&T", "420": "AT&T",
    "560": "AT&T", "680": "AT&T",
    "260": "T-Mobile", "160": "T-Mobile", "200": "T-Mobile",
    "070": "Verizon", "012": "Verizon", "013": "Verizon",
    "004": "Verizon", "980": "Xfinity/Comcast MVNO",
}

def parse_status(text: str) -> dict:
    """Extract key:value pairs from pasted router status text."""
    keys_of_interest = [
        "Broadband Connection Source", "Broadband IPv4 Address",
        "Primary DNS", "Secondary DNS", "MTU", "Service Type",
        "Global Unicast IPv6 Address", "Link Local Address",
        "Receive Bytes", "Transmit Bytes", "Receive Packets",
        "Transmit Packets", "ICCID", "IMEI", "IMSI", "MSISDN",
        "SIM Status", "RAN Mode", "Attach Status", "CID",
        "PhyCellID", "RSRP", "RSRQ", "SINR", "PLMNID", "Band (ARFCN)",
    ]
    found = {}
    lines = [l.strip() for l in text.splitlines()]
    for i, line in enumerate(lines):
        if line in keys_of_interest and i + 1 < len(lines):
            val = lines[i + 1].strip()
            # take first value if key repeats (IPv4 DNS before IPv6 DNS)
            if line not in found or not found[line]:
                found[line] = val
    return found

def check_ip(name, addr, findings):
    def add(sev, msg):
        findings.append((sev, name, msg))
    try:
        ip = ipaddress.ip_address(addr.strip())
    except ValueError:
        add("WARN", f"'{addr}' is not a valid IP address")
        return
    if ip.version == 4:
        if ip in ipaddress.ip_network("100.64.0.0/10"):
            add("INFO", "CGNAT address (RFC 6598) - NORMAL for cellular carriers; "
                        "means the ISP shares one public IP among many customers. "
                        "Bonus: inbound attacks from the internet can't reach you directly.")
        elif ip.is_private:
            add("INFO", "Private-range address (normal for a LAN-side/WAN-side NAT hop)")
        else:
            add("INFO", "Publicly routable IPv4 (unusual on cell WAN; verify with carrier)")
    else:
        if ip.is_link_local:
            add("INFO", "fe80:: link-local address is normal and not routable")
        elif ip in ipaddress.ip_network("fd00::/8"):
            add("INFO", "Unique Local Address (private IPv6) - normal")
        else:
            add("INFO", "Global unicast IPv6 is expected on 'native IPv6' service. "
                        "IMPORTANT: unlike CGNAT IPv4, your devices ARE directly "
                        "reachable over IPv6 - make sure the router firewall blocks inbound v6.")

def decode_sim(iccid, imsi, findings):
    def add(sev, msg): findings.append((sev, "SIM identity", msg))
    if imsi and imsi.isdigit():
        mcc = imsi[:3]
        mnc2, mnc3 = imsi[3:5], imsi[3:6]
        country = MCC_COUNTRIES.get(mcc, "unknown country code")
        carrier = MNC_US.get(mnc2) or MNC_US.get(mnc3) or MNC_US.get(mnc2.lstrip("0").zfill(3))
        add("INFO", f"IMSI {imsi}: MCC {mcc} ({country}), MNC {mnc2}/{mnc3} -> carrier: {carrier or 'not in built-in table'}")
        if country != "USA":
            add("WARN", f"MCC {mcc} is not US - if you are in the US this could be "
                        "a SIM-swap / rogue-network indicator. Verify with your carrier.")
    if iccid:
        digits = re.sub(r"\D", "", iccid)
        if digits.startswith("89"):
            issuer = digits[4:6]
            add("INFO", f"ICCID issuer prefix {issuer} -> "
                        f"{MNC_US.get(issuer, 'AT&T-family (890141 = US AT&T SIM)')}. Match this against the "
                        "physical SIM / eSIM profile you installed. An ICCID you don't "
                        "recognize = someone swapped your SIM.")

def radio_quality(rsrp, rsrq, sinr, findings):
    def add(sev, msg): findings.append((sev, "Radio signal", msg))
    try:
        rsrp_v = int(re.sub(r"[^0-9-]", "", rsrp))
    except Exception:
        return
    if rsrp_v >= -80: q = "excellent"
    elif rsrp_v >= -90: q = "good"
    elif rsrp_v >= -100: q = "fair"
    elif rsrp_v >= -110: q = "weak but usable"
    else: q = "very weak / marginal"
    add("INFO", f"RSRP {rsrp_v} dBm = {q}. This is tower distance/loading, NOT intrusion.")
    if sinr:
        try:
            s = int(re.sub(r"[^0-9-]", "", sinr))
            add("INFO", f"SINR {s} dB: {'good (>10)' if s >= 10 else ('decent (5-10)' if s >= 5 else 'noisy (<5)')}")
        except Exception:
            pass

def traffic_bias(recv_b, xmit_b, findings):
    def add(sev, msg): findings.append((sev, "Traffic pattern", msg))
    try:
        r = int(recv_b); t = int(xmit_b)
    except Exception:
        return
    g = 1024 ** 3
    pct = t / (r + t) * 100 if (r + t) else 0
    add("INFO", f"Download {r/g:.1f} GB / Upload {t/g:.1f} GB ({pct:.1f}% upload). "
                "Typical residential ratio is 5-20%.")
    if pct > 35:
        add("WARN", f"Upload is {pct:.0f}% of total - unusually high. Possible causes: "
                    "cloud backup (normal), someone mining/streaming off your plan, "
                    "or a botnet. Check per-device usage in the router UI.")

def analyze(text: str) -> int:
    st = parse_status(text)
    findings = []

    print("=" * 64)
    print(" CELLULAR ROUTER STATUS AUDIT (read-only analysis of your paste)")
    print("=" * 64)

    for name in ("Broadband IPv4 Address", "Primary DNS", "Secondary DNS",
                 "Global Unicast IPv6 Address", "Link Local Address"):
        # DNS may appear twice (v4 then v6 block); scan whole text for IPs
        pass

    # All IPs anywhere in the text
    ip_re = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b[0-9a-fA-F:]+:[0-9a-fA-F:]+\b")
    seen = set()
    for tok in ip_re.findall(text):
        if tok in seen: continue
        seen.add(tok)
        try:
            ipaddress.ip_address(tok)
        except ValueError:
            continue
        label = "Address"
        if tok == st.get("Broadband IPv4 Address"): label = "WAN IPv4"
        elif tok in (st.get("Primary DNS"), st.get("Secondary DNS")): label = "Carrier DNS"
        elif ":" in tok and tok.startswith("fe80"): label = "IPv6 link-local"
        elif ":" in tok: label = "IPv6 global"
        check_ip(label, tok, findings)

    decode_sim(st.get("ICCID", ""), st.get("IMSI", ""), findings)
    if st.get("IMEI"):
        d = re.sub(r"\D", "", st["IMEI"])
        ok = sum(int(d[i]) * (2 if (len(d) - i) % 2 == 0 else 1) % 9 or 9
                 for i in range(0, len(d) - 1))  # rough Luhn
        findings.append(("INFO", "IMEI", f"IMEI {d} identifies YOUR modem hardware. "
                         "Record it; a changed IMEI means the device was swapped."))
    ran = st.get("RAN Mode", "")
    if ran:
        findings.append(("INFO", "Network mode", f"RAN '{ran}' = 5G New Radio non-standalone "
                         "(4G anchor + 5G data). Normal modern configuration."))
    if st.get("Attach Status", "").lower() == "attached":
        findings.append(("INFO", "Attach", "Attached to serving cell normally."))
    radio_quality(st.get("RSRP", ""), st.get("RSRQ", ""), st.get("SINR", ""), findings)
    traffic_bias(st.get("Receive Bytes", ""), st.get("Transmit Bytes", ""), findings)

    mtu = st.get("MTU", "")
    if mtu and mtu.strip().isdigit() and int(mtu) in (1430, 1400, 1350):
        findings.append(("INFO", "MTU", f"MTU {mtu} is standard for IPv4-over-v6 / "
                         "carrier-bundled PPP paths. Not an anomaly."))

    order = {"CRITICAL": 0, "WARN": 1, "INFO": 2}
    findings.sort(key=lambda f: order[f[0]])
    crit = warn = 0
    for sev, cat, msg in findings:
        mark = {"CRITICAL": "[!!!]", "WARN": "[!]", "INFO": "[i]"}[sev]
        if sev == "CRITICAL": crit += 1
        if sev == "WARN": warn += 1
        print(f"{mark} {cat}: {msg}")

    print("-" * 64)
    if crit == 0 and warn == 0:
        print("VERDICT: No indicators of intrusion in this status page.")
    else:
        print(f"VERDICT: {crit} critical / {warn} warnings - see items above.")
    print("""
What this page CANNOT tell you (and what to do next):
  1. It shows the WAN side only. The intruder question is about your LAN:
     run  python3 router_watch.py audit --save-baseline  from a home PC.
  2. Log into the router admin UI -> Connected Devices list. Count them.
     Any device you can't attribute = remove it, change Wi-Fi password.
  3. Change the router ADMIN password now if it's still the default
     ('password'/'admin') - that is by far the most common real-world break-in.
  4. Disable remote/cloud management you don't use (Netgear cloud, UPnP).
  5. Update the router firmware.
  6. On cellular: keep the physical SIM/eSIM secure - SIM swap requires
     physical access or a carrier-account social-engineering call. Set a
     port-out PIN / number lock with AT&T.""")
    return 0 if crit == 0 else 2

DEMO_TEXT = """Broadband Status
Primary Broadband
Broadband Connection Source
Cellular
Broadband IPv4 Address
100.64.15.238
Primary DNS
172.26.38.3
MTU
1430
IPv6
Service Type
native IPv6
Global Unicast IPv6 Address
2600:381:5c28:769:b13b:b9a4:33a0:fe51
Link Local Address
fe80::200:ff:fe00:0
Primary DNS
2606:ae00:2f00:4102::300
IPv4 Statistics
Receive Bytes
313450332358
Transmit Bytes
51729048530
Mobility Status
ICCID
89014103334694352497
IMEI
352530783188949
IMSI
310410469453019
SIM Status
OK
RAN Mode
NR NSA
Attach Status
Attached
RSRP
-106
RSRQ
-10
SINR
14
"""

def main():
    ap = argparse.ArgumentParser(description="Ethical cellular-router status auditor")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_an = sub.add_parser("analyze", help="analyze a status page saved as text")
    p_an.add_argument("file")
    sub.add_parser("demo", help="run on built-in sample")
    args = ap.parse_args()
    if args.cmd == "demo":
        return analyze(DEMO_TEXT)
    with open(args.file, encoding="utf-8", errors="replace") as fh:
        return analyze(fh.read())

if __name__ == "__main__":
    sys.exit(main())
