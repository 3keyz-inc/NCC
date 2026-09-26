#!/usr/bin/env python3
"""router_watch.py — ethical, read-only intrusion checks for YOUR OWN router/LAN.

See README.md. Only audit networks you own or administer.
"""
from __future__ import annotations

import argparse
import html
import ipaddress
import subprocess
import sys
from dataclasses import asdict

from netlib import baseline as bl
from netlib import dns as dnsmod
from netlib import hosts as H
from netlib import ports as P
from netlib import sniffer as S
from netlib import spoof


def gateway_mac_for(gateway: str, host_list) -> str:
    for h in host_list:
        if h.ip == gateway:
            return h.mac
    return ""


def run_audit(args) -> tuple[list, list]:
    gw, iface = H.default_gateway()
    print(f"[*] Gateway: {gw}  Interface: {iface or '?'}")

    cidrs = H.local_interface_cidr(iface) or [gw + "/24"]
    all_hosts = []
    seen = set()
    # Always include ARP table (covers other subnets/VLANs we saw traffic from)
    for h in H.arp_table():
        if h.key() not in seen:
            seen.add(h.key())
            all_hosts.append(h)
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if not net.network_address.is_private:
            continue
        if net.num_addresses > 1024 and not args.full_scan:
            print(f"[!] Skipping large subnet {cidr} (use --full-scan to include)")
            continue
        print(f"[*] Sweeping {cidr} ...")
        for h in H.scan_subnet(str(net)):
            if h.key() not in seen:
                seen.add(h.key())
                all_hosts.append(h)

    gmac = gateway_mac_for(gw, all_hosts)
    base = bl.load_baseline()
    findings: list[spoof.Finding] = []
    findings += spoof.check_spoofing(all_hosts, base, gmac)
    if base:
        findings += bl.diff_hosts(all_hosts, base)
    else:
        findings.append(spoof.Finding("INFO", "No baseline yet",
                                      "Run with --save-baseline when you know "
                                      "your network is clean."))
    findings += S.check_promisc()
    findings += P.check_router_ports(gw)
    findings += P.check_wan_exposure(gw)
    print("[*] Checking DNS integrity ...")
    findings += dnsmod.check_dns()

    # sort by severity
    order = {"CRITICAL": 0, "WARN": 1, "INFO": 2}
    findings.sort(key=lambda f: order.get(f.severity, 3))

    print(f"\n=== {len(all_hosts)} hosts found ===")
    for h in sorted(all_hosts, key=lambda x: ipaddress.ip_address(x.ip)):
        name = h.hostname or H.reverse_dns(h.ip) or ""
        print(f"  {h.ip:<16} {h.mac:<18} {name}")

    print("\n=== Findings ===")
    for f in findings:
        marker = {"CRITICAL": "!!!", "WARN": " ! ", "INFO": " . "}[f.severity]
        print(f"[{marker}] {f.severity}: {f.title}\n      {f.detail}")

    crit = sum(1 for f in findings if f.severity == "CRITICAL")
    warn = sum(1 for f in findings if f.severity == "WARN")
    print(f"\nSummary: {crit} critical, {warn} warnings.")

    if args.save_baseline:
        path = bl.save_baseline(all_hosts, gw, gmac)
        print(f"[*] Baseline saved to {path}")
    if args.html:
        write_html(args.html, gw, iface, all_hosts, findings)
        print(f"[*] Report written to {args.html}")
    return all_hosts, findings


def write_html(path: str, gw: str, iface: str, hosts, findings):
    sev_color = {"CRITICAL": "#c0392b", "WARN": "#e67e22", "INFO": "#2980b9"}
    rows = "".join(
        f"<tr><td>{html.escape(h.ip)}</td><td>{html.escape(h.mac)}</td>"
        f"<td>{html.escape(h.hostname or H.reverse_dns(h.ip))}</td>"
        f"<td>{html.escape(h.source)}</td></tr>"
        for h in hosts)
    finds = "".join(
        f"<div style='border-left:5px solid {sev_color[f.severity]};"
        f"padding:8px;margin:8px 0;background:#fafafa'>"
        f"<b style='color:{sev_color[f.severity]}'>{f.severity}</b> — "
        f"{html.escape(f.title)}<br><small>{html.escape(f.detail)}</small></div>"
        for f in findings)
    doc = f"""<!doctype html><meta charset="utf-8">
<title>Router Watch report</title>
<style>body{{font-family:system-ui;max-width:900px;margin:2em auto}}
table{{border-collapse:collapse}}td,th{{border:1px solid #ccc;padding:4px 10px}}</style>
<h1>Router Watch — home network audit</h1>
<p>Gateway <code>{html.escape(gw)}</code> on <code>{html.escape(iface)}</code>.
Only audit networks you own.</p>
<h2>Findings</h2>{finds or '<p>No findings.</p>'}
<h2>Hosts ({len(hosts)})</h2>
<table><tr><th>IP</th><th>MAC</th><th>Name</th><th>Source</th></tr>{rows}</table>
"""
    with open(path, "w") as f:
        f.write(doc)


def cmd_hosts(args):
    gw, iface = H.default_gateway()
    for h in H.scan_subnet(args.cidr or gw + "/24"):
        print(f"{h.ip:<16} {h.mac:<18} {h.source}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="full intrusion audit")
    a.add_argument("--save-baseline", action="store_true")
    a.add_argument("--diff-baseline", action="store_true",
                   help="(baseline diff runs automatically if file exists)")
    a.add_argument("--html", metavar="FILE")
    a.add_argument("--full-scan", action="store_true",
                   help="also sweep subnets larger than /22")
    a.set_defaults(fn=run_audit)

    h = sub.add_parser("hosts", help="list LAN hosts")
    h.add_argument("--cidr")
    h.set_defaults(fn=cmd_hosts)

    s = sub.add_parser("spoof", help="MAC/IP conflict check only")
    s.set_defaults(fn=lambda a: [print(vars(f)) for f in spoof.check_spoofing(
        H.arp_table(), bl.load_baseline(),
        gateway_mac_for(H.default_gateway()[0], H.arp_table()))])

    n = sub.add_parser("sniffer", help="promiscuous-mode check")
    n.set_defaults(fn=lambda a: [print(vars(f)) for f in S.check_promisc()])

    p = sub.add_parser("ports", help="gateway port probe")
    p.set_defaults(fn=lambda a: [print(vars(f)) for f in
                                 P.check_router_ports(H.default_gateway()[0])])

    d = sub.add_parser("dns", help="DNS hijack check")
    d.set_defaults(fn=lambda a: [print(vars(f)) for f in dnsmod.check_dns()])

    args = ap.parse_args()
    try:
        args.fn(args)
    except PermissionError as e:
        print(f"[denied] {e}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
