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
from netlib import defense as D
from netlib import dns as dnsmod
from netlib import egress as E
from netlib import ethics
from netlib import firewalllog as FW
from netlib import hosts as H
from netlib import ports as P
from netlib import privacy as PR
from netlib import sniffer as S
from netlib import spoof
from netlib import threatintel as TI
from netlib import watcher as W


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


def _show(findings):
    order = {"CRITICAL": 0, "WARN": 1, "INFO": 2}
    findings = sorted(findings, key=lambda f: order.get(f.severity, 3))
    for f in findings:
        marker = {"CRITICAL": "!!!", "WARN": " ! ", "INFO": " . "}[f.severity]
        print(f"[{marker}] {f.severity}: {f.title}\n      {f.detail}")
    crit = sum(1 for f in findings if f.severity == "CRITICAL")
    warn = sum(1 for f in findings if f.severity == "WARN")
    print(f"\nSummary: {crit} critical, {warn} warnings.")


def cmd_logscan(args):
    text = open(args.file).read()
    events = FW.parse_log(text)
    if not events:
        print("[!] No parseable log lines (expected columns: date/time, "
              "src IP, dst IP, proto, reason)")
        return
    print(f"[*] Parsed {len(events)} entries. Clustering sources ...")
    profiles, findings = FW.analyze(events, identify=not args.no_id)
    print(f"\n=== Top sources ===")
    for p in profiles[:args.top]:
        risk, why = p.score()
        print(f"  {p.ip:<18} drops={p.count:<5} protos={','.join(p.protos)}"
              f" risk={risk}/100  {'; '.join(why)}")
    print("\n=== Findings ===")
    _show(findings)


def cmd_whois(args):
    for ip in args.ips:
        info = TI.classify(ip)
        print(f"{ip}: rdns={info['rdns'] or '-'} org={info['org'] or '-'} "
              f"name={info['name'] or '-'} cc={info['country'] or '-'}\n"
              f"   -> {info['category']}: {info['verdict']}")


def cmd_block(args):
    _show(D.block_host(args.ip, dry_run=not args.apply))


def cmd_evict(args):
    _show(D.evict_plan(args.mac, args.ip))


def cmd_rules(args):
    _show(D.lan_blocklist())


def cmd_egress(args):
    if args.watch:
        _show(E.watch(seconds=args.seconds))
    else:
        _show(E.top_egress(n=args.top))


def cmd_privacy(args):
    lines, findings = PR.dns_leaks()
    for ln in lines:
        print("[.] " + ln)
    print("[.] Routes: " + "; ".join(PR.routes()))
    env = PR.proxy_env()
    print("[.] Proxy env: " + (str(env) if env else "none set"))
    scope = PR.webScope()
    print(f"[.] A website currently sees you as: "
          f"{scope.get('origin_seen_by_site', scope.get('error'))}")
    findings += PR.hardening_findings(scope)
    print("=== Privacy findings ===")
    _show(findings)


def cmd_refuse(args):
    # Deliberate dead end so the CLI answers this question itself.
    try:
        ethics.refuse_offensive(args.feature)
    except PermissionError as e:
        print(f"[denied] {e}", file=sys.stderr)
        sys.exit(2)


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

    ls = sub.add_parser("logscan", help="analyze router firewall log file")
    ls.add_argument("file")
    ls.add_argument("--top", type=int, default=10)
    ls.add_argument("--no-id", action="store_true",
                    help="skip RDAP/rdns identification (fully offline)")
    ls.set_defaults(fn=cmd_logscan)

    w = sub.add_parser("whois", help="passive owner ID for IP(s)")
    w.add_argument("ips", nargs="+")
    w.set_defaults(fn=cmd_whois)

    b = sub.add_parser("block", help="defensive firewall block (LAN IPs only)")
    b.add_argument("ip")
    b.add_argument("--apply", action="store_true",
                   help="actually run iptables (default is dry-run)")
    b.set_defaults(fn=cmd_block)

    ev = sub.add_parser("evict", help="rogue Wi-Fi client eviction plan")
    ev.add_argument("mac")
    ev.add_argument("ip")
    ev.set_defaults(fn=cmd_evict)

    rl = sub.add_parser("rules", help="show current local deny rules")
    rl.set_defaults(fn=cmd_rules)

    eg = sub.add_parser("egress", help="what your computer is sending out NOW")
    eg.add_argument("--watch", action="store_true",
                    help="sample over time to catch new endpoints")
    eg.add_argument("--seconds", type=int, default=15)
    eg.add_argument("--top", type=int, default=12)
    eg.set_defaults(fn=cmd_egress)

    pv = sub.add_parser("privacy", help="DNS/route/IPv6 leak + fingerprint scope")
    pv.set_defaults(fn=cmd_privacy)

    rf = sub.add_parser("refuse", help="ask why an offensive feature won't exist")
    rf.add_argument("feature")
    rf.set_defaults(fn=cmd_refuse)

    wt = sub.add_parser("watch", help="background alerting daemon")
    wt.add_argument("--interval", type=int, default=600)
    def _watch(a):
        W.run(interval=a.interval)
    wt.set_defaults(fn=_watch)

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
