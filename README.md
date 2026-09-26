# Router Watch — Ethical Home-Network Intrusion Check

A small Python toolkit to help you audit **your own** router and Wi-Fi network:

- See what devices are connected (ARP table + subnet scan)
- Detect MAC spoofing / duplicate IPs (classic "evil twin inside your LAN" signs)
- Detect promiscuous-mode NICs (a device sniffing everyone's traffic)
- Find open ports / UPnP holes on your router
- Spot DNS hijacking (router changed your DNS behind your back)
- Baseline & diff scans so you can see what CHANGED since last week
- Generate a human-readable HTML report with red flags

## Ethics / legal note

Only run this against networks **you own or administer**. The tool refuses to
target anything outside your local subnet by default. It performs passive reads
and light, standard checks (ARP ping, TCP connect-scan of a few ports) — no
exploits, no deauth attacks, no password cracking.

## Usage

```bash
# 1. Auto-detect gateway + interface, full audit
python3 router_watch.py audit

# 2. Save a baseline, then re-run later and see what changed
python3 router_watch.py audit --save-baseline
python3 router_watch.py audit --diff-baseline

# 3. Individual checks
python3 router_watch.py hosts          # who's on the LAN
python3 router_watch.py spoof          # MAC/IP conflict detection
python3 router_watch.py sniffer        # promiscuous-mode detection
python3 router_watch.py ports          # router open-port probe
python3 router_watch.py dns            # DNS hijack check

# 4. Pretty report
python3 router_watch.py audit --html report.html
```

Works best as root (needs raw sockets for the sniffer check). Without root it
will skip that check and still do everything else.

## Files

- `router_watch.py` — CLI entry point
- `netlib/` — check modules (hosts, spoof, sniffer, ports, dns, baseline)
