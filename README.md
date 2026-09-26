# Router Watch — ethical home-network intrusion audit & privacy shield

Stdlib-only Python. Observe, identify, harden. **Never attack.**

## Commands
| Command | What it does |
|---|---|
| `python3 router_watch.py audit --save-baseline` | Full LAN audit (hosts, spoofing, sniffers, open ports, DNS). Save when clean. |
| `python3 router_watch.py audit --html report.html` | Re-audit + severity-ranked findings + HTML report (diffs vs baseline). |
| `python3 router_watch.py logscan firewall_logs/att_log1.txt` | Parse router firewall drop-log: cluster sources, score behavior (scan vs benign retransmit), auto-ID owners via RDAP/rDNS. `--no-id` = offline. |
| `python3 router_watch.py whois 52.70.199.254 ...` | Passive owner identification for any IP(s) in your logs. |
| `python3 router_watch.py egress [--watch --seconds 30]` | Live view of what YOUR computer is sending out and to whom (ss/lsof based). |
| `python3 router_watch.py privacy` | DNS-resolver leak check, IPv6-egress leak, proxy env, what a website sees right now, hardening checklist. |
| `python3 router_watch.py block <LAN-IP> [--apply]` | Defensive firewall block on this machine (dry-run default). Refuses remote IPs by design. |
| `python3 router_watch.py evict <MAC> <LAN-IP>` | Step-by-step rogue Wi-Fi client eviction via your router. |
| `python3 router_watch.py rules` | Audit current local deny rules. |
| `python3 router_watch.py watch --interval 600` | Background daemon: alerts the moment a new host or MAC swap appears. |
| `python3 router_watch.py refuse "reverse attack"` | The tool's own answer to offensive requests. |

## Ethics (non-negotiable, see netlib/ethics.py)
- **No reverse attacks, ever.** Hitting back at internet IPs is illegal (CFAA et al.) even if they scanned you — and your firewall already dropped them. Response = block, evict, rotate credentials.
- Action commands (`block`, `evict`) are guarded to RFC1918 LAN space you administer; remote IPs get router-side instructions instead.
- Identification is passive registry data only (RDAP/rDNS); we never probe third-party hosts.
- Only audit networks you own or administer.

## Reading your AT&T gateway
- "Generic Discards" rows = inbound packets **blocked** by the firewall. Seeing CloudFront/Apple/Google/Akamai/Twilio IPs with backoff-timer patterns = normal reply traffic from services your devices use. Not intruders.
- Who can see your router page: anyone who reaches `http://192.168.1.254` (devices on your LAN) plus AT&T management (TR-069/Firmware). Disable remote administration, keep unique admin password, and check the client list against `audit` output.
