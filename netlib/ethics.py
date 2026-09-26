"""Ethics gate — the hard line this tool will not cross.

Every network module that could touch anything beyond *observing your own
network* must call one of these guards first. If you are reading this code
wondering "can I just flip a flag to attack back?" — no, and deliberately so:

1. Offensive actions (blocking/evicting/killing traffic) are only permitted
   against targets on RFC1918/RFC6598 space that you administer, and only via
   standard OS/router mechanisms you control (firewall rules, deauth frames
   from YOUR AP). Hitting an arbitrary internet IP is illegal under CFAA-type
   laws regardless of what their log said.
2. Counter-strike / reverse-attack primitives do not exist in this codebase
   and won't be added. There is nothing to disable.
3. Identification is passive: WHOIS + reverse DNS + pattern analysis of data
   YOU already have. No scanning of third-party infrastructure.
"""
from __future__ import annotations

import ipaddress


class EthicsError(PermissionError):
    pass


def is_ownable(ip: str) -> bool:
    """True for addresses in ranges a home admin legitimately controls."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.is_private or a.is_loopback or a.is_link_local:
        return True
    # CGNAT 100.64.0.0/10 (what AT&T hands out as WAN) — technically carrier
    # space; we treat it as "yours to observe" but never as a target.
    return False


def is_lan_owned(ip: str) -> bool:
    """Stricter: private LAN space only (safe targets for local block/evict)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private and not a.is_loopback


def require_lan_target(ip: str, action: str) -> None:
    """Guard before any packet-leaving-the-box 'remove' action."""
    if not is_lan_owned(ip):
        raise EthicsError(
            f"REFUSED: '{action}' against {ip}. This tool only takes action "
            "against devices on your own private LAN. The internet IPs in "
            "your firewall log were DROPPED BY YOUR ROUTER already — they "
            "never reached you. 'Removing' or retaliating against remote "
            "hosts is both unnecessary and illegal. See netlib/ethics.py.")


def refuse_offensive(feature: str) -> None:
    """Named dead-end for anything offensive someone might try to wire in."""
    raise EthicsError(
        f"REFUSED: '{feature}' is an offensive capability. Router Watch is "
        "observe-and-harden only. Legitimate response to an intruder is: "
        "block (via your router/firewall), evict (deauth from YOUR AP), "
        "rotate credentials, update firmware. Not attack-back.")
