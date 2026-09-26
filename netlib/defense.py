"""Defense actions — the 'remove' half of incident response, done legally.

Allowed (defensive, on YOUR equipment only):
  * block_host(ip)      : add a firewall deny rule on THIS machine (iptables/
                          pf), or print the exact router-side rule to paste.
  * lan_blocklist()     : read current block rules so you can audit them.
  * evict_plan(mac,ip)  : step-by-step eviction of a rogue WI-FI client via
                          YOUR router admin (block MAC / change PSK). Emits
                          instructions + optionally an SNMP-less checklist;
                          it never injects frames itself from this tool.
Refused (offensive — see ethics.py):
  * anything aimed at a public/internet IP ("reverse attack", honeypunish,
    credential stuffing back at attacker, packet injection to third parties).
"""
from __future__ import annotations

import shutil
import subprocess

from . import ethics
from .spoof import Finding


def _sudo(cmd: list[str], dry_run: bool = True) -> tuple[bool, str]:
    """Run privileged defense command unless dry_run."""
    printable = " ".join(cmd)
    if dry_run:
        return False, f"[dry-run] would run: sudo {printable}"
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        ok = r.returncode == 0
        return ok, (r.stdout or r.stderr or "").strip() or \
               ("ok" if ok else f"failed rc={r.returncode}")
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def block_host(ip: str, comment: str = "router-watch-block",
               dry_run: bool = True) -> list[Finding]:
    """Block inbound+outbound traffic to/from ip ON THIS MACHINE's firewall.
    Only permitted for LAN-owned IPs; remote IPs belong in your ROUTER's
    blocklist (we print instructions instead of touching carrier space)."""
    findings: list[Finding] = []
    if not ethics.is_lan_owned(ip):
        findings.append(Finding(
            "WARN", "Remote IP — no local action taken",
            f"{ip} is not on your LAN and every logged packet from it was "
            "already DROPPED by your router. Nothing to remove here. If you "
            "still want to pre-deny it, add it in the AT&T router under "
            "Home Network > Firewall > Block Sites, or use a DNS sinkhole "
            "(Pi-hole/NextDNS) — both are defensive and legal."))
        return findings
    ethics.require_lan_target(ip, "block_host")
    if shutil.which("iptables"):
        cmd = ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]
        ok, out = _sudo(cmd, dry_run)
        findings.append(Finding("INFO", "iptables INPUT deny",
                                f"{ip}: {'applied' if ok and dry_run is False else out}"))
        cmd2 = ["iptables", "-I", "OUTPUT", "1", "-d", ip, "-j", "DROP"]
        ok2, out2 = _sudo(cmd2, dry_run)
        findings.append(Finding("INFO", "iptables OUTPUT deny",
                                f"{ip}: {'applied' if ok2 and dry_run is False else out2}"))
    elif shutil.which("pfctl"):
        anchor = f"block in quick from {ip} # {comment}\n"
        findings.append(Finding("INFO", "macOS pf rule",
                                "Add to /etc/pf.anchors/routerwatch:\n" + anchor))
    else:
        findings.append(Finding("WARN", "No supported firewall CLI",
                                "Apply the block in your OS GUI or router UI."))
    findings.append(Finding(
        "INFO", "Router-side eviction (preferred)",
        "For a device on your Wi-Fi: Smart Home Manager app > Devices > "
        "select device > Block, OR router admin 192.168.1.254 > Wi-Fi > "
        "MAC filtering = On and deny its MAC. Then change the WPA key — a "
        "rogue that learned the old password is gone permanently."))
    return findings


def lan_blocklist() -> list[Finding]:
    """Show existing local firewall DROP rules so blocks stay auditable."""
    findings: list[Finding] = []
    if shutil.which("iptables"):
        try:
            r = subprocess.run(["iptables", "-S"], capture_output=True,
                               text=True, timeout=8)
            rules = [ln for ln in r.stdout.splitlines()
                     if "DROP" in ln or "REJECT" in ln]
            findings.append(Finding("INFO", "Active local deny rules",
                                    "\n".join(rules) or "(none)"))
        except Exception as e:  # noqa: BLE001
            findings.append(Finding("WARN", "Could not read iptables", str(e)))
    else:
        findings.append(Finding("INFO", "iptables not present",
                                "On Windows use: netsh advfirewall show "
                                "allprofiles; macOS: pfctl -sr"))
    return findings


def evict_plan(mac: str, ip: str) -> list[Finding]:
    """Human-executable eviction plan for a rogue LAN/Wi-Fi client."""
    ethics.require_lan_target(ip, "evict_plan")
    return [
        Finding("WARN", "Eviction steps (do these in order)",
                f"Target {ip} / {mac}:\n"
                "1. Router admin (192.168.1.254) → confirm MAC in client list.\n"
                "2. Enable MAC filtering and EXCLUDE it (allow-list mode).\n"
                "3. Change WPA2 passphrase (Settings→Wi-Fi→Password) — forces\n"
                "   re-auth of everyone; rogue without new PSK stays out.\n"
                "4. Disable WPS (classic bypass of MAC filtering).\n"
                "5. Reboot router; watch DHCP leases page for its return.\n"
                "6. If it persists → someone has your PSK shared widely;\n"
                "   rotate again and stop sharing."),
        Finding("INFO", "Why not deauth it from here?",
                "Sending deauthentication frames is only lawful against "
                "your own AP's clients using your own hardware in monitor "
                "mode; this tool does not do radio injection. The router's\n"
                "own kick/block button achieves the same result legally."),
    ]
