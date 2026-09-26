"""Firewall-log analyzer: ingest AT&T/generic drop logs, cluster sources,
score behavior (scan vs retransmit vs flood), and hand off to passive
threatintel for identification. Works entirely offline except RDAP lookups.
"""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from . import threatintel
from .spoof import Finding

TS = re.compile(r"(\d{4})[-/](\d{2})[-/](\d{2})[ T](\d{2}):(\d{2}):(\d{2})")
IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


@dataclass
class Event:
    ts: datetime
    src: str
    dst: str
    proto: str
    reason: str


@dataclass
class SourceProfile:
    ip: str
    events: list = field(default_factory=list)
    protos: set = field(default_factory=set)
    dsts: set = field(default_factory=set)

    @property
    def count(self) -> int:
        return len(self.events)

    def gaps(self) -> list[float]:
        ts = sorted(e.ts for e in self.events)
        return [(b - a).total_seconds() for a, b in zip(ts, ts[1:])]

    def score(self) -> tuple[int, list[str]]:
        """Heuristic 0-100 suspicion + reasons. Dropped inbound packets are
        NORMAL; we only escalate on true attack signatures."""
        risk, why = 0, []
        n = self.count
        g = self.gaps()
        # burst rate: >60 drops/min sustained
        if n >= 30:
            span = (max(e.ts for e in self.events) -
                    min(e.ts for e in self.events)).total_seconds() or 1
            rate = n / (span / 60.0)
            if rate > 60:
                risk += 40
                why.append(f"high packet rate ({rate:.0f}/min)")
        # port-scan signature: many distinct destinations in short window
        if len(self.dsts) >= 8:
            risk += 25
            why.append(f"{len(self.dsts)} distinct destination IPs")
        # perfectly periodic keepalives = benign service retries
        if g and all(abs(x - g[0]) < 2.5 for x in g) and g[0] > 30:
            risk -= 30
            why.append(f"regular {g[0]:.0f}s interval — retry/keepalive timer,"
                       " not human-driven")
        # exponential backoff ladder = client retransmission (benign)
        ints = [round(x) for x in g if 0.5 < x < 400]
        if len(ints) > 6:
            doubles = sum(1 for a, b in zip(ints, ints[1:])
                          if 1.6 <= b / max(a, 1) <= 2.6)
            if doubles >= len(ints) * 0.3:
                risk -= 25
                why.append("exponential-backoff retransmit pattern (benign)")
        try:
            if ipaddress.ip_address(self.ip).is_private or \
               self.ip.startswith("100.64.") or self.ip.startswith("100.6"):
                pass  # CGNAT dest side handled elsewhere
        except ValueError:
            pass
        return max(0, min(100, risk)), why


def parse_log(text: str) -> list[Event]:
    events: list[Event] = []
    for line in text.splitlines():
        m_ts = TS.search(line)
        ips = IPV4.findall(line)
        if not m_ts or len(ips) < 2:
            continue
        proto = "TCP" if re.search(r"\bTCP\b", line, re.I) else \
                "UDP" if re.search(r"\bUDP\b", line, re.I) else "?"
        reason_m = re.search(r"(Generic Discards|Deny|Drop|Block|Scan|"
                             r"Attack|Flood|SYN)", line, re.I)
        try:
            ts = datetime(*map(int, m_ts.groups()))
        except ValueError:
            continue
        events.append(Event(ts, ips[0], ips[1], proto,
                            reason_m.group(1) if reason_m else "log entry"))
    return events


def analyze(events: list[Event], identify: bool = True) -> \
        tuple[list[SourceProfile], list[Finding]]:
    by_src: dict[str, SourceProfile] = {}
    for e in events:
        p = by_src.setdefault(e.src, SourceProfile(e.src))
        p.events.append(e)
        p.protos.add(e.proto)
        p.dsts.add(e.dst)
    profiles = sorted(by_src.values(), key=lambda p: -p.count)
    findings: list[Finding] = []
    for p in profiles:
        risk, why = p.score()
        info = threatintel.classify(p.ip) if identify else {}
        label = info.get("category", "?") if identify else ""
        verdict = info.get("verdict", "") if identify else ""
        sev = "CRITICAL" if risk >= 70 else "WARN" if risk >= 40 else "INFO"
        msg = (f"{p.ip} [{p.count} pkts dropped | {label}] — risk {risk}/100."
               f" {'; '.join(why) if why else 'no attack signature'}."
               + (f" Owner: {info.get('org') or info.get('rdns') or 'n/a'}."
                  if identify else ""))
        findings.append(Finding(sev, "Firewall log source", msg))
    total = len(events)
    findings.insert(0, Finding(
        "INFO", "Log summary",
        f"{total} dropped entries from {len(profiles)} unique sources. "
        "'Generic Discards' means your firewall BLOCKED these — nothing "
        "reached your computers. This is the firewall working, not failing."))
    return profiles, findings
