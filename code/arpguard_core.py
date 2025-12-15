#!/usr/bin/env python3
"""
arpguard_core.py
ARPGuard: Lightweight ARP spoofing detector for offline PCAP analysis (and reuse by the web dashboard).

This implementation is intentionally dependency-light:
- It can parse classic PCAP (DLT_EN10MB) using the Python standard library.
- If Scapy is installed, it can be used, but it is not required.

Design intent:
- Parse ARP traffic from a capture.
- Maintain an IP<->MAC mapping table observed over time.
- Emit anomaly events when mappings change in suspicious ways.

Notes on protocol assumptions:
- ARP resolves IPv4 addresses to MAC addresses on a local Ethernet segment. Hosts maintain ARP caches and
  may update cached entries when they see ARP replies (and sometimes requests), which enables spoofing. [1]

References (IEEE-style):
[1] D. C. Plummer, “An Ethernet Address Resolution Protocol,” RFC 826, Nov. 1982.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple, Any, Iterable
import argparse
import json
import os
import struct
import socket

# Optional Scapy support (not required)
try:  # pragma: no cover
    from scapy.all import ARP as SCAPY_ARP, rdpcap as scapy_rdpcap  # type: ignore
except Exception:  # pragma: no cover
    SCAPY_ARP = None  # type: ignore
    scapy_rdpcap = None  # type: ignore


@dataclass
class ArpEvent:
    ts: float
    event_type: str              # e.g., "IP_MAC_CONFLICT", "MAC_IP_FANOUT", "UNSOLICITED_REPLY"
    severity: str                # e.g., "LOW", "MEDIUM", "HIGH"
    ip: Optional[str] = None
    mac: Optional[str] = None
    old_mac: Optional[str] = None
    new_mac: Optional[str] = None
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisResult:
    hosts_ip_to_mac: Dict[str, str]
    hosts_mac_to_ips: Dict[str, List[str]]
    events: List[ArpEvent]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hosts_ip_to_mac": dict(self.hosts_ip_to_mac),
            "hosts_mac_to_ips": {k: list(v) for k, v in self.hosts_mac_to_ips.items()},
            "events": [e.to_dict() for e in self.events],
        }


def _normalize_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    return mac.lower()


def _mac_bytes_to_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _ip_bytes_to_str(b: bytes) -> str:
    return socket.inet_ntoa(b)


def _read_pcap_packets(path: str) -> Iterable[Tuple[float, bytes]]:
    """
    Minimal classic-PCAP reader supporting Ethernet captures (DLT_EN10MB).
    Supports microsecond and nanosecond timestamp magic numbers.
    """
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) != 24:
            raise ValueError("Invalid PCAP: file too small for global header.")

        magic = gh[:4]
        # Determine endianness + ts resolution
        if magic == b"\xd4\xc3\xb2\xa1":      # little-endian, usec
            endian = "<"
            ts_res = 1e-6
        elif magic == b"\xa1\xb2\xc3\xd4":    # big-endian, usec
            endian = ">"
            ts_res = 1e-6
        elif magic == b"\x4d\x3c\xb2\xa1":    # little-endian, nsec
            endian = "<"
            ts_res = 1e-9
        elif magic == b"\xa1\xb2\x3c\x4d":    # big-endian, nsec
            endian = ">"
            ts_res = 1e-9
        else:
            raise ValueError("Unsupported PCAP magic number.")

        _, _, _, _, snaplen, network = struct.unpack(endian + "HHIIII", gh[4:])
        if network != 1:
            raise ValueError(f"Unsupported linktype (expected Ethernet=1), got {network}.")

        while True:
            ph = f.read(16)
            if not ph:
                break
            if len(ph) != 16:
                raise ValueError("Truncated PCAP packet header.")
            ts_sec, ts_sub, incl_len, orig_len = struct.unpack(endian + "IIII", ph)
            data = f.read(incl_len)
            if len(data) != incl_len:
                raise ValueError("Truncated PCAP packet data.")
            ts = float(ts_sec) + float(ts_sub) * ts_res
            yield ts, data


def _iter_arp_from_pcap_stdlib(path: str) -> Iterable[Tuple[float, str, str, str, str, int]]:
    """
    Yield (ts, spa, sha, tpa, tha, op) for each ARP packet.
    Only supports Ethernet+IPv4 ARP frames.
    """
    for ts, frame in _read_pcap_packets(path):
        if len(frame) < 14:
            continue
        eth_type = struct.unpack("!H", frame[12:14])[0]
        if eth_type != 0x0806:  # ARP
            continue
        if len(frame) < 14 + 28:
            continue

        arp = frame[14:42]
        htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", arp[0:8])
        if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
            continue

        sha = _mac_bytes_to_str(arp[8:14])
        spa = _ip_bytes_to_str(arp[14:18])
        tha = _mac_bytes_to_str(arp[18:24])
        tpa = _ip_bytes_to_str(arp[24:28])

        yield ts, spa, sha, tpa, tha, int(op)


def _iter_arp_from_pcap(path: str) -> Iterable[Tuple[float, str, str, str, str, int]]:
    """
    Prefer Scapy if available; otherwise use the standard-library parser.
    """
    if scapy_rdpcap is not None and SCAPY_ARP is not None:  # pragma: no cover
        pkts = scapy_rdpcap(path)
        for p in pkts:
            if SCAPY_ARP not in p:
                continue
            a = p[SCAPY_ARP]
            ts = float(getattr(p, "time", 0.0))
            spa = getattr(a, "psrc", None)
            tpa = getattr(a, "pdst", None)
            sha = _normalize_mac(getattr(a, "hwsrc", None))
            tha = _normalize_mac(getattr(a, "hwdst", None))
            op = int(getattr(a, "op", 0))
            if spa and tpa and sha and tha:
                yield ts, spa, sha, tpa, tha, op
        return

    # Fallback: stdlib PCAP parsing (portable)
    yield from _iter_arp_from_pcap_stdlib(path)


def analyze_pcap(
    pcap_path: str,
    *,
    conflict_severity: str = "HIGH",
    unsolicited_reply_severity: str = "MEDIUM",
    mac_fanout_threshold: int = 3,
) -> AnalysisResult:
    """
    Analyze a capture and return host tables + detected ARP anomaly events.

    Heuristics implemented:
    1) IP->MAC conflict: same IP observed mapping to multiple MACs over time (classic ARP spoof indicator).
    2) Unsolicited ARP reply: ARP is-at (op=2) seen without a recently observed who-has for the same pairing.
       This is a soft signal; legitimate gratuitous ARP exists.
    3) MAC fanout: one MAC claiming many IPs (can indicate poisoning or misconfig). Flag only if above threshold.
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    ip_to_mac: Dict[str, str] = {}
    mac_to_ips: Dict[str, set] = {}
    events: List[ArpEvent] = []

    # Track last "who-has" requests to support unsolicited reply detection
    # key: (requester_ip, target_ip) -> last timestamp
    recent_who_has: Dict[Tuple[str, str], float] = {}

    for ts, spa, sha, tpa, tha, op in _iter_arp_from_pcap(pcap_path):
        sha = _normalize_mac(sha)

        if not spa or not sha:
            continue

        # Update mac->ips fanout
        mac_to_ips.setdefault(sha, set()).add(spa)

        # who-has
        if op == 1 and tpa:
            recent_who_has[(spa, tpa)] = ts

        # unsolicited reply
        if op == 2 and tpa:
            key = (tpa, spa)  # requester=target host, target=sender ip
            last = recent_who_has.get(key)
            if last is None or (ts - last) > 5.0:
                events.append(
                    ArpEvent(
                        ts=ts,
                        event_type="UNSOLICITED_REPLY",
                        severity=unsolicited_reply_severity,
                        ip=spa,
                        mac=sha,
                        details=f"ARP reply (is-at) for {spa} seen without a recent who-has from {tpa}.",
                    )
                )

        # IP->MAC conflict
        old = ip_to_mac.get(spa)
        if old is None:
            ip_to_mac[spa] = sha
        else:
            if old != sha:
                events.append(
                    ArpEvent(
                        ts=ts,
                        event_type="IP_MAC_CONFLICT",
                        severity=conflict_severity,
                        ip=spa,
                        old_mac=old,
                        new_mac=sha,
                        details=f"Observed {spa} map to {old} then {sha}. Potential ARP spoof/poisoning.",
                    )
                )
                ip_to_mac[spa] = sha

    # MAC fanout (post-pass)
    hosts_mac_to_ips: Dict[str, List[str]] = {}
    for mac, ips in mac_to_ips.items():
        ip_list = sorted(list(ips))
        hosts_mac_to_ips[mac] = ip_list
        if len(ip_list) >= mac_fanout_threshold:
            events.append(
                ArpEvent(
                    ts=0.0,
                    event_type="MAC_IP_FANOUT",
                    severity="LOW",
                    mac=mac,
                    details=f"MAC {mac} claims {len(ip_list)} IPs: {', '.join(ip_list)}",
                )
            )

    events_sorted = sorted(events, key=lambda e: (e.ts == 0.0, e.ts))

    return AnalysisResult(
        hosts_ip_to_mac=dict(sorted(ip_to_mac.items(), key=lambda kv: kv[0])),
        hosts_mac_to_ips=hosts_mac_to_ips,
        events=events_sorted,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="ARPGuard core PCAP analyzer")
    parser.add_argument("pcap", help="Path to .pcap file")
    parser.add_argument("--json", dest="json_out", default=None, help="Write JSON output to this path")
    args = parser.parse_args()

    result = analyze_pcap(args.pcap)
    payload = result.to_dict()

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"[arpguard_core] Wrote results to: {args.json_out}")
    else:
        print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
