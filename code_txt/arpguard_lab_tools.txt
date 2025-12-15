#!/usr/bin/env python3
"""
arpguard_lab_tools.py
Utilities for the ARPGuard lab:
- Generate synthetic PCAPs for a benign ARP exchange and a controlled ARP spoofing scenario.
- Provide a one-command demo that generates captures and runs the ARPGuard analyzer.

This file is dependency-light and uses a minimal PCAP writer implemented with the standard library.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import List, Tuple
import struct
import socket

from arpguard_core import analyze_pcap


def _mac_str_to_bytes(mac: str) -> bytes:
    parts = mac.split(":")
    if len(parts) != 6:
        raise ValueError(f"Invalid MAC: {mac}")
    return bytes(int(p, 16) for p in parts)


def _ip_str_to_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)


def build_ethernet_header(dst_mac: str, src_mac: str, ethertype: int) -> bytes:
    return _mac_str_to_bytes(dst_mac) + _mac_str_to_bytes(src_mac) + struct.pack("!H", ethertype)


def build_arp_payload(op: int, sha: str, spa: str, tha: str, tpa: str) -> bytes:
    # Ethernet + IPv4 ARP
    htype = 1
    ptype = 0x0800
    hlen = 6
    plen = 4
    hdr = struct.pack("!HHBBH", htype, ptype, hlen, plen, op)
    return (
        hdr
        + _mac_str_to_bytes(sha)
        + _ip_str_to_bytes(spa)
        + _mac_str_to_bytes(tha)
        + _ip_str_to_bytes(tpa)
    )


def build_arp_frame(dst_mac: str, src_mac: str, *, op: int, sha: str, spa: str, tha: str, tpa: str) -> bytes:
    eth = build_ethernet_header(dst_mac, src_mac, 0x0806)
    arp = build_arp_payload(op, sha, spa, tha, tpa)
    return eth + arp


def write_pcap(path: str, packets: List[Tuple[float, bytes]]) -> str:
    """
    Write a classic PCAP (microsecond timestamps) with Ethernet linktype.
    """
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)

    # PCAP global header (little endian, microsecond)
    magic = 0xA1B2C3D4
    version_major = 2
    version_minor = 4
    thiszone = 0
    sigfigs = 0
    snaplen = 65535
    network = 1  # DLT_EN10MB

    with open(out, "wb") as f:
        f.write(struct.pack("<IHHIIII", magic, version_major, version_minor, thiszone, sigfigs, snaplen, network))
        for ts, data in packets:
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            incl_len = len(data)
            orig_len = len(data)
            f.write(struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len))
            f.write(data)

    return str(out)


def generate_benign_pcap(out_path: str) -> str:
    """
    Create a small capture with consistent IP<->MAC mappings:
    - Host asks for Gateway
    - Gateway replies with stable MAC
    - Host repeats later (same answer)
    """
    host_ip = "192.168.1.10"
    host_mac = "00:11:22:33:44:10"
    gw_ip = "192.168.1.1"
    gw_mac = "00:aa:bb:cc:dd:01"

    pkts: List[Tuple[float, bytes]] = []
    t = 1.0

    # who-has gw? (broadcast)
    pkts.append((t, build_arp_frame(
        dst_mac="ff:ff:ff:ff:ff:ff", src_mac=host_mac,
        op=1, sha=host_mac, spa=host_ip, tha="00:00:00:00:00:00", tpa=gw_ip
    )))
    t += 0.2

    # gw is-at (unicast to host)
    pkts.append((t, build_arp_frame(
        dst_mac=host_mac, src_mac=gw_mac,
        op=2, sha=gw_mac, spa=gw_ip, tha=host_mac, tpa=host_ip
    )))
    t += 0.8

    # repeat benign resolution
    pkts.append((t, build_arp_frame(
        dst_mac="ff:ff:ff:ff:ff:ff", src_mac=host_mac,
        op=1, sha=host_mac, spa=host_ip, tha="00:00:00:00:00:00", tpa=gw_ip
    )))
    t += 0.2
    pkts.append((t, build_arp_frame(
        dst_mac=host_mac, src_mac=gw_mac,
        op=2, sha=gw_mac, spa=gw_ip, tha=host_mac, tpa=host_ip
    )))

    return write_pcap(out_path, pkts)


def generate_attack_pcap(out_path: str) -> str:
    """
    Create a capture with a controlled ARP spoof pattern:
    - Host asks for Gateway
    - Real Gateway replies
    - Attacker later claims the same gateway IP with a different MAC (poisoning)
    """
    host_ip = "192.168.1.10"
    host_mac = "00:11:22:33:44:10"
    gw_ip = "192.168.1.1"
    gw_mac = "00:aa:bb:cc:dd:01"
    attacker_ip = "192.168.1.66"
    attacker_mac = "de:ad:be:ef:00:66"

    pkts: List[Tuple[float, bytes]] = []
    t = 1.0

    # host who-has gw
    pkts.append((t, build_arp_frame(
        dst_mac="ff:ff:ff:ff:ff:ff", src_mac=host_mac,
        op=1, sha=host_mac, spa=host_ip, tha="00:00:00:00:00:00", tpa=gw_ip
    )))
    t += 0.2

    # real gateway reply
    pkts.append((t, build_arp_frame(
        dst_mac=host_mac, src_mac=gw_mac,
        op=2, sha=gw_mac, spa=gw_ip, tha=host_mac, tpa=host_ip
    )))
    t += 1.0

    # attacker unsolicited poisoning replies (claim gw_ip)
    for _ in range(3):
        pkts.append((t, build_arp_frame(
            dst_mac=host_mac, src_mac=attacker_mac,
            op=2, sha=attacker_mac, spa=gw_ip, tha=host_mac, tpa=host_ip
        )))
        t += 0.15

    # host asks again; attacker wins race, gateway later responds
    pkts.append((t, build_arp_frame(
        dst_mac="ff:ff:ff:ff:ff:ff", src_mac=host_mac,
        op=1, sha=host_mac, spa=host_ip, tha="00:00:00:00:00:00", tpa=gw_ip
    )))
    t += 0.05
    pkts.append((t, build_arp_frame(
        dst_mac=host_mac, src_mac=attacker_mac,
        op=2, sha=attacker_mac, spa=gw_ip, tha=host_mac, tpa=host_ip
    )))
    t += 0.25
    pkts.append((t, build_arp_frame(
        dst_mac=host_mac, src_mac=gw_mac,
        op=2, sha=gw_mac, spa=gw_ip, tha=host_mac, tpa=host_ip
    )))

    return write_pcap(out_path, pkts)


def demo(out_dir: str) -> Tuple[str, str]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    benign = generate_benign_pcap(str(out / "benign_arp.pcap"))
    attack = generate_attack_pcap(str(out / "arp_spoof_attack.pcap"))

    res_benign = analyze_pcap(benign)
    res_attack = analyze_pcap(attack)

    print("\n=== BENIGN PCAP RESULTS ===")
    print(f"PCAP: {benign}")
    print(f"Events: {len(res_benign.events)}")
    for e in res_benign.events:
        print(f"  - {e.event_type} ({e.severity}) {e.details}")

    print("\n=== ATTACK PCAP RESULTS ===")
    print(f"PCAP: {attack}")
    print(f"Events: {len(res_attack.events)}")
    for e in res_attack.events:
        print(f"  - {e.event_type} ({e.severity}) {e.details}")

    return benign, attack


def main() -> None:
    parser = argparse.ArgumentParser(description="ARPGuard lab utilities")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_gen = sub.add_parser("generate", help="Generate benign and attack PCAPs")
    p_gen.add_argument("--out-dir", default="pcaps", help="Output directory for pcaps")

    p_demo = sub.add_parser("demo", help="Generate pcaps and run analyzer demo")
    p_demo.add_argument("--out-dir", default="pcaps", help="Output directory for pcaps")

    args = parser.parse_args()

    if args.cmd == "generate":
        benign = generate_benign_pcap(os.path.join(args.out_dir, "benign_arp.pcap"))
        attack = generate_attack_pcap(os.path.join(args.out_dir, "arp_spoof_attack.pcap"))
        print(f"[arpguard_lab_tools] Wrote: {benign}")
        print(f"[arpguard_lab_tools] Wrote: {attack}")
    elif args.cmd == "demo":
        demo(args.out_dir)


if __name__ == "__main__":
    main()
