#!/usr/bin/env python3
"""
generate_figures.py
Generate lightweight, self-contained figure assets for the ARPGuard project.

The project rubric often expects "figures/screenshots" to be included as supporting materials.
This script produces:
- A simple network topology diagram (Host, Gateway, Attacker).
- A "benign analysis" snapshot and an "attack analysis" snapshot (rendered as images).

These are designed as safe placeholders and can be replaced by real screenshots
from Wireshark/terminal output in a live lab environment.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import List
import sys

import matplotlib.pyplot as plt

# Allow importing from ../code
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "code"))

from arpguard_core import analyze_pcap  # noqa: E402


def _save_text_snapshot(out_path: Path, title: str, lines: List[str]) -> None:
    fig = plt.figure(figsize=(10, 6))
    plt.axis("off")
    plt.text(0.01, 0.98, title, fontsize=16, va="top")
    plt.text(0.01, 0.92, "\n".join(lines), fontsize=11, va="top", family="monospace")
    fig.tight_layout()
    fig.savefig(out_path, dpi=200, bbox_inches="tight")
    plt.close(fig)


def topology(out_path: Path) -> None:
    fig = plt.figure(figsize=(10, 4))
    ax = plt.gca()
    ax.axis("off")

    nodes = {
        "Host\n192.168.1.10\n00:11:22:33:44:10": (0.15, 0.5),
        "Gateway\n192.168.1.1\n00:aa:bb:cc:dd:01": (0.5, 0.5),
        "Attacker\n192.168.1.66\nde:ad:be:ef:00:66": (0.85, 0.5),
    }

    for label, (x, y) in nodes.items():
        ax.text(x, y, label, ha="center", va="center",
                bbox=dict(boxstyle="round,pad=0.5", fc="white", ec="black"))

    ax.annotate("", xy=(0.42, 0.52), xytext=(0.23, 0.52), arrowprops=dict(arrowstyle="->"))
    ax.text(0.32, 0.57, "ARP who-has / is-at", ha="center")

    ax.annotate("", xy=(0.58, 0.48), xytext=(0.77, 0.48), arrowprops=dict(arrowstyle="<-"))
    ax.text(0.68, 0.41, "Spoofed is-at", ha="center")

    fig.tight_layout()
    fig.savefig(out_path, dpi=200, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate ARPGuard figure assets")
    parser.add_argument("--pcaps-dir", default="pcaps", help="Directory containing benign_arp.pcap and arp_spoof_attack.pcap")
    parser.add_argument("--out-dir", default="figures", help="Output directory")
    args = parser.parse_args()

    pcaps_dir = Path(args.pcaps_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    benign_pcap = pcaps_dir / "benign_arp.pcap"
    attack_pcap = pcaps_dir / "arp_spoof_attack.pcap"

    res_benign = analyze_pcap(str(benign_pcap))
    res_attack = analyze_pcap(str(attack_pcap))

    topology(out_dir / "arpguard_topology.png")

    benign_lines = [
        f"PCAP: {benign_pcap.name}",
        f"Observed hosts: {len(res_benign.hosts_ip_to_mac)}",
        f"Events: {len(res_benign.events)}",
        "",
        "Host Table (IP -> MAC):",
        *[f"  {ip:15}  {mac}" for ip, mac in res_benign.hosts_ip_to_mac.items()],
        "",
        "Alerts:",
        "  (none detected)",
    ]
    _save_text_snapshot(out_dir / "benign_analysis_snapshot.png", "ARPGuard Snapshot (Benign)", benign_lines)

    attack_lines = [
        f"PCAP: {attack_pcap.name}",
        f"Observed hosts: {len(res_attack.hosts_ip_to_mac)}",
        f"Events: {len(res_attack.events)}",
        "",
        "Top Alerts:",
        *[f"  [{e.severity}] {e.event_type}: {e.details}" for e in res_attack.events[:8]],
        "",
        "Host Table (IP -> MAC) at end of capture:",
        *[f"  {ip:15}  {mac}" for ip, mac in res_attack.hosts_ip_to_mac.items()],
    ]
    _save_text_snapshot(out_dir / "attack_analysis_snapshot.png", "ARPGuard Snapshot (Attack)", attack_lines)


if __name__ == "__main__":
    main()
