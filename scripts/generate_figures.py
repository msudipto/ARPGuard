#!/usr/bin/env python3
"""
generate_figures.py

What it does
------------
It generates lightweight, self-contained figure assets for the ARPGuard project so the submission
includes reproducible "figures/screenshots" without requiring manual GUI screenshots.

It produces:
1) figures/topology_diagram.png
2) figures/benign_analysis_snapshot.png
3) figures/attack_analysis_snapshot.png

How it works
------------
It runs ARPGuard's offline analyzer on the included benign and attack PCAPs and then renders short,
human-readable summaries into PNG images using Matplotlib.

Note
----
These are designed as safe placeholders. In a live lab, the learner can replace them with real
Wireshark screenshots and terminal outputs if desired.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any

import matplotlib
matplotlib.use("Agg")  # headless-safe
import matplotlib.pyplot as plt


def _run_core(core_path: Path, pcap_path: Path) -> Dict[str, Any]:
    """It runs arpguard_core.py and returns the parsed JSON dict."""
    cmd = [sys.executable, str(core_path), str(pcap_path)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"arpguard_core.py failed for {pcap_path}: {res.stderr.strip()}")
    try:
        return json.loads(res.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Could not parse JSON output from arpguard_core.py: {e}")


def _draw_topology(out_path: Path) -> None:
    fig, ax = plt.subplots(figsize=(9, 4))
    ax.set_axis_off()

    def box(x, y, w, h, title, subtitle):
        ax.add_patch(plt.Rectangle((x, y), w, h, fill=False, linewidth=2))
        ax.text(x + w / 2, y + h * 0.62, title, ha="center", va="center", fontsize=13, fontweight="bold")
        ax.text(x + w / 2, y + h * 0.30, subtitle, ha="center", va="center", fontsize=10)

    box(0.08, 0.35, 0.25, 0.30, "Host", "Victim workstation")
    box(0.38, 0.35, 0.25, 0.30, "Gateway", "Default router")
    box(0.68, 0.35, 0.25, 0.30, "Attacker", "Spoofing endpoint")

    ax.annotate("", xy=(0.38, 0.50), xytext=(0.33, 0.50), arrowprops=dict(arrowstyle="->"))
    ax.text(0.355, 0.56, "ARP who-has", ha="center", fontsize=9)

    ax.annotate("", xy=(0.63, 0.47), xytext=(0.68, 0.47), arrowprops=dict(arrowstyle="<-"))  # spoofed replies
    ax.text(0.655, 0.40, "Spoofed is-at", ha="center", fontsize=9)

    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=220, bbox_inches="tight")
    plt.close(fig)


def _draw_snapshot(title: str, result: Dict[str, Any], out_path: Path) -> None:
    s = result.get("summary", {})
    p = result.get("pcap", {})
    events = result.get("events", [])

    lines = [
        title,
        "",
        f"PCAP packets: {p.get('packet_count', 'N/A')} (ARP: {p.get('arp_packet_count', 'N/A')})",
        f"Time window: {p.get('time_start_s', 0.0):.3f}s to {p.get('time_end_s', 0.0):.3f}s",
        "",
        "Summary:",
        f"  anomaly_event_count   : {s.get('anomaly_event_count', 'N/A')}",
        f"  ip_mac_conflict_count : {s.get('ip_mac_conflict_count', 'N/A')}",
        f"  arp_requests/replies  : {s.get('arp_requests', 'N/A')}/{s.get('arp_replies', 'N/A')}",
        f"  gratuitous_arp        : {s.get('gratuitous_arp', 'N/A')}",
        f"  unsolicited_replies   : {s.get('unsolicited_replies', 'N/A')}",
        "",
        "Top anomaly (if any):",
    ]

    if events:
        e0 = events[0]
        lines += [
            f"  type     : {e0.get('event_type')}",
            f"  severity : {e0.get('severity')}",
            f"  ip       : {e0.get('ip')}",
            f"  old->new : {e0.get('old_mac')} -> {e0.get('new_mac')}",
        ]
    else:
        lines += ["  (none)"]

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.set_axis_off()
    ax.text(0.02, 0.98, "\n".join(lines), va="top", family="monospace", fontsize=11)
    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=220, bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate ARPGuard figure assets")
    parser.add_argument("--pcaps-dir", default="pcaps", help="Directory containing benign_arp.pcap and arp_spoof_attack.pcap")
    parser.add_argument("--code-dir", default="code", help="Directory containing arpguard_core.py")
    parser.add_argument("--out-dir", default="figures", help="Output directory for generated figures")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    pcaps_dir = (root / args.pcaps_dir).resolve()
    code_dir = (root / args.code_dir).resolve()
    out_dir = (root / args.out_dir).resolve()

    core_path = code_dir / "arpguard_core.py"
    benign = pcaps_dir / "benign_arp.pcap"
    attack = pcaps_dir / "arp_spoof_attack.pcap"

    if not core_path.exists():
        raise FileNotFoundError(f"Missing: {core_path}")
    if not benign.exists():
        raise FileNotFoundError(f"Missing: {benign}")
    if not attack.exists():
        raise FileNotFoundError(f"Missing: {attack}")

    _draw_topology(out_dir / "topology_diagram.png")

    benign_res = _run_core(core_path, benign)
    attack_res = _run_core(core_path, attack)

    _draw_snapshot("BENIGN PCAP: Analysis Snapshot", benign_res, out_dir / "benign_analysis_snapshot.png")
    _draw_snapshot("ATTACK PCAP: Analysis Snapshot", attack_res, out_dir / "attack_analysis_snapshot.png")

    print(f"[generate_figures] Wrote figures to: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
