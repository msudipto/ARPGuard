ARPGuard — Detecting ARP Spoofing in a Tactile, Hands-On Lab
==============================================================

1. Overview
-----------
ARPGuard is a compact, classroom-friendly toolchain that helps learners observe and detect ARP spoofing
(ARP cache poisoning) using packet captures. The project pairs a small analyzer (ARPGuard core) with guided
teaching materials (lab handout, facilitator notes, and a quiz with answers + justification).

The intended teaching arc is:
  (i) observe benign ARP resolution and cache behavior,
 (ii) observe a controlled spoofing pattern in a capture,
(iii) run ARPGuard and interpret why specific alerts fired.

2. Learning Objectives
----------------------
After completing the lab, a learner should be able to:
- Explain ARP’s role at the L2/L3 boundary and why it is vulnerable to spoofing.
- Identify ARP spoofing indicators in traffic traces (e.g., one IP mapping to multiple MACs).
- Describe mitigations (static ARP, DHCP snooping + DAI, VLAN segmentation) and map them to defense-in-depth.

3. Repository Layout
--------------------
code/
  arpguard_core.py              Core PCAP analyzer (heuristics + JSON output)
  arpguard_lab_tools.py         PCAP generator + one-command demo
  arpguard_web_dashboard.py     Minimal Flask UI for PCAP upload + visualization

docs/
  ARPGuard_Project_Overview.txt
  ARPGuard_Lab_Handout.txt
  ARPGuard_Facilitator_Notes.txt
  ARPGuard_Quiz_and_AnswerKey.txt

docs_pdf/
  PDF versions of the text materials for submission where PDFs are required.

pcaps/
  benign_arp.pcap               Benign ARP exchange (consistent mapping)
  arp_spoof_attack.pcap         Controlled spoofing pattern (gateway IP claimed by attacker MAC)

figures/
  arpguard_topology.png
  benign_analysis_snapshot.png
  attack_analysis_snapshot.png

reports/
  CYBSC5300_FinalReflection_msudipto.docx
  ARPGuard_Appendices_Outline.docx

milestones/
  Prior submissions / reference PDFs (proposal and research & content development).

4. Installation
---------------
Create a virtual environment (recommended) and install dependencies:

  python -m venv .venv
  source .venv/bin/activate     (macOS/Linux)
  .venv\Scripts\activate        (Windows PowerShell)
  pip install -r requirements.txt

Note: ARPGuard can parse classic PCAP (Ethernet) using only the standard library. If Scapy is installed in a
given environment, ARPGuard can optionally use it, but Scapy is not required to run the core analyzer.

5. Quickstart (Command-Line)
----------------------------
A) Generate the PCAPs:

  python code/arpguard_lab_tools.py generate --out-dir pcaps

B) Run a demo analysis on both captures:

  python code/arpguard_lab_tools.py demo --out-dir pcaps

C) Analyze a PCAP and write JSON output:

  python code/arpguard_core.py pcaps/arp_spoof_attack.pcap --json sanity/attack_results.json --pretty

6. Quickstart (Web Dashboard)
-----------------------------
Start the dashboard locally:

  python code/arpguard_web_dashboard.py --host 127.0.0.1 --port 5000

Then upload:
- pcaps/benign_arp.pcap
- pcaps/arp_spoof_attack.pcap

7. Figures / Screenshots
------------------------
This repository includes generated, self-contained figure assets in figures/.
They are designed as safe placeholders and can be replaced by real screenshots from Wireshark/terminal output.

To regenerate the included figures after generating PCAPs:

  python scripts/generate_figures.py --pcaps-dir pcaps --out-dir figures

8. Submission Notes (Canvas vs. GitHub)
----------------------------------
It is structured so that Canvas and GitHub submissions remain unambiguous:

- GitHub (public): it hosts the full auxiliary package (scripts, PCAPs, figures, PDFs, and doc templates).
- Canvas (LMS): it uploads only the files the rubric explicitly permits (typically PDF/TXT), without ZIP archives.

Canvas-ready files
------------------
The canvas_upload/ directory is a ready-to-upload bundle (after unzipping locally). It contains:
- PDFs for the text materials (Project Overview, Lab Handout, Facilitator Notes, Quiz + Answer Key).
- Plain-text copies of the primary Python scripts (arpguard_core.txt, arpguard_lab_tools.txt,
  arpguard_web_dashboard.txt) and requirements.txt.

Important rubric alignment
--------------------------
- It does not submit ZIP archives to Canvas. If it is using a ZIP for transport, it unzips locally and uploads
  the individual files.
- If a GitHub/YouTube link is provided, it still follows the rubric’s rule that required materials must be
  accessible to the grader without additional renaming or reconstruction.
- If the project includes any video/audio, it submits the actual media file(s) to Canvas in the allowed formats,
  rather than relying only on an external link.

References
----------
[1] D. C. Plummer, “An Ethernet Address Resolution Protocol,” RFC 826, Nov. 1982.
