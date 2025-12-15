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

  python code/arpguard_core.py pcaps/arp_spoof_attack.pcap --json sanity/attack_results.json

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
---------------------------------------
- Auxiliary files are intended to be hosted publicly on GitHub (this repository).
- Appendices in the final write-up should remain short outlines; full materials are provided as separate files here.
- If the rubric requires PDFs for text documents, use the docs_pdf/ versions (already included in this package).

Important: A ZIP package is convenient for uploading to GitHub, but many course LMS workflows require uploading
individual files rather than a compressed archive. Follow the rubric’s submission instructions for Canvas.

9. References
-------------
[1] D. C. Plummer, “An Ethernet Address Resolution Protocol,” RFC 826, Nov. 1982.
