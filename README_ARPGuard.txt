ARPGuard — Detecting ARP Spoofing in a Tactile, Hands-On Lab
==============================================================

Public repository (auxiliary files + runnable code):
  https://github.com/msudipto/ARPGuard

1. Overview
-----------
ARPGuard is a compact, classroom-friendly toolchain that helps learners observe and detect ARP spoofing
(ARP cache poisoning) using packet captures (PCAPs). It pairs a small analyzer (ARPGuard Core) with guided
teaching materials (lab handout, facilitator notes, and a quiz with answers + justification).

The intended teaching arc is:
  (i) observe benign ARP resolution and cache behavior,
 (ii) observe a controlled spoofing pattern in a capture,
(iii) run ARPGuard and interpret why specific alerts fired.

2. Learning Objectives
----------------------
After completing the lab, a learner should be able to:
- Explain ARP’s role at the L2/L3 boundary and why it is vulnerable to spoofing.
- Identify ARP spoofing indicators in traces (e.g., one IP mapping to multiple MACs, repeated MAC flips).
- Describe mitigations (static ARP, DHCP snooping + DAI, VLAN segmentation) and map them to defense-in-depth.

3. Quickstart (CLI) — Grader-Friendly
------------------------------------
A) Install dependencies (recommended: virtual environment)

  python -m venv .venv
  source .venv/bin/activate     (macOS/Linux)
  .venv\Scripts\activate      (Windows PowerShell)
  pip install -r requirements.txt

B) Analyze the included PCAPs

  python code/arpguard_core.py pcaps/benign_arp.pcap
  python code/arpguard_core.py pcaps/arp_spoof_attack.pcap

Expected behavior:
- benign produces 0 anomaly events
- attack produces >= 1 anomaly event (typically IP<->MAC conflict)

4. Repository Layout
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
  PDF versions of the text materials (use if the rubric requires PDFs)

pcaps/
  benign_arp.pcap               Benign ARP exchange (consistent mapping)
  arp_spoof_attack.pcap         Controlled spoofing pattern (gateway IP claimed by attacker MAC)

figures/
  Generated screenshots/figures + ARPGuard_Figures.pdf

scripts/
  generate_figures.py           Regenerates figures from analyzer outputs

sanity/
  SANITY_CHECK_REPORT.txt       Deterministic PASS/FAIL evidence (benign=0, attack>=1)
  benign_results.json
  attack_results.json

canvas_upload/
  Canvas-ready bundle (after unzipping locally):
  - .txt copies of main code files
  - requirements.txt
  - teaching-material PDFs

5. Running ARPGuard (Command-Line)
----------------------------------
A) (Optional) Generate PCAPs

  python code/arpguard_lab_tools.py generate --out-dir pcaps

B) Run a one-command demo analysis over both captures

  python code/arpguard_lab_tools.py demo --out-dir pcaps

C) Analyze a PCAP and write JSON output (recommended for reproducibility)

  python code/arpguard_core.py pcaps/arp_spoof_attack.pcap --json sanity/attack_results.json --pretty

Output notes:
- The analyzer emits JSON that includes: events (alerts), summary counters, PCAP metadata (hash/size),
  and observed IP<->MAC bindings. This makes evaluation deterministic.

6. Web Dashboard (Optional)
---------------------------
Start the dashboard locally:

  python code/arpguard_web_dashboard.py --host 127.0.0.1 --port 5000

Then upload:
- pcaps/benign_arp.pcap
- pcaps/arp_spoof_attack.pcap

7. Figures / Screenshots
------------------------
This repository includes generated figure assets in figures/.
To regenerate them:

  python scripts/generate_figures.py --pcaps-dir pcaps --out-dir figures

8. Submission Notes (Canvas vs. GitHub)
---------------------------------------
- GitHub (public): hosts auxiliary/supporting artifacts (PCAPs, figures, runnable code, PDFs).
- Canvas (LMS): upload only the file types the rubric permits (typically PDF/TXT). Do not upload ZIP archives.

Canvas-ready files:
- The canvas_upload/ directory is a ready-to-upload bundle (after unzipping locally).
  It contains .txt copies of the primary scripts, requirements.txt, and teaching-material PDFs.

9. Troubleshooting
------------------
- ModuleNotFoundError: activate the virtual environment and run pip install -r requirements.txt.
- Dashboard port in use: change --port (e.g., 5050).
- File not found: run commands from repository root and verify paths.

References
----------
[1] D. C. Plummer, “An Ethernet Address Resolution Protocol,” RFC 826, Nov. 1982.
