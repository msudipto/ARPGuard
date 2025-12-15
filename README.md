# ARPGuard — ARP Spoofing Detection Lab (PCAP-Based)

**Public repository:** https://github.com/msudipto/ARPGuard

ARPGuard is a compact, classroom-friendly toolchain that helps learners **observe and detect ARP spoofing (ARP cache poisoning)** using packet captures (PCAPs). It pairs a small analyzer (**ARPGuard Core**) with guided teaching materials (**lab handout**, **facilitator notes**, and a **quiz with answers + justification**).

The intended teaching arc is:

1. Observe benign ARP resolution and cache behavior.
2. Observe a controlled spoofing pattern in a capture.
3. Run ARPGuard and explain **why specific alerts fired**.

---

## Learning Objectives

After completing the lab, a learner should be able to:

- Explain ARP’s role at the L2/L3 boundary and why it is vulnerable to spoofing.
- Identify spoofing indicators in traces (e.g., **one IP mapping to multiple MACs**, rapid MAC flips).
- Describe practical mitigations (static ARP, DHCP snooping + DAI, VLAN segmentation) and map them to defense-in-depth.

---

## 60‑Second Quickstart (CLI)

### 1) Install dependencies
```bash
python -m venv .venv
source .venv/bin/activate          # macOS/Linux
# .venv\Scripts\activate         # Windows PowerShell
pip install -r requirements.txt
```

### 2) Analyze the included PCAPs
```bash
python code/arpguard_core.py pcaps/benign_arp.pcap
python code/arpguard_core.py pcaps/arp_spoof_attack.pcap
```

**Expected behavior (grading-friendly):**
- Benign capture produces **0 anomaly events**.
- Attack capture produces **≥ 1 anomaly event** (typically an IP↔MAC conflict).

---

## Repository Layout

```
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
  PDF versions of the text materials (use these if PDFs are required)

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
  Ready-to-upload Canvas bundle (after unzipping locally):
    - .txt copies of main code files
    - requirements.txt
    - teaching-material PDFs
```

---

## Installation Notes

- **Python:** 3.9+ recommended (3.10/3.11 ideal).
- ARPGuard Core is designed to parse **classic Ethernet PCAP** without requiring a heavy dependency set.
- If **Scapy** is installed, some helper workflows may use it; however, the core analyzer workflow remains functional with the listed requirements.

---

## Running ARPGuard (Command-Line)

### A) Generate PCAPs (optional)
If you want to generate fresh captures (instead of using the included ones):

```bash
python code/arpguard_lab_tools.py generate --out-dir pcaps
```

This creates:
- `pcaps/benign_arp.pcap`
- `pcaps/arp_spoof_attack.pcap`

### B) Run a one-command demo (recommended for graders)
```bash
python code/arpguard_lab_tools.py demo --out-dir pcaps
```

This runs analysis over both PCAPs and prints a short results summary.

### C) Analyze a PCAP and write JSON output
```bash
python code/arpguard_core.py pcaps/arp_spoof_attack.pcap --json sanity/attack_results.json --pretty
```

**What the analyzer outputs**
- A machine-readable JSON object including:
  - `events`: anomaly events (empty for benign)
  - `summary`: counts and aggregates (grader-friendly)
  - `pcap` metadata: file hash, size, time window
  - `hosts_ip_to_mac`, `hosts_mac_to_ips`: observed bindings

---

## Running the Web Dashboard (Optional UI)

1) Start the dashboard:
```bash
python code/arpguard_web_dashboard.py --host 127.0.0.1 --port 5000
```

2) Open a browser and upload:
- `pcaps/benign_arp.pcap`
- `pcaps/arp_spoof_attack.pcap`

The UI displays key counts and alert summaries. If you prefer “CLI-only,” this section can be skipped.

---

## Figures / Screenshots (Regeneration)

This repository includes pre-generated figures in `figures/`. To regenerate them:

```bash
python scripts/generate_figures.py --pcaps-dir pcaps --out-dir figures
```

This produces (or refreshes):
- benign/attack analysis snapshots
- a simple topology diagram
- `figures/ARPGuard_Figures.pdf` (for PDF-first workflows)

---

## Sanity Check (Deterministic Verification)

To re-run the same verification used for packaging:

```bash
python code/arpguard_core.py pcaps/benign_arp.pcap --json sanity/benign_results.json
python code/arpguard_core.py pcaps/arp_spoof_attack.pcap --json sanity/attack_results.json
```

Then confirm:
- `sanity/benign_results.json` has **0** `events`
- `sanity/attack_results.json` has **≥ 1** `events`

A summarized report is included in `sanity/SANITY_CHECK_REPORT.txt`.

---

## Submission Notes (Canvas vs. GitHub)

Many LMS workflows restrict file types. This repository is structured so submissions remain unambiguous:

- **GitHub (public):** hosts auxiliary/supporting artifacts (PCAPs, figures, runnable `.py` code, and full documentation set).
- **Canvas:** upload only the rubric-permitted file types (typically **PDF/TXT**) and **do not upload ZIP archives**.

### Canvas-ready files
The `canvas_upload/` folder contains:
- Plain-text `.txt` copies of the primary scripts:
  - `arpguard_core.txt`
  - `arpguard_lab_tools.txt`
  - `arpguard_web_dashboard.txt`
- `requirements.txt`
- Teaching materials as PDFs (`docs_pdf/`)

Unzip locally, then upload **individual files** to Canvas as required.

---

## Troubleshooting

- **`ModuleNotFoundError`**: Ensure your virtual environment is active and you ran `pip install -r requirements.txt`.
- **Port in use (dashboard)**: Change the port, e.g., `--port 5050`.
- **PCAP not found**: Verify paths (e.g., `pcaps/benign_arp.pcap`) and run from repo root.
- **Windows execution**: Use `python` (not `python3`), and activate `.venv\Scripts\activate`.

---

## Reference

[1] D. C. Plummer, “An Ethernet Address Resolution Protocol,” **RFC 826**, Nov. 1982.
