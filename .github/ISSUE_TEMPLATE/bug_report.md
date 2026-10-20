---
name: Bug report
about: Report a technical glitch, parsing failure, or dashboard bug in ARPGuard
title: '[BUG] '
labels: 'bug'
assignees: ''

---

**Describe the bug**
A clear and concise description of the issue you are experiencing with the ARPGuard lab suite.

**Which component is failing?**
- [ ] `code/arpguard_core.py` (PCAP parsing / detection heuristics)
- [ ] `code/arpguard_web_dashboard.py` (Flask UI / upload dashboard)
- [ ] `code/arpguard_lab_tools.py` (PCAP generator / demo tool)
- [ ] Other / Lab Documentation

**To Reproduce**
Steps to reproduce the behavior:
1. Run command '...' or upload PCAP file '...'
2. Set environment parameters '....'
3. See error or unexpected output

**Expected behavior**
A clear description of what you expected to happen (e.g., "The analyzer should output 0 events for the benign PCAP, but it raised a false positive").

**Error Logs / Output Snippets**
If applicable, paste terminal traces, Python traceback text, or custom JSON output results here:
```text
Place traceback here
```

**Environment Data (please complete the following information):**
 - OS: [e.g., Ubuntu 22.04, Windows 11, macOS Sequoia]
 - Python Version: [e.g., 3.10.12]
 - Scapy Version (if applicable): [e.g., 2.5.0]
 - Browser (if using the Flask Web Dashboard): [e.g., Chrome, Firefox]

**Additional context**
Add any other context about the specific PCAP file properties, environment quirks, or grading setup configurations here.
