## Description
Provide a concise overview of the changes introduced by this PR. Mention any related open issues if applicable.

## Type of Change
- [ ] Bug fix (non-breaking change fixing an engine or dashboard error)
- [ ] New heuristic feature (adds detection rules to `arpguard_core.py`)
- [ ] Documentation update (modifies lab handouts, quizzes, or README)
- [ ] Tooling/CI enhancement

## Checklist Before Merging
- [ ] My code follows the repository's PEP 8 style guidelines.
- [ ] I have verified my changes by running `python code/arpguard_lab_tools.py demo`.
- [ ] My changes produce clean outputs (0 events for `benign_arp.pcap`, ≥ 1 for `arp_spoof_attack.pcap`).
- [ ] If changing core script logic, I have updated the text mirror copies inside `canvas_upload/`.
- [ ] I have provided descriptive markdown alt text for any modified diagrams or figures.
