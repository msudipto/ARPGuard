# Accessibility

ARPGuard is designed as an instructional tool to help learners observe and detect ARP spoofing patterns. We believe that security education should be universally accessible. We are committed to making our code repository, local Flask dashboards, and core lab documentation readable, navigable, and usable for all learners and instructors, including those using assistive technologies.

## Priorities

Our project focuses on the following accessibility pillars to accommodate diverse classroom needs:
* **Content Clarity & Plain Text Options:** We provide plain-text copy variations (`.txt`) of all major scripts and teaching manuals within the `canvas_upload/` directory. This ensures high compatibility with text-to-speech engine tools, braille displays, and lightweight terminal clients without requiring web browsers or graphic readers.
* **Keyboard Navigation:** The local web dashboard UI is designed to be fully navigable via keyboard inputs (`Tab`, `Shift+Tab`, `Enter`, and spacebars) for all interactive uploads and analytics review fields.
* **Contrast & Semantic Hierarchy:** We prioritize high-contrast structural text elements and clean headings throughout both markdown layouts and document sheets to support magnification tools.

## Contributor expectations

When submitting structural upgrades or changing user-facing files in this repository, contributors must adhere to these guardrails:
* **Alternative Text:** Ensure all instructional diagrams, topology layouts, or visual screenshot attachments within the `figures/` directory are documented with descriptive alt-text summaries in markdown.
* **Semantic Code Elements:** Do not rely solely on color indicators (e.g., green/red alert dots) in the Flask frontend or code logging output to convey an anomaly state. Always pair color indications with clear textual status descriptors (e.g., "[ALERT]", "[PASS]").

## Reporting accessibility issues

If you encounter an accessibility barrier while running the analyzer, uploading PCAPs to the Flask interface, or reading the lab handout, please let us know so we can fix it.

To report an accessibility issue, please open an issue in this repository using the standard template and include:
* A description of the barrier you encountered and what task you were trying to complete.
* The file or dashboard interface component where the issue occurred.
* Your environment details (Operating system, browser, and assistive technologies in use if relevant).

### How we respond
The repository maintainer triages incoming issues regularly. Once an accessibility report is verified, we will acknowledge your report within **3 business days** and coordinate an appropriate patch or formatting workaround.

## Supported environments

ARPGuard targets standard accessibility tools bundled natively into modern operating systems:
* **Operating Systems:** Windows Narrator/Magnifier, macOS VoiceOver, and Linux-based screen readers.
* **Browsers:** Modern, standard-compliant browsers (Google Chrome, Mozilla Firefox, Safari, Microsoft Edge) running the local dashboard at `127.0.0.1:5000`.

## Known limitations

Because the core network packet engine generates complex, structured multi-line raw string metrics, screen reader streams mapping dense nested data outputs might sound overwhelming. 
* **Workaround:** We highly recommend utilizing our machine-readable JSON save outputs (`--json`) to pipe packet data cleanly into preferred local parsers, screen readers, or text tools.
