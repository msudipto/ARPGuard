# Contributing to ARPGuard

Thank you for your interest in improving ARPGuard! As an instructional lab, keeping this repository organized, deterministic, and clean helps instructors and students alike. 

Please take a moment to review these guidelines before submitting a pull request.

## 🛠️ Code & Script Contributions
ARPGuard relies on deterministic outputs to ensure it remains a helpful grading tool. If you modify any script in `code/` or `scripts/`:
* **Maintain Formatting:** Follow strict PEP 8 guidelines for Python files.
* **Run Sanity Checks:** Ensure your edits do not break the core analyzer output. Running `python code/arpguard_lab_tools.py demo` should still pass successfully.
* **Keep Dependencies Minimal:** Avoid introducing heavy third-party networking dependencies that deviate from the core library setup.

## 📝 Documentation & Teaching Materials
When updating materials inside the `docs/` folder (such as the lab handout, quiz, or facilitator notes):
* Keep text-based (`.txt`) and PDF-based (`docs_pdf/`) documentation synced.
* Ensure answer keys remain clear, accurate, and explain the technical "why" behind any packet behavior.

## 📦 Canvas-Ready Bundles
Any changes to primary script logic or documentation must be updated in the `canvas_upload/` directory as well. This ensures instructors downloading the text version bundle receive the latest fixes without cloning the full repository.

## 🚀 Pull Request Process
1. **Fork** the repository and create your feature branch.
2. **Commit** your changes with clear, descriptive commit messages.
3. **Verify** that no stray cache or configuration files (like `.DS_Store` or local virtual environment folders) are tracked.
4. **Open a PR** detailing the exact problem you are solving or the feature you are adding.
