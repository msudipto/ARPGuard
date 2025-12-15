#!/usr/bin/env python3
"""
arpguard_web_dashboard.py
A minimal Flask web dashboard for ARPGuard.

Features:
- Upload a .pcap file
- Run ARPGuard analysis
- View host tables and anomaly events in a browser

This is intentionally lightweight to keep the project easy to run for students.

Dependencies:
- flask
- scapy (used by arpguard_core)

Run:
  python arpguard_web_dashboard.py --host 127.0.0.1 --port 5000

Security note:
- This demo is intended for local use in a controlled environment.
- Do not expose it on an untrusted network without note/controls (authentication, size limits, etc.).
"""

from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path
from typing import Optional

from flask import Flask, request, redirect, url_for, render_template_string, flash

from arpguard_core import analyze_pcap


HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>ARPGuard Dashboard</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; }
    .box { border: 1px solid #ddd; padding: 16px; border-radius: 8px; margin-bottom: 16px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #eee; padding: 8px; text-align: left; }
    th { background: #f7f7f7; }
    .sev-HIGH { color: #b00020; font-weight: 700; }
    .sev-MEDIUM { color: #a05a00; font-weight: 700; }
    .sev-LOW { color: #1b5e20; font-weight: 700; }
    code { background: #f3f3f3; padding: 2px 4px; border-radius: 4px; }
    .muted { color: #666; }
  </style>
</head>
<body>
  <h1>ARPGuard Dashboard</h1>
  <p class="muted">Upload a PCAP to analyze ARP mappings and detect basic ARP spoofing indicators.</p>

  {% with messages = get_flashed_messages() %}
    {% if messages %}
      <div class="box">
        {% for m in messages %}
          <div>{{m}}</div>
        {% endfor %}
      </div>
    {% endif %}
  {% endwith %}

  <div class="box">
    <h2>Upload PCAP</h2>
    <form method="post" action="{{ url_for('upload') }}" enctype="multipart/form-data">
      <input type="file" name="pcap" accept=".pcap,.pcapng" required />
      <button type="submit">Analyze</button>
    </form>
    <p class="muted">Tip: Start with <code>pcaps/benign_arp.pcap</code> and <code>pcaps/arp_spoof_attack.pcap</code>.</p>
  </div>

  {% if result %}
    <div class="box">
      <h2>Summary</h2>
      <div><b>PCAP:</b> {{ result_pcap }}</div>
      <div><b>Events:</b> {{ result.events|length }}</div>
    </div>

    <div class="box">
      <h2>Host Table (IP → MAC)</h2>
      <table>
        <thead><tr><th>IP</th><th>MAC</th></tr></thead>
        <tbody>
          {% for ip, mac in result.hosts_ip_to_mac.items() %}
            <tr><td>{{ip}}</td><td>{{mac}}</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>

    <div class="box">
      <h2>Alerts</h2>
      {% if result.events|length == 0 %}
        <p>No anomalies detected in this capture.</p>
      {% else %}
        <table>
          <thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>Details</th></tr></thead>
          <tbody>
            {% for e in result.events %}
              <tr>
                <td>{{ "%.3f"|format(e.ts) }}</td>
                <td>{{ e.event_type }}</td>
                <td class="sev-{{e.severity}}">{{ e.severity }}</td>
                <td>{{ e.details }}</td>
              </tr>
            {% endfor %}
          </tbody>
        </table>
      {% endif %}
    </div>
  {% endif %}
</body>
</html>
"""


def create_app() -> Flask:
    app = Flask(__name__)
    # Dev/demo secret; for classroom use only.
    app.secret_key = "arpguard-demo-secret"

    @app.get("/")
    def index():
        return render_template_string(HTML, result=None, result_pcap=None)

    @app.post("/upload")
    def upload():
        if "pcap" not in request.files:
            flash("No file part named 'pcap' found.")
            return redirect(url_for("index"))
        f = request.files["pcap"]
        if not f.filename:
            flash("No file selected.")
            return redirect(url_for("index"))

        suffix = Path(f.filename).suffix.lower()
        if suffix not in [".pcap", ".pcapng"]:
            flash("Unsupported file type. Please upload a .pcap or .pcapng.")
            return redirect(url_for("index"))

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / f"upload{suffix}"
            f.save(p)
            try:
                res = analyze_pcap(str(p))
            except Exception as e:
                flash(f"Analysis failed: {e}")
                return redirect(url_for("index"))

            # Render results on the same page
            return render_template_string(HTML, result=res, result_pcap=f.filename)

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="ARPGuard Flask dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    app = create_app()
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
