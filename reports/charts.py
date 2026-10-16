"""
Chart generation for reports using matplotlib.

Renders to PNG bytes/files (Agg backend, no GUI dependency) so charts
can be embedded in PDF reports and referenced by HTML reports.
"""

from __future__ import annotations

import matplotlib
matplotlib.use("Agg")  # headless rendering, safe for background threads

import matplotlib.pyplot as plt
from pathlib import Path

from scanner.risk_engine import SEVERITY_COLORS, SEVERITY_ORDER


def render_severity_chart(severity_counts: dict[str, int], output_path: Path) -> Path:
    labels = [s for s in SEVERITY_ORDER if severity_counts.get(s, 0) > 0]
    values = [severity_counts[s] for s in labels]
    colors = [SEVERITY_COLORS[s] for s in labels]

    fig, ax = plt.subplots(figsize=(5, 3.2), dpi=150)
    if values:
        bars = ax.bar(labels, values, color=colors)
        ax.bar_label(bars, padding=2)
    ax.set_title("Findings by Severity")
    ax.set_ylabel("Count")
    fig.tight_layout()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, transparent=True)
    plt.close(fig)
    return output_path


def render_severity_pie(severity_counts: dict[str, int], output_path: Path) -> Path:
    labels = [s for s in SEVERITY_ORDER if severity_counts.get(s, 0) > 0]
    values = [severity_counts[s] for s in labels]
    colors = [SEVERITY_COLORS[s] for s in labels]

    fig, ax = plt.subplots(figsize=(4, 4), dpi=150)
    if values:
        ax.pie(values, labels=labels, colors=colors, autopct="%1.0f%%", startangle=90)
    ax.set_title("Severity Distribution")
    fig.tight_layout()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, transparent=True)
    plt.close(fig)
    return output_path
