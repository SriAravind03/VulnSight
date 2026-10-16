"""Settings page: theme, scan tuning, report directory, and API keys."""

from __future__ import annotations

import tkinter as tk

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, X, LEFT, W

from gui.widgets import SectionHeader
from utils.config import config

THEMES = ["darkly", "cyborg", "superhero", "solar", "flatly", "cosmo", "litera", "journal"]


class SettingsPage(ttk.Frame):
    def __init__(self, master, app, **kwargs):
        super().__init__(master, **kwargs)
        self.app = app

        SectionHeader(self, "Settings", "Application preferences and scan tuning", icon="⚙").pack(
            fill=X, padx=24, pady=(20, 10)
        )

        form = ttk.Frame(self)
        form.pack(fill=X, padx=24, pady=10)
        form.columnconfigure(1, weight=1)

        row = 0
        ttk.Label(form, text="Theme").grid(row=row, column=0, sticky=W, pady=6)
        self.theme_var = tk.StringVar(value=config.get("app.theme", "darkly"))
        theme_combo = ttk.Combobox(form, textvariable=self.theme_var, values=THEMES, state="readonly", width=20)
        theme_combo.grid(row=row, column=1, sticky=W, padx=10)
        theme_combo.bind("<<ComboboxSelected>>", self._apply_theme)
        row += 1

        ttk.Label(form, text="Socket Timeout (seconds)").grid(row=row, column=0, sticky=W, pady=6)
        self.timeout_var = tk.StringVar(value=str(config.get("scan.socket_timeout", 2.0)))
        ttk.Entry(form, textvariable=self.timeout_var, width=12).grid(row=row, column=1, sticky=W, padx=10)
        row += 1

        ttk.Label(form, text="Max Threads").grid(row=row, column=0, sticky=W, pady=6)
        self.threads_var = tk.StringVar(value=str(config.get("scan.max_threads", 40)))
        ttk.Entry(form, textvariable=self.threads_var, width=12).grid(row=row, column=1, sticky=W, padx=10)
        row += 1

        ttk.Label(form, text="Report Directory").grid(row=row, column=0, sticky=W, pady=6)
        self.report_dir_var = tk.StringVar(value=config.get("report.output_dir", "exports"))
        ttk.Entry(form, textvariable=self.report_dir_var, width=40).grid(row=row, column=1, sticky=W, padx=10)
        row += 1

        ttk.Label(form, text="Company Name (for reports)").grid(row=row, column=0, sticky=W, pady=6)
        self.company_var = tk.StringVar(value=config.get("report.company_name", ""))
        ttk.Entry(form, textvariable=self.company_var, width=40).grid(row=row, column=1, sticky=W, padx=10)
        row += 1

        ttk.Label(form, text="Report Author").grid(row=row, column=0, sticky=W, pady=6)
        self.author_var = tk.StringVar(value=config.get("report.author", ""))
        ttk.Entry(form, textvariable=self.author_var, width=40).grid(row=row, column=1, sticky=W, padx=10)
        row += 1

        ttk.Label(form, text="NVD API Key (optional)").grid(row=row, column=0, sticky=W, pady=6)
        self.nvd_key_var = tk.StringVar(value=config.get("cve.nvd_api_key", ""))
        ttk.Entry(form, textvariable=self.nvd_key_var, width=40, show="•").grid(row=row, column=1, sticky=W, padx=10)
        row += 1

        self.status_var = tk.StringVar(value="")
        ttk.Label(self, textvariable=self.status_var, bootstyle="success").pack(anchor=W, padx=24)

        ttk.Button(self, text="Save Settings", bootstyle="success", command=self.save).pack(
            anchor=W, padx=24, pady=16
        )

    def _apply_theme(self, _event=None) -> None:
        self.app.set_theme(self.theme_var.get())

    def save(self) -> None:
        try:
            config.set("app.theme", self.theme_var.get(), persist=False)
            config.set("scan.socket_timeout", float(self.timeout_var.get()), persist=False)
            config.set("scan.max_threads", int(self.threads_var.get()), persist=False)
            config.set("report.output_dir", self.report_dir_var.get(), persist=False)
            config.set("report.company_name", self.company_var.get(), persist=False)
            config.set("report.author", self.author_var.get(), persist=False)
            config.set("cve.nvd_api_key", self.nvd_key_var.get(), persist=True)
            self.status_var.set("Settings saved.")
        except ValueError as exc:
            self.status_var.set(f"Invalid value: {exc}")
