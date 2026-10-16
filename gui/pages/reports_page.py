"""Reports page: generate PDF/HTML/CSV/JSON reports for a scan and browse past reports."""

from __future__ import annotations

import os
import platform
import subprocess
import threading
import tkinter as tk

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, X, LEFT, W

from database.models import ScanRepository, ReportRepository
from gui.widgets import SectionHeader, EmptyState
from reports.manager import generate_report
from utils.logger import get_logger

logger = get_logger("gui.reports_page")


class ReportsPage(ttk.Frame):
    def __init__(self, master, app, **kwargs):
        super().__init__(master, **kwargs)
        self.app = app
        self.scan_repo = ScanRepository()
        self.report_repo = ReportRepository()
        self.current_scan_id: int | None = None
        self._scan_lookup: dict[str, int] = {}
        self._format_buttons: list[ttk.Button] = []

        SectionHeader(self, "Reports", "Generate and export professional scan reports",
                      icon="📄").pack(fill=X, padx=24, pady=(20, 10))

        top_bar = ttk.Frame(self)
        top_bar.pack(fill=X, padx=24)
        ttk.Label(top_bar, text="Scan:").pack(side=LEFT)
        self.scan_selector = ttk.Combobox(top_bar, state="readonly", width=55)
        self.scan_selector.pack(side=LEFT, padx=8)
        self.scan_selector.bind("<<ComboboxSelected>>", self._on_scan_selected)

        format_frame = ttk.Labelframe(self, text="  Generate  ", padding=14)
        format_frame.pack(fill=X, padx=24, pady=14)

        self.status_var = tk.StringVar(value="")
        for fmt, style in (("pdf", "danger"), ("html", "info"), ("csv", "success"), ("json", "secondary")):
            btn = ttk.Button(
                format_frame, text=f"⬇  Generate {fmt.upper()}", bootstyle=style,
                command=lambda f=fmt: self._generate(f),
            )
            btn.pack(side=LEFT, padx=6)
            self._format_buttons.append(btn)

        ttk.Label(self, textvariable=self.status_var, bootstyle="secondary").pack(anchor=W, padx=24)

        self.body = ttk.Frame(self)
        self.body.pack(fill=BOTH, expand=True, padx=24, pady=16)

        self._empty_state = EmptyState(
            self.body, icon="📄", title="No scans available yet",
            subtitle="Run a scan first, then generate a PDF/HTML/CSV/JSON report here.",
            button_text="Go to Scan Page", button_command=lambda: self.app.navigate("scan"),
        )

        self.history_frame = ttk.Labelframe(self.body, text="  Generated Reports  ", padding=12)

        columns = ("format", "path", "generated_at")
        self.tree = ttk.Treeview(self.history_frame, columns=columns, show="headings", bootstyle="info")
        for col, label, width in (("format", "Format", 80), ("path", "File Path", 480),
                                   ("generated_at", "Generated At", 180)):
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width)
        self.tree.pack(fill=BOTH, expand=True)
        self.tree.bind("<Double-1>", self._open_selected_report)

        self._showing_empty = True
        self._set_generate_enabled(False)
        self._empty_state.pack(fill=BOTH, expand=True)

    def _set_generate_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        for btn in self._format_buttons:
            btn.configure(state=state)

    def refresh(self, scan_id: int | None = None) -> None:
        scans = self.scan_repo.list_recent(limit=100)
        self._scan_lookup = {f"#{s['id']} - {s['target']} ({s['started_at']})": s["id"] for s in scans}
        self.scan_selector["values"] = list(self._scan_lookup.keys())

        if not scans:
            self.current_scan_id = None
            self._set_generate_enabled(False)
            if not self._showing_empty:
                self.history_frame.pack_forget()
            self._empty_state.pack(fill=BOTH, expand=True)
            self._showing_empty = True
            return

        if self._showing_empty:
            self._empty_state.pack_forget()
            self.history_frame.pack(fill=BOTH, expand=True)
        self._showing_empty = False
        self._set_generate_enabled(True)

        target_id = scan_id or self.current_scan_id
        if target_id is None:
            target_id = scans[0]["id"]

        for label, sid in self._scan_lookup.items():
            if sid == target_id:
                self.scan_selector.set(label)
                break

        self.current_scan_id = target_id
        self._reload_history()

    def _on_scan_selected(self, _event=None) -> None:
        label = self.scan_selector.get()
        scan_id = self._scan_lookup.get(label)
        if scan_id:
            self.current_scan_id = scan_id
            self._reload_history()

    def _reload_history(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        if self.current_scan_id is None:
            return
        for r in self.report_repo.list_for_scan(self.current_scan_id):
            self.tree.insert("", "end", iid=str(r["id"]),
                              values=(r["format"].upper(), r["file_path"], r["generated_at"]))

    def _generate(self, fmt: str) -> None:
        if self.current_scan_id is None:
            self.app.show_error("No scan selected", "Select a scan first.")
            return
        self.status_var.set(f"Generating {fmt.upper()} report...")
        threading.Thread(target=self._generate_thread, args=(fmt,), daemon=True).start()

    def _generate_thread(self, fmt: str) -> None:
        try:
            path = generate_report(self.current_scan_id, fmt)
            self.after(0, self._on_generated, fmt, path)
        except Exception as exc:
            logger.exception("Report generation failed")
            self.after(0, self.status_var.set, f"Failed to generate {fmt.upper()} report: {exc}")

    def _on_generated(self, fmt: str, path) -> None:
        self.status_var.set(f"✓ {fmt.upper()} report generated: {path}")
        self._reload_history()

    def _open_selected_report(self, _event=None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        values = self.tree.item(selection[0], "values")
        file_path = values[1]
        self._open_file(file_path)

    @staticmethod
    def _open_file(path: str) -> None:
        try:
            system = platform.system()
            if system == "Windows":
                os.startfile(path)  # type: ignore[attr-defined]
            elif system == "Darwin":
                subprocess.run(["open", path], check=False)
            else:
                subprocess.run(["xdg-open", path], check=False)
        except Exception as exc:
            logger.warning("Could not open %s: %s", path, exc)
