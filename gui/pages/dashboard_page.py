"""Dashboard page: KPIs, recent scan activity, and quick actions."""

from __future__ import annotations

import tkinter as tk

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, X, LEFT, W, RIGHT

from database.models import ScanRepository, CveRepository
from gui.widgets import SectionHeader, StatCard, EmptyState, theme_colors
from scanner.engine import is_nmap_available, is_openvas_available


class DashboardPage(ttk.Frame):
    def __init__(self, master, app, **kwargs):
        super().__init__(master, **kwargs)
        self.app = app
        self.scan_repo = ScanRepository()
        self.cve_repo = CveRepository()

        header_row = ttk.Frame(self)
        header_row.pack(fill=X, padx=24, pady=(20, 10))
        SectionHeader(header_row, "Dashboard", "Overview of scan activity and system status",
                      icon="🏠").pack(side=LEFT, anchor=W)
        ttk.Button(header_row, text="＋  New Scan", bootstyle="success",
                   command=lambda: self.app.navigate("scan")).pack(side=RIGHT, anchor="e", pady=8)

        cards_frame = ttk.Frame(self)
        cards_frame.pack(fill=X, padx=24, pady=(6, 14))
        for i in range(4):
            cards_frame.columnconfigure(i, weight=1, uniform="cards", minsize=200)

        self.total_scans_card = StatCard(cards_frame, "Total Scans", "0", bootstyle="info", icon="📊")
        self.total_scans_card.grid(row=0, column=0, padx=6, sticky="nsew")
        self.critical_card = StatCard(cards_frame, "Critical / High Findings", "0", bootstyle="danger", icon="⚠")
        self.critical_card.grid(row=0, column=1, padx=6, sticky="nsew")
        self.engine_card = StatCard(cards_frame, "Scan Engine", "...", bootstyle="secondary", icon="🛰",
                                     value_font_size=17)
        self.engine_card.grid(row=0, column=2, padx=6, sticky="nsew")
        self.openvas_card = StatCard(cards_frame, "OpenVAS / Greenbone", "...", bootstyle="secondary", icon="🧩",
                                      value_font_size=17)
        self.openvas_card.grid(row=0, column=3, padx=6, sticky="nsew")

        recent_frame = ttk.Labelframe(self, text="  Recent Scans  ", padding=12)
        recent_frame.pack(fill=BOTH, expand=True, padx=24, pady=(0, 20))
        self._recent_container = recent_frame

        columns = ("target", "type", "status", "started")
        self.tree = ttk.Treeview(recent_frame, columns=columns, show="headings", bootstyle="info", height=10)
        for col, label, width in (
            ("target", "Target", 260), ("type", "Type", 110),
            ("status", "Status", 110), ("started", "Started", 200),
        ):
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width)
        self.tree.tag_configure("completed", foreground="#2ea043")
        self.tree.tag_configure("failed", foreground="#e5484d")
        self.tree.tag_configure("running", foreground="#d29922")
        self.tree.bind("<Double-1>", self._open_selected_scan)

        self._empty_state: EmptyState | None = None
        self._tree_visible = False

    def refresh(self) -> None:
        self.engine_card.set_value("nmap" if is_nmap_available() else "Fallback")
        self.openvas_card.set_value("Detected" if is_openvas_available() else "Not Found")

        scans = self.scan_repo.list_recent(limit=25)
        self.total_scans_card.set_value(str(len(scans)))

        if not scans:
            self._show_empty_state()
        else:
            self._show_tree()
            for row in self.tree.get_children():
                self.tree.delete(row)
            for scan in scans:
                self.tree.insert(
                    "", "end", iid=str(scan["id"]),
                    values=(scan["target"], scan["target_type"], scan["status"], scan["started_at"]),
                    tags=(scan["status"],),
                )

        critical_count = 0
        for scan in scans[:10]:
            for cve in self.cve_repo.list_for_scan(scan["id"]):
                if cve.get("cvss_score") and cve["cvss_score"] >= 7.0:
                    critical_count += 1
        self.critical_card.set_value(str(critical_count))

    def _show_empty_state(self) -> None:
        if self._tree_visible:
            self.tree.pack_forget()
            self._tree_visible = False
        if self._empty_state is None:
            colors = theme_colors(self)
            self._empty_state = EmptyState(
                self._recent_container, icon="🔍", title="No scans yet",
                subtitle="Run your first authorized scan to see results here.",
                button_text="Start a Scan", button_command=lambda: self.app.navigate("scan"),
                bg=colors.bg,
            )
        self._empty_state.pack(fill=BOTH, expand=True)

    def _show_tree(self) -> None:
        if self._empty_state is not None:
            self._empty_state.pack_forget()
        if not self._tree_visible:
            self.tree.pack(fill=BOTH, expand=True)
            self._tree_visible = True

    def _open_selected_scan(self, _event=None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        scan_id = int(selection[0])
        self.app.open_scan_in_results(scan_id)
