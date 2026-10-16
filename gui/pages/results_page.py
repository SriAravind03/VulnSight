"""Results page: browse hosts/ports/CVE/web findings for a selected scan, with search."""

from __future__ import annotations

import tkinter as tk

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, X, LEFT, W, RIGHT

from database.models import ScanRepository, HostRepository, PortRepository, CveRepository, WebFindingRepository
from gui.widgets import SectionHeader, EmptyState

SEVERITY_TAG_COLORS = {
    "Critical": "#d9534f",
    "High": "#f0ad4e",
    "Medium": "#c9a227",
    "Low": "#5bc0de",
    "Informational": "#7d8fa3",
    "Unknown": "#7d8fa3",
}


class ResultsPage(ttk.Frame):
    def __init__(self, master, app, **kwargs):
        super().__init__(master, **kwargs)
        self.app = app
        self.scan_repo = ScanRepository()
        self.host_repo = HostRepository()
        self.port_repo = PortRepository()
        self.cve_repo = CveRepository()
        self.web_repo = WebFindingRepository()
        self.current_scan_id: int | None = None
        self._scan_lookup: dict[str, int] = {}

        SectionHeader(self, "Results", "Hosts, services, and vulnerabilities for a scan",
                      icon="📋").pack(fill=X, padx=24, pady=(20, 10))

        top_bar = ttk.Frame(self)
        top_bar.pack(fill=X, padx=24)
        ttk.Label(top_bar, text="Scan:").pack(side=LEFT)
        self.scan_selector = ttk.Combobox(top_bar, state="readonly", width=55)
        self.scan_selector.pack(side=LEFT, padx=8)
        self.scan_selector.bind("<<ComboboxSelected>>", self._on_scan_selected)

        ttk.Label(top_bar, text="Search:").pack(side=LEFT, padx=(20, 4))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(top_bar, textvariable=self.search_var, width=30)
        search_entry.pack(side=LEFT)
        search_entry.bind("<KeyRelease>", lambda e: self._apply_filters())

        self.report_btn = ttk.Button(top_bar, text="Generate Report →", bootstyle="success",
                                      command=self._go_to_reports)
        self.report_btn.pack(side=RIGHT)

        self.body = ttk.Frame(self)
        self.body.pack(fill=BOTH, expand=True, padx=24, pady=14)

        self._empty_state = EmptyState(
            self.body, icon="📭", title="No scans available yet",
            subtitle="Run a scan first, then come back here to explore its results.",
            button_text="Go to Scan Page", button_command=lambda: self.app.navigate("scan"),
        )

        self.notebook = ttk.Notebook(self.body)

        self.hosts_tab = self._make_tree_tab(
            "🖥  Hosts", ("ip", "hostname", "status", "os", "vendor"),
            [("ip", "IP Address"), ("hostname", "Hostname"), ("status", "Status"),
             ("os", "OS Guess"), ("vendor", "Vendor")],
        )
        self.ports_tab = self._make_tree_tab(
            "🔌  Ports & Services", ("host", "port", "proto", "state", "service", "version"),
            [("host", "Host"), ("port", "Port"), ("proto", "Proto"), ("state", "State"),
             ("service", "Service"), ("version", "Version")],
        )
        self.cve_tab = self._make_tree_tab(
            "🛡  CVE Findings", ("host", "cve", "severity", "cvss", "exploit", "patch"),
            [("host", "Host:Port"), ("cve", "CVE ID"), ("severity", "Severity"),
             ("cvss", "CVSS"), ("exploit", "Exploit"), ("patch", "Patch")],
            severity_col_index=2,
        )
        self.web_tab = self._make_tree_tab(
            "🌐  Web Findings", ("url", "category", "severity", "finding"),
            [("url", "URL"), ("category", "Category"), ("severity", "Severity"), ("finding", "Finding")],
            severity_col_index=2,
        )

        self._all_rows: dict[str, list[tuple]] = {"hosts": [], "ports": [], "cve": [], "web": []}
        self._showing_empty = True
        self._empty_state.pack(fill=BOTH, expand=True)

    def _make_tree_tab(self, title, columns, headers, severity_col_index: int | None = None):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=title)
        tree = ttk.Treeview(frame, columns=columns, show="headings", bootstyle="info")
        for col, label in headers:
            tree.heading(col, text=label)
            tree.column(col, width=150)
        for severity, color in SEVERITY_TAG_COLORS.items():
            tree.tag_configure(severity, foreground=color)
        tree._severity_col_index = severity_col_index  # stashed for row-tagging in _apply_filters
        tree.pack(fill=BOTH, expand=True, padx=4, pady=4)
        return tree

    def refresh(self, scan_id: int | None = None) -> None:
        scans = self.scan_repo.list_recent(limit=100)
        self._scan_lookup = {f"#{s['id']} - {s['target']} ({s['started_at']})": s["id"] for s in scans}
        self.scan_selector["values"] = list(self._scan_lookup.keys())

        if not scans:
            self._show_empty()
            self.current_scan_id = None
            return
        self._show_content()

        target_id = scan_id or self.current_scan_id
        if target_id is None:
            target_id = scans[0]["id"]

        for label, sid in self._scan_lookup.items():
            if sid == target_id:
                self.scan_selector.set(label)
                break

        self._load_scan(target_id)

    def _show_empty(self) -> None:
        if not self._showing_empty:
            self.notebook.pack_forget()
        self._empty_state.pack(fill=BOTH, expand=True)
        self._showing_empty = True
        self.report_btn.configure(state="disabled")

    def _show_content(self) -> None:
        if self._showing_empty:
            self._empty_state.pack_forget()
            self.notebook.pack(fill=BOTH, expand=True)
        self._showing_empty = False
        self.report_btn.configure(state="normal")

    def _on_scan_selected(self, _event=None) -> None:
        label = self.scan_selector.get()
        scan_id = self._scan_lookup.get(label)
        if scan_id:
            self._load_scan(scan_id)

    def _load_scan(self, scan_id: int) -> None:
        self.current_scan_id = scan_id
        hosts = self.host_repo.list_for_scan(scan_id)

        host_rows = []
        port_rows = []
        for h in hosts:
            host_rows.append((h["ip_address"], h.get("hostname") or "-", h.get("status", ""),
                               h.get("os_guess") or "-", h.get("vendor") or "-"))
            for p in self.port_repo.list_for_host(h["id"]):
                version = f"{p.get('product','')} {p.get('version','')}".strip() or "-"
                port_rows.append((h["ip_address"], p["port_number"], p["protocol"], p["state"],
                                   p.get("service_name") or "-", version))

        cve_rows = []
        for c in self.cve_repo.list_for_scan(scan_id):
            host_port = c.get("host_ip", "") + (f":{c['port_number']}" if c.get("port_number") else "")
            cve_rows.append((
                host_port, c["cve_id"], c.get("cvss_severity") or "Unknown",
                c.get("cvss_score", "N/A"),
                "Yes" if c.get("exploit_known") else "No",
                "Yes" if c.get("patch_available") else "No",
            ))

        web_rows = []
        for f in self.web_repo.list_for_scan(scan_id):
            web_rows.append((f["url"], f["category"], f["severity"], f["finding"]))

        self._all_rows = {"hosts": host_rows, "ports": port_rows, "cve": cve_rows, "web": web_rows}
        self._apply_filters()

    def _apply_filters(self) -> None:
        query = self.search_var.get().strip().lower()

        def matches(row: tuple) -> bool:
            return not query or any(query in str(v).lower() for v in row)

        for tree, key in ((self.hosts_tab, "hosts"), (self.ports_tab, "ports"),
                           (self.cve_tab, "cve"), (self.web_tab, "web")):
            for item in tree.get_children():
                tree.delete(item)
            sev_idx = getattr(tree, "_severity_col_index", None)
            for row in self._all_rows[key]:
                if not matches(row):
                    continue
                tags = ()
                if sev_idx is not None and sev_idx < len(row):
                    severity = str(row[sev_idx])
                    tags = (severity,) if severity in SEVERITY_TAG_COLORS else ()
                tree.insert("", "end", values=row, tags=tags)

    def _go_to_reports(self) -> None:
        if self.current_scan_id is None:
            self.app.show_error("No scan selected", "Select a scan first.")
            return
        self.app.navigate("reports", scan_id=self.current_scan_id)
