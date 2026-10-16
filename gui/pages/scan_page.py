"""Scan page: target/options entry, authorization gate, and live scan execution."""

from __future__ import annotations

import threading
import tkinter as tk

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, X, LEFT, W, YES

from gui.widgets import SectionHeader
from scanner.engine import is_nmap_available
from scanner.orchestrator import ScanOrchestrator, ScanOptions, AuthorizationError, ProgressEvent
from utils.logger import get_logger
from utils.validators import ValidatedTarget, ValidationError

logger = get_logger("gui.scan_page")


class ScanPage(ttk.Frame):
    def __init__(self, master, app, **kwargs):
        super().__init__(master, **kwargs)
        self.app = app
        self.orchestrator = ScanOrchestrator()
        self._scan_thread: threading.Thread | None = None
        self._last_scan_id: int | None = None

        SectionHeader(self, "Scan", "Configure and run a new authorized scan", icon="🔍").pack(
            fill=X, padx=24, pady=(20, 10)
        )

        form = ttk.Frame(self)
        form.pack(fill=X, padx=24, pady=6)

        ttk.Label(form, text="Target (IP, CIDR, hostname, or URL)").grid(row=0, column=0, sticky=W, pady=4)
        self.target_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.target_var, width=48).grid(row=0, column=1, sticky=W, padx=10)

        ttk.Label(form, text="Ports").grid(row=1, column=0, sticky=W, pady=4)
        self.ports_var = tk.StringVar(value="1-1024")
        ttk.Entry(form, textvariable=self.ports_var, width=24).grid(row=1, column=1, sticky=W, padx=10)

        options_frame = ttk.Labelframe(self, text="Scan Options", padding=14)
        options_frame.pack(fill=X, padx=24, pady=10)

        self.opt_host_discovery = tk.BooleanVar(value=True)
        self.opt_tcp = tk.BooleanVar(value=True)
        self.opt_udp = tk.BooleanVar(value=False)
        self.opt_service = tk.BooleanVar(value=True)
        self.opt_os = tk.BooleanVar(value=False)
        self.opt_web = tk.BooleanVar(value=True)
        self.opt_cve = tk.BooleanVar(value=True)

        checks = [
            ("Host Discovery", self.opt_host_discovery),
            ("TCP Scan", self.opt_tcp),
            ("UDP Scan (slower)", self.opt_udp),
            ("Service Detection", self.opt_service),
            ("OS Detection (nmap only)", self.opt_os),
            ("Safe Web Scan", self.opt_web),
            ("CVE Lookup", self.opt_cve),
        ]
        for i, (label, var) in enumerate(checks):
            ttk.Checkbutton(options_frame, text=label, variable=var, bootstyle="round-toggle").grid(
                row=i // 3, column=i % 3, sticky=W, padx=10, pady=4
            )

        engine_note = "Engine: nmap detected" if is_nmap_available() else \
            "Engine: nmap not found -- using built-in Python fallback scanner"
        ttk.Label(self, text=engine_note, bootstyle="secondary").pack(anchor=W, padx=24)

        auth_frame = ttk.Labelframe(self, text="Authorization (required)", padding=14, bootstyle="warning")
        auth_frame.pack(fill=X, padx=24, pady=12)
        self.auth_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            auth_frame,
            text="I confirm I own this target or have explicit written authorization to test it.",
            variable=self.auth_var, bootstyle="warning-round-toggle",
        ).pack(anchor=W)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=X, padx=24, pady=6)
        self.start_btn = ttk.Button(btn_frame, text="▶ Start Scan", bootstyle="success", command=self.start_scan)
        self.start_btn.pack(side=LEFT, padx=(0, 8))
        self.cancel_btn = ttk.Button(btn_frame, text="■ Cancel", bootstyle="danger-outline",
                                      command=self.cancel_scan, state="disabled")
        self.cancel_btn.pack(side=LEFT)

        log_frame = ttk.Labelframe(self, text="Scan Log", padding=8)
        log_frame.pack(fill=BOTH, expand=True, padx=24, pady=(6, 20))
        self.log_text = tk.Text(log_frame, height=10, wrap="word", state="disabled",
                                 bg="#12181f", fg="#d6e0ea", insertbackground="#d6e0ea", relief="flat")
        self.log_text.pack(fill=BOTH, expand=True)

    def _log(self, message: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def start_scan(self) -> None:
        raw_target = self.target_var.get().strip()
        try:
            target = ValidatedTarget.from_input(raw_target)
        except ValidationError as exc:
            self.app.show_error("Invalid target", str(exc))
            return

        if not self.auth_var.get():
            self.app.show_error(
                "Authorization required",
                "You must confirm you own this target or have explicit written authorization to test it "
                "before a scan can start.",
            )
            return

        options = ScanOptions(
            port_spec=self.ports_var.get().strip() or "1-1024",
            host_discovery=self.opt_host_discovery.get(),
            tcp_scan=self.opt_tcp.get(),
            udp_scan=self.opt_udp.get(),
            service_detection=self.opt_service.get(),
            os_detection=self.opt_os.get(),
            web_scan=self.opt_web.get(),
            cve_lookup=self.opt_cve.get(),
        )

        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

        self.start_btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal")
        self.app.status_bar.set_message(f"Scanning {target.normalized_value}...")
        self.app.status_bar.set_progress(0, 0)

        self._scan_thread = threading.Thread(
            target=self._run_scan_thread, args=(target, options), daemon=True
        )
        self._scan_thread.start()

    def _run_scan_thread(self, target: ValidatedTarget, options: ScanOptions) -> None:
        def progress_cb(event: ProgressEvent) -> None:
            self.after(0, self._handle_progress, event)

        try:
            scan_id = self.orchestrator.run(target, options, authorized=True, progress_cb=progress_cb)
            self._last_scan_id = scan_id
            self.after(0, self._on_scan_success, scan_id)
        except AuthorizationError as exc:
            self.after(0, self.app.show_error, "Authorization required", str(exc))
            self.after(0, self._on_scan_finished)
        except Exception as exc:
            logger.exception("Scan thread failed")
            self.after(0, self._log, f"ERROR: {exc}")
            self.after(0, self._on_scan_finished)

    def _handle_progress(self, event: ProgressEvent) -> None:
        self._log(f"[{event.stage}] {event.message}")
        self.app.status_bar.set_message(event.message)
        if event.total:
            self.app.status_bar.set_progress(event.current, event.total)

    def _on_scan_success(self, scan_id: int) -> None:
        self._log(f"Scan #{scan_id} completed successfully.")
        self.app.status_bar.set_message("Scan completed.")
        self.app.status_bar.reset_progress()
        self._on_scan_finished()
        self.app.open_scan_in_results(scan_id)

    def _on_scan_finished(self) -> None:
        self.start_btn.configure(state="normal")
        self.cancel_btn.configure(state="disabled")

    def cancel_scan(self) -> None:
        self.orchestrator.cancel()
        self._log("Cancellation requested; finishing current step...")
        self.app.status_bar.set_message("Cancelling...")
