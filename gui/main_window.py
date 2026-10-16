"""Main application window: sidebar navigation + page container + status bar."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, LEFT, RIGHT, X, Y, TOP

from gui.pages.about_page import AboutPage
from gui.pages.dashboard_page import DashboardPage
from gui.pages.reports_page import ReportsPage
from gui.pages.results_page import ResultsPage
from gui.pages.scan_page import ScanPage
from gui.pages.settings_page import SettingsPage
from gui.sidebar import Sidebar
from gui.widgets import StatusBar
from scanner.engine import is_nmap_available
from utils.config import config
from utils.logger import get_logger

logger = get_logger("gui.main_window")


class SentinelApp(ttk.Window):
    def __init__(self) -> None:
        theme = config.get("app.theme", "darkly")
        super().__init__(themename=theme, title="Sentinel Vulnerability Scanner")
        self.geometry("1200x760")
        self.minsize(980, 620)

        body = ttk.Frame(self)
        body.pack(fill=BOTH, expand=True)

        self.sidebar = Sidebar(body, on_navigate=self.navigate)
        self.sidebar.pack(side=LEFT, fill=Y)

        self.content = ttk.Frame(body)
        self.content.pack(side=LEFT, fill=BOTH, expand=True)

        self.status_bar = StatusBar(self)
        self.status_bar.pack(side="bottom", fill=X)
        self.status_bar.set_engine("Engine: nmap" if is_nmap_available() else "Engine: fallback scanner")

        self.pages: dict[str, ttk.Frame] = {
            "dashboard": DashboardPage(self.content, self),
            "scan": ScanPage(self.content, self),
            "results": ResultsPage(self.content, self),
            "reports": ReportsPage(self.content, self),
            "settings": SettingsPage(self.content, self),
            "about": AboutPage(self.content, self),
        }
        for page in self.pages.values():
            page.place(relx=0, rely=0, relwidth=1, relheight=1)

        self._current_page = None
        self.navigate("dashboard")

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def navigate(self, page_key: str, scan_id: int | None = None) -> None:
        page = self.pages.get(page_key)
        if page is None:
            return
        page.tkraise()
        self.sidebar.select(page_key)
        self._current_page = page_key

        if page_key == "dashboard":
            page.refresh()
        elif page_key == "results":
            page.refresh(scan_id)
        elif page_key == "reports":
            page.refresh(scan_id)

    def open_scan_in_results(self, scan_id: int) -> None:
        self.navigate("results", scan_id=scan_id)

    def set_theme(self, theme_name: str) -> None:
        try:
            self.style.theme_use(theme_name)
            config.set("app.theme", theme_name, persist=True)
        except Exception as exc:
            logger.warning("Failed to apply theme %s: %s", theme_name, exc)

    def show_error(self, title: str, message: str) -> None:
        messagebox.showerror(title, message, parent=self)

    def show_info(self, title: str, message: str) -> None:
        messagebox.showinfo(title, message, parent=self)

    def _on_close(self) -> None:
        logger.info("Application closing.")
        self.destroy()
