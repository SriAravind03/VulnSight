"""
Left-hand navigation sidebar.

Built with plain tk.Frame/tk.Label "buttons" (click-bound labels) using
explicit hex colors rather than ttkbootstrap bootstyle link-buttons.
This guarantees identical appearance and correct highlight/selection
behavior across platforms and ttkbootstrap versions, since it does not
depend on any theme-specific button style resolution.
"""

from __future__ import annotations

from typing import Callable

import tkinter as tk

from gui.widgets import theme_colors

NAV_ITEMS = [
    ("dashboard", "🏠", "Dashboard"),
    ("scan", "🔍", "Scan"),
    ("results", "📋", "Results"),
    ("reports", "📄", "Reports"),
    ("settings", "⚙", "Settings"),
    ("about", "ℹ", "About"),
]

SIDEBAR_BG = "#161b22"
ACTIVE_BG = "#2f6fed"
HOVER_BG = "#22283a"
TEXT_COLOR = "#c9d1d9"
ACTIVE_TEXT = "#ffffff"
MUTED_TEXT = "#7d8fa3"


class _NavButton(tk.Frame):
    def __init__(self, master, icon: str, label: str, on_click: Callable[[], None]):
        super().__init__(master, bg=SIDEBAR_BG, cursor="hand2")
        self.on_click = on_click
        self._active = False

        self.icon_label = tk.Label(self, text=icon, bg=SIDEBAR_BG, fg=TEXT_COLOR,
                                    font=("Segoe UI", 12), width=2)
        self.icon_label.pack(side="left", padx=(16, 6), pady=10)
        self.text_label = tk.Label(self, text=label, bg=SIDEBAR_BG, fg=TEXT_COLOR,
                                    font=("Segoe UI", 11), anchor="w")
        self.text_label.pack(side="left", fill="x", expand=True, pady=10)

        for widget in (self, self.icon_label, self.text_label):
            widget.bind("<Button-1>", lambda _e: self.on_click())
            widget.bind("<Enter>", self._on_enter)
            widget.bind("<Leave>", self._on_leave)

    def _on_enter(self, _event=None) -> None:
        if not self._active:
            self._set_bg(HOVER_BG)

    def _on_leave(self, _event=None) -> None:
        if not self._active:
            self._set_bg(SIDEBAR_BG)

    def _set_bg(self, color: str) -> None:
        for widget in (self, self.icon_label, self.text_label):
            widget.configure(bg=color)

    def set_active(self, active: bool) -> None:
        self._active = active
        if active:
            self._set_bg(ACTIVE_BG)
            self.icon_label.configure(fg=ACTIVE_TEXT)
            self.text_label.configure(fg=ACTIVE_TEXT, font=("Segoe UI", 11, "bold"))
        else:
            self._set_bg(SIDEBAR_BG)
            self.icon_label.configure(fg=TEXT_COLOR)
            self.text_label.configure(fg=TEXT_COLOR, font=("Segoe UI", 11))


class Sidebar(tk.Frame):
    def __init__(self, master, on_navigate: Callable[[str], None], **kwargs):
        super().__init__(master, width=216, bg=SIDEBAR_BG, highlightthickness=0, **kwargs)
        self.on_navigate = on_navigate
        self.pack_propagate(False)
        self._buttons: dict[str, _NavButton] = {}

        header = tk.Frame(self, bg=SIDEBAR_BG)
        header.pack(fill="x", pady=(22, 26), padx=18)
        tk.Label(header, text="🛡  Sentinel", bg=SIDEBAR_BG, fg="#ffffff",
                 font=("Segoe UI", 16, "bold")).pack(anchor="w")
        tk.Label(header, text="Vulnerability Scanner", bg=SIDEBAR_BG, fg=MUTED_TEXT,
                 font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 0))

        nav_frame = tk.Frame(self, bg=SIDEBAR_BG)
        nav_frame.pack(fill="x", padx=10)
        for key, icon, label in NAV_ITEMS:
            btn = _NavButton(nav_frame, icon, label, on_click=lambda k=key: self._select(k))
            btn.pack(fill="x", pady=2)
            self._buttons[key] = btn

        # Footer version tag, pinned to the bottom of the sidebar.
        footer = tk.Frame(self, bg=SIDEBAR_BG)
        footer.pack(side="bottom", fill="x", pady=14, padx=18)
        tk.Label(footer, text="v1.0.0", bg=SIDEBAR_BG, fg=MUTED_TEXT,
                 font=("Segoe UI", 8)).pack(anchor="w")

        self.select("dashboard")

    def _select(self, key: str) -> None:
        self.select(key)
        self.on_navigate(key)

    def select(self, key: str) -> None:
        for k, btn in self._buttons.items():
            btn.set_active(k == key)
