"""
Small reusable widgets shared across pages.

Design note: composite widgets here (StatCard, SeverityPill, EmptyState)
are built with plain tk.Frame/tk.Label and EXPLICIT hex colors pulled
from the active ttkbootstrap theme's Colors object, rather than relying
on 'bootstyle' shorthand strings on Frame/Label. This is a deliberate
defensive choice: bootstyle-based coloring on composite widgets can
render inconsistently across ttkbootstrap versions/platforms, while
plain tk color options are part of core Tkinter and render identically
everywhere. Standard controls (Button, Entry, Combobox, Treeview,
Checkbutton) still use ttkbootstrap's bootstyle system since that is
its well-tested core use case.
"""

from __future__ import annotations

import tkinter as tk

import ttkbootstrap as ttk
from ttkbootstrap.constants import LEFT, RIGHT, X, W


def theme_colors(widget):
    """Fetch the active theme's Colors object from any widget in the app."""
    root = widget.winfo_toplevel()
    return root.style.colors


class StatusBar(ttk.Frame):
    """Bottom status bar with a message label, a progress bar, and an
    engine indicator (nmap vs. built-in fallback scanner)."""

    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.message_var = tk.StringVar(value="Ready.")
        self.engine_var = tk.StringVar(value="")

        self.message_label = ttk.Label(self, textvariable=self.message_var, anchor=W)
        self.message_label.pack(side=LEFT, padx=10, pady=4, fill=X, expand=True)

        self.engine_label = ttk.Label(self, textvariable=self.engine_var, anchor="e",
                                       bootstyle="secondary")
        self.engine_label.pack(side=RIGHT, padx=10)

        self.progress = ttk.Progressbar(self, mode="determinate", length=180, bootstyle="info-striped")
        self.progress.pack(side=RIGHT, padx=10, pady=6)

    def set_message(self, text: str) -> None:
        self.message_var.set(text)

    def set_engine(self, text: str) -> None:
        self.engine_var.set(text)

    def set_progress(self, current: int, total: int) -> None:
        if total <= 0:
            self.progress.configure(mode="indeterminate")
            self.progress.start(12)
            return
        self.progress.stop()
        self.progress.configure(mode="determinate", maximum=total, value=current)

    def reset_progress(self) -> None:
        self.progress.stop()
        self.progress.configure(mode="determinate", value=0)


class SectionHeader(ttk.Frame):
    def __init__(self, master, title: str, subtitle: str = "", icon: str = "", **kwargs):
        super().__init__(master, **kwargs)
        title_text = f"{icon}  {title}" if icon else title
        ttk.Label(self, text=title_text, font=("Segoe UI", 19, "bold")).pack(anchor=W)
        if subtitle:
            ttk.Label(self, text=subtitle, bootstyle="secondary", font=("Segoe UI", 10)).pack(
                anchor=W, pady=(3, 0)
            )


class SeverityPill(tk.Label):
    """A small colored pill/badge showing a severity label with guaranteed
    background/foreground contrast (plain tk, no theme dependency)."""

    _COLORS = {
        "Critical": ("#d9534f", "#ffffff"),
        "High": ("#f0ad4e", "#231b0e"),
        "Medium": ("#f7d154", "#231b0e"),
        "Low": ("#5bc0de", "#0b2530"),
        "Informational": ("#7d8fa3", "#ffffff"),
        "Unknown": ("#7d8fa3", "#ffffff"),
    }

    def __init__(self, master, severity: str, **kwargs):
        bg, fg = self._COLORS.get(severity, self._COLORS["Unknown"])
        super().__init__(
            master, text=f"  {severity}  ", bg=bg, fg=fg,
            font=("Segoe UI", 9, "bold"), padx=2, pady=1, **kwargs,
        )


class StatCard(tk.Frame):
    """
    A dashboard KPI card: a big number + caption on a solid colored
    background. Built with plain tk widgets and explicit hex colors so
    it always renders correctly regardless of ttkbootstrap version.
    """

    _PALETTE = {
        "info": ("#2f6fed", "#ffffff"),
        "danger": ("#e5484d", "#ffffff"),
        "success": ("#2ea043", "#ffffff"),
        "warning": ("#d29922", "#1c1400"),
        "secondary": ("#3a4351", "#ffffff"),
    }

    def __init__(self, master, title: str, value: str = "0", bootstyle: str = "info",
                 icon: str = "", value_font_size: int = 24, **kwargs):
        bg, fg = self._PALETTE.get(bootstyle, self._PALETTE["secondary"])
        super().__init__(master, bg=bg, padx=16, pady=14, highlightthickness=0, **kwargs)

        top_row = tk.Frame(self, bg=bg)
        top_row.pack(fill="x", anchor=W)
        if icon:
            tk.Label(top_row, text=icon, bg=bg, fg=fg, font=("Segoe UI", 14)).pack(side=LEFT)

        self.value_var = tk.StringVar(value=value)
        self.value_label = tk.Label(self, textvariable=self.value_var, bg=bg, fg=fg,
                                     font=("Segoe UI", value_font_size, "bold"), anchor=W)
        self.value_label.pack(anchor=W, pady=(2, 0), fill="x")
        tk.Label(self, text=title, bg=bg, fg=fg, font=("Segoe UI", 10), anchor=W).pack(anchor=W, fill="x")

    def set_value(self, value: str) -> None:
        self.value_var.set(value)


class EmptyState(tk.Frame):
    """A friendly placeholder shown instead of a blank table when there is
    no data yet, with an icon, message, and an optional call-to-action button."""

    def __init__(self, master, icon: str, title: str, subtitle: str = "",
                 button_text: str = "", button_command=None, bg: str | None = None, **kwargs):
        colors = theme_colors(master)
        bg = bg or colors.bg
        super().__init__(master, bg=bg, **kwargs)

        inner = tk.Frame(self, bg=bg)
        inner.place(relx=0.5, rely=0.42, anchor="center")

        tk.Label(inner, text=icon, bg=bg, fg=colors.secondary, font=("Segoe UI", 36)).pack()
        tk.Label(inner, text=title, bg=bg, fg=colors.fg, font=("Segoe UI", 13, "bold")).pack(pady=(10, 2))
        if subtitle:
            tk.Label(inner, text=subtitle, bg=bg, fg=colors.secondary, font=("Segoe UI", 10)).pack()
        if button_text and button_command:
            ttk.Button(inner, text=button_text, bootstyle="success", command=button_command).pack(pady=(14, 0))
