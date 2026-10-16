"""About page: application info, disclaimer, and third-party components."""

from __future__ import annotations

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, X, W

from gui.widgets import SectionHeader
from scanner.engine import is_nmap_available, is_openvas_available
from utils.config import config

DISCLAIMER = (
    "Sentinel Vulnerability Scanner is intended solely for assessing systems "
    "that you own or have explicit written authorization to test. Scanning "
    "systems without authorization may be illegal in your jurisdiction. "
    "The authors accept no liability for misuse of this software. All web "
    "checks performed by this tool are non-destructive and passive; it does "
    "not attempt exploitation, authentication bypass, or denial-of-service."
)


class AboutPage(ttk.Frame):
    def __init__(self, master, app, **kwargs):
        super().__init__(master, **kwargs)
        self.app = app

        SectionHeader(self, "About", "Sentinel Vulnerability Scanner", icon="ℹ").pack(fill=X, padx=24, pady=(20, 10))

        info = ttk.Frame(self)
        info.pack(fill=X, padx=24, pady=10)

        ttk.Label(info, text=f"Version: {config.get('app.version', '1.0.0')}").pack(anchor=W, pady=2)
        ttk.Label(info, text=f"Scan Engine: {'nmap (python-nmap)' if is_nmap_available() else 'Built-in fallback (socket-based)'}").pack(anchor=W, pady=2)
        ttk.Label(info, text=f"OpenVAS/Greenbone: {'Detected' if is_openvas_available() else 'Not detected'}").pack(anchor=W, pady=2)

        disclaimer_frame = ttk.Labelframe(self, text="Authorized Use Only", padding=14, bootstyle="warning")
        disclaimer_frame.pack(fill=X, padx=24, pady=16)
        ttk.Label(disclaimer_frame, text=DISCLAIMER, wraplength=760, justify="left").pack(anchor=W)

        credits_frame = ttk.Labelframe(self, text="Built With", padding=14)
        credits_frame.pack(fill=X, padx=24, pady=6)
        components = (
            "Python 3.12+, Tkinter, ttkbootstrap, python-nmap, requests, BeautifulSoup4, "
            "reportlab, Jinja2, matplotlib, PyYAML, SQLite"
        )
        ttk.Label(credits_frame, text=components, wraplength=760, justify="left").pack(anchor=W)
