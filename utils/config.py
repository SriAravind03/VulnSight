"""
Configuration management for Sentinel Vulnerability Scanner.

Loads a YAML configuration file, falling back to bundled defaults on
first run, and exposes a small typed API for reading/writing settings
so the rest of the application never touches raw dictionaries directly.
"""

from __future__ import annotations

import shutil
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "default_config.yaml"
USER_CONFIG_PATH = PROJECT_ROOT / "config" / "user_config.yaml"


@dataclass
class ConfigManager:
    """Thread-safe wrapper around the application's YAML configuration."""

    path: Path = field(default_factory=lambda: USER_CONFIG_PATH)
    _data: dict[str, Any] = field(default_factory=dict, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def __post_init__(self) -> None:
        self._ensure_user_config_exists()
        self.reload()

    def _ensure_user_config_exists(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            if DEFAULT_CONFIG_PATH.exists():
                shutil.copy(DEFAULT_CONFIG_PATH, self.path)
            else:
                self.path.write_text("{}", encoding="utf-8")

    def reload(self) -> None:
        with self._lock:
            with open(self.path, "r", encoding="utf-8") as fh:
                self._data = yaml.safe_load(fh) or {}

    def save(self) -> None:
        with self._lock:
            with open(self.path, "w", encoding="utf-8") as fh:
                yaml.safe_dump(self._data, fh, sort_keys=False)

    def get(self, dotted_key: str, default: Any = None) -> Any:
        """Read a nested value using dotted notation, e.g. 'scan.max_threads'."""
        with self._lock:
            node: Any = self._data
            for part in dotted_key.split("."):
                if not isinstance(node, dict) or part not in node:
                    return default
                node = node[part]
            return node

    def set(self, dotted_key: str, value: Any, persist: bool = True) -> None:
        """Write a nested value using dotted notation and optionally persist it."""
        with self._lock:
            parts = dotted_key.split(".")
            node = self._data
            for part in parts[:-1]:
                node = node.setdefault(part, {})
            node[parts[-1]] = value
            if persist:
                self.save()

    def as_dict(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._data)


# Single shared instance used throughout the application.
config = ConfigManager()
