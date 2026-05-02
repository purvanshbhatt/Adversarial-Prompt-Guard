"""Base class for all SIEM/EDR integrations."""

import time
import uuid
from abc import ABC, abstractmethod
from collections import deque
from typing import Any, Dict, List, Optional


class SIEMIntegration(ABC):
    name: str           = "base"
    display_name: str   = "Base Integration"
    vendor: str         = "Unknown"
    icon: str           = "🔌"
    format_name: str    = "Generic"
    color: str          = "#58a6ff"
    category: str       = "SIEM"

    def __init__(self):
        self._events:     deque = deque(maxlen=500)
        self._forwarded:  int   = 0
        self._failed:     int   = 0
        self._last_error: Optional[str] = None
        self._connected:  Optional[bool] = None  # None = not yet tested

    # ── Abstract ───────────────────────────────────────────────────────────────

    @abstractmethod
    def is_configured(self) -> bool:
        """Returns True if real API credentials are set via env vars."""

    @abstractmethod
    def format_event(self, hec_event: Dict) -> Dict:
        """Convert a HEC event envelope to this tool's native format."""

    def _send(self, native_event: Dict) -> bool:
        """
        Attempt to POST the native event to the real API.
        Override this in subclasses that support real connectivity.
        Returns True on success.
        """
        return False

    # ── Public ─────────────────────────────────────────────────────────────────

    def forward(self, hec_event: Dict) -> bool:
        """Format and forward a HEC event. Always succeeds in simulation mode."""
        try:
            native = self.format_event(hec_event)
        except Exception as e:
            self._last_error = f"Format error: {e}"
            return False

        record = {
            "_id":        str(uuid.uuid4()),
            "_ts":        time.time(),
            "_simulated": not self.is_configured(),
            "native":     native,
        }
        self._events.appendleft(record)

        if self.is_configured():
            ok = self._send(native)
            if ok:
                self._forwarded += 1
                self._connected = True
            else:
                self._failed += 1
                self._connected = False
            return ok
        else:
            self._forwarded += 1
            return True

    def get_recent_events(self, limit: int = 20) -> List[Dict]:
        return list(self._events)[:limit]

    def status(self) -> Dict:
        if self.is_configured():
            mode = "LIVE" if self._connected else ("ERROR" if self._connected is False else "PENDING")
        else:
            mode = "SIMULATION"
        return {
            "name":         self.name,
            "display_name": self.display_name,
            "vendor":       self.vendor,
            "icon":         self.icon,
            "format":       self.format_name,
            "color":        self.color,
            "category":     self.category,
            "mode":         mode,
            "configured":   self.is_configured(),
            "forwarded":    self._forwarded,
            "failed":       self._failed,
            "last_error":   self._last_error,
            "env_vars":     self._env_var_names(),
        }

    def _env_var_names(self) -> List[str]:
        return []

    def _extract_event(self, hec_event: Dict) -> Dict:
        return hec_event.get("event", hec_event)
