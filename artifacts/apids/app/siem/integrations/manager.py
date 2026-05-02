"""
Integration Manager — routes every SIEM event to all registered integrations.
"""

from typing import Dict, List

from .wazuh       import WazuhIntegration
from .crowdstrike import CrowdStrikeIntegration
from .elastic     import ElasticIntegration
from .sentinel    import SentinelIntegration
from .qradar      import QRadarIntegration
from .xsoar       import XSOARIntegration
from .chronicle   import ChronicleIntegration


class IntegrationManager:
    def __init__(self):
        self._integrations = [
            WazuhIntegration(),
            CrowdStrikeIntegration(),
            ElasticIntegration(),
            SentinelIntegration(),
            QRadarIntegration(),
            XSOARIntegration(),
            ChronicleIntegration(),
        ]

    def forward_all(self, hec_event: Dict) -> Dict[str, bool]:
        """Forward a HEC event to every integration. Returns {name: success}."""
        results: Dict[str, bool] = {}
        for integration in self._integrations:
            try:
                ok = integration.forward(hec_event)
                results[integration.name] = ok
            except Exception:
                results[integration.name] = False
        return results

    def get_all_statuses(self) -> List[Dict]:
        return [i.status() for i in self._integrations]

    def get_status(self, name: str) -> Dict:
        for i in self._integrations:
            if i.name == name:
                return i.status()
        return {}

    def get_events(self, name: str, limit: int = 20) -> List[Dict]:
        for i in self._integrations:
            if i.name == name:
                return i.get_recent_events(limit)
        return []

    def get_native_event_preview(self, name: str) -> Dict:
        """Return the most recent native event formatted for this integration."""
        for i in self._integrations:
            if i.name == name:
                events = i.get_recent_events(1)
                if events:
                    return events[0].get("native", {})
        return {}

    def get_summary(self) -> Dict:
        statuses = self.get_all_statuses()
        return {
            "total":       len(statuses),
            "live":        sum(1 for s in statuses if s["mode"] == "LIVE"),
            "simulation":  sum(1 for s in statuses if s["mode"] == "SIMULATION"),
            "error":       sum(1 for s in statuses if s["mode"] == "ERROR"),
            "configured":  sum(1 for s in statuses if s["configured"]),
            "total_forwarded": sum(s["forwarded"] for s in statuses),
        }


# Singleton
integration_manager = IntegrationManager()
