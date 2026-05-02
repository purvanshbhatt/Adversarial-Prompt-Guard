from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict


class AgentBase(ABC):
    name: str = "base"
    version: str = "1.0.0"
    description: str = ""

    def status(self) -> Dict[str, Any]:
        return {
            "agent": self.name,
            "version": self.version,
            "description": self.description,
            "status": "online",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @abstractmethod
    def process(self, *args, **kwargs) -> Dict[str, Any]:
        ...
