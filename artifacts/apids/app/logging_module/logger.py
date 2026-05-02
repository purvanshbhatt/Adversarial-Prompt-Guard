import os
import json
import uuid
from datetime import datetime, timezone
from typing import List, Dict

LOG_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../data/prompt_logs.json")
)


class PromptLogger:
    def __init__(self):
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        if not os.path.exists(LOG_PATH):
            self._save([])

    def log(self, entry: Dict) -> str:
        log_id = str(uuid.uuid4())[:8]
        entry["id"] = log_id
        entry["timestamp"] = datetime.now(timezone.utc).isoformat()
        logs = self._load()
        logs.append(entry)
        if len(logs) > 10000:
            logs = logs[-10000:]
        self._save(logs)
        return log_id

    def get_logs(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        logs = self._load()
        return list(reversed(logs))[offset : offset + limit]

    def get_stats(self) -> Dict:
        logs = self._load()
        if not logs:
            return {
                "total": 0,
                "malicious": 0,
                "benign": 0,
                "attack_type_breakdown": {},
                "avg_risk_score": 0.0,
                "detection_rate": 0.0,
            }

        malicious = [l for l in logs if l.get("is_malicious")]
        attack_types: Dict[str, int] = {}
        for log in malicious:
            for at in log.get("attack_types", []):
                attack_types[at] = attack_types.get(at, 0) + 1

        scores = [l.get("risk_score", 0) for l in logs]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        detection_rate = round(len(malicious) / len(logs) * 100, 1) if logs else 0.0

        return {
            "total": len(logs),
            "malicious": len(malicious),
            "benign": len(logs) - len(malicious),
            "attack_type_breakdown": attack_types,
            "avg_risk_score": avg_score,
            "detection_rate": detection_rate,
        }

    def clear(self):
        self._save([])

    def _load(self) -> List[Dict]:
        try:
            with open(LOG_PATH, "r") as f:
                return json.load(f)
        except Exception:
            return []

    def _save(self, logs: List[Dict]):
        with open(LOG_PATH, "w") as f:
            json.dump(logs, f, indent=2, ensure_ascii=False)
