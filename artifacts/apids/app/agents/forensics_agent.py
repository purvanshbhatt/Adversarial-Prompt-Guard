from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base import AgentBase
from .shared_memory import EventStore, SecurityEvent


class ForensicsAgent(AgentBase):
    name = "forensics"
    version = "1.0.0"
    description = "Stores all security events, builds attack timeline, generates investigation reports"

    def process(
        self,
        event: SecurityEvent,
    ) -> Dict[str, Any]:
        store = EventStore.get()
        store.add(event)
        stats = store.get_stats()

        return {
            "agent": self.name,
            "event_stored": True,
            "event_id": event.event_id,
            "total_events": stats["total_events"],
            "malicious_events": stats["malicious_events"],
            "critical_events": stats["critical_events"],
        }

    def get_timeline(self, limit: int = 50) -> List[Dict]:
        store = EventStore.get()
        raw = store.get_timeline(limit=limit)
        timeline = []
        for e in raw:
            data = e.get("data", {})
            timeline.append({
                "event_id": e.get("event_id"),
                "timestamp": e.get("timestamp", ""),
                "session_id": e.get("session_id", ""),
                "agent": e.get("agent", ""),
                "severity": e.get("severity", "INFO"),
                "event_type": e.get("event_type", ""),
                "enterprise_risk_score": e.get("enterprise_risk_score", 0.0),
                "is_malicious": data.get("is_malicious", False),
                "attack_types": data.get("attack_types", []),
                "prompt_preview": e.get("prompt", "")[:120],
                "tags": e.get("tags", []),
            })
        return timeline

    def get_investigation_report(self, session_id: Optional[str] = None) -> str:
        store = EventStore.get()
        stats = store.get_stats()

        if session_id:
            events = store.get_events(limit=200, session_id=session_id)
            scope = f"Session `{session_id}`"
        else:
            events = store.get_events(limit=200)
            scope = "All Sessions (Global)"

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        malicious = [e for e in events if e.get("data", {}).get("is_malicious")]
        critical = [e for e in events if e.get("severity") == "CRITICAL"]
        high = [e for e in events if e.get("severity") == "HIGH"]

        attack_type_counts: Dict[str, int] = {}
        for e in malicious:
            for at in e.get("data", {}).get("attack_types", []):
                attack_type_counts[at] = attack_type_counts.get(at, 0) + 1
        top_attacks = sorted(attack_type_counts.items(), key=lambda x: -x[1])[:5]

        corr_insights: List[str] = []
        for e in events:
            corr = e.get("data", {}).get("correlation", {})
            for ins in corr.get("insights", []):
                desc = ins.get("description", "")
                if desc and desc not in corr_insights:
                    corr_insights.append(desc)

        risk_scores = [e.get("enterprise_risk_score", 0) for e in events if e.get("enterprise_risk_score", 0) > 0]
        avg_risk = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0.0
        max_risk = round(max(risk_scores), 1) if risk_scores else 0.0

        report_lines = [
            "# AuroraSOC — Forensic Investigation Report",
            f"**Generated:** {now}",
            f"**Scope:** {scope}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            f"- **Total Events Analyzed:** {stats['total_events']}",
            f"- **Malicious Events:** {stats['malicious_events']}",
            f"- **Critical Severity Events:** {stats['critical_events']}",
            f"- **High Severity Events:** {stats['high_events']}",
            f"- **Active Agents:** {', '.join(stats['agents_active']) or 'None'}",
            f"- **Avg Enterprise Risk Score:** {avg_risk} / 100",
            f"- **Peak Enterprise Risk Score:** {max_risk} / 100",
            "",
            "---",
            "",
            "## Attack Type Distribution",
            "",
        ]

        if top_attacks:
            for atype, count in top_attacks:
                report_lines.append(f"- **{atype.replace('_', ' ').title()}**: {count} occurrences")
        else:
            report_lines.append("- No attack types recorded yet.")

        report_lines += [
            "",
            "---",
            "",
            "## Threat Correlation Insights",
            "",
        ]

        if corr_insights:
            for ins in corr_insights[:8]:
                report_lines.append(f"- {ins}")
        else:
            report_lines.append("- No cross-event correlation insights detected yet.")

        report_lines += [
            "",
            "---",
            "",
            "## Critical Events",
            "",
        ]

        if critical:
            for e in critical[:10]:
                ts = e.get("timestamp", "")[:19].replace("T", " ")
                prompt = e.get("prompt", "")[:100]
                score = e.get("enterprise_risk_score", 0.0)
                report_lines.append(
                    f"- `{ts}` | Session `{e.get('session_id','')}` | "
                    f"Risk {score:.1f} | `{prompt}…`"
                )
        else:
            report_lines.append("- No critical events in scope.")

        report_lines += [
            "",
            "---",
            "",
            "## Attack Timeline (Last 20 Events)",
            "",
            "| Time | Severity | Risk | Attack Types | Prompt Preview |",
            "|------|----------|------|--------------|----------------|",
        ]

        for e in events[:20]:
            ts = e.get("timestamp", "")[:19].replace("T", " ")
            sev = e.get("severity", "INFO")
            score = e.get("enterprise_risk_score", 0.0)
            atypes = ", ".join(e.get("data", {}).get("attack_types", [])) or "—"
            preview = e.get("prompt", "")[:60].replace("|", "\\|")
            report_lines.append(f"| {ts} | {sev} | {score:.1f} | {atypes} | {preview}… |")

        report_lines += [
            "",
            "---",
            "",
            "## Recommended Actions",
            "",
            "1. Review all CRITICAL and HIGH severity events immediately.",
            "2. Invalidate sessions with coordinated attack signatures.",
            "3. Retrain ML classifier with newly captured adversarial prompts.",
            "4. Update rule-based signatures to cover detected attack patterns.",
            "5. Run adversary simulation to verify post-hardening robustness.",
            "",
            "---",
            "*Report generated by AuroraSOC Forensics Agent v1.0.0*",
        ]

        return "\n".join(report_lines)
