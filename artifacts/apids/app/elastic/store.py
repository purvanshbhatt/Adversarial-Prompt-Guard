"""
Elastic Security log store — ECS 8.x format with in-memory indexing.

Every detection event is indexed with:
  - event_type          "prompt_injection" | "benign" | "obfuscation" | "jailbreak"
  - risk_score          0–100 float
  - attack_category     primary attack category (first in list)
  - attack_categories   full list
  - obfuscation_type    primary obfuscation technique (first in list)
  - obfuscation_types   full list
  - @timestamp, host, aurora.* fields

Provides:
  - index(event)                 — add a document
  - search(q, filters, size)     — full-text + field filter
  - get_timeline(hours, bucket)  — histogram
  - aggregate(field, size)       — top-N value counts
  - get_stats()                  — dashboard KPIs
"""

import re
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

MAX_DOCS = 5000

_SEVERITY_MAP = [
    (90, "critical"),
    (75, "high"),
    (40, "medium"),
    (0,  "low"),
]

_EVENT_TYPE_MAP = {
    "jailbreak":            "jailbreak",
    "instruction_override": "instruction_override",
    "data_exfiltration":    "data_exfiltration",
    "prompt_injection":     "prompt_injection",
    "role_play":            "social_engineering",
    "social_engineering":   "social_engineering",
    "token_manipulation":   "obfuscation",
    "obfuscation":          "obfuscation",
    "context_manipulation": "context_manipulation",
    "harmful_content":      "harmful_content",
}

_ECS_CATEGORY = {
    "jailbreak":            ["intrusion_detection"],
    "instruction_override": ["intrusion_detection"],
    "data_exfiltration":    ["intrusion_detection", "network"],
    "prompt_injection":     ["intrusion_detection", "web"],
    "role_play":            ["intrusion_detection"],
    "social_engineering":   ["intrusion_detection"],
    "token_manipulation":   ["malware"],
    "obfuscation":          ["malware"],
    "context_manipulation": ["intrusion_detection"],
    "harmful_content":      ["intrusion_detection"],
}


def _severity(risk_score: float) -> str:
    for t, s in _SEVERITY_MAP:
        if risk_score >= t:
            return s
    return "low"


class ElasticStore:
    def __init__(self):
        self._docs: deque = deque(maxlen=MAX_DOCS)
        # Inverted index: term → set of doc _ids
        self._term_index: Dict[str, set] = defaultdict(set)
        self._field_index: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))

    # ── Indexing ───────────────────────────────────────────────────────────────

    def index_detection(self, prompt: str, detection: Dict, action: str = "DETECT") -> Dict:
        """Build an ECS document from a detection result and index it."""
        doc = self._build_doc(prompt, detection, action)
        self._index_doc(doc)
        return doc

    def index_raw(self, doc: Dict) -> Dict:
        """Index a pre-built ECS document."""
        if "_id" not in doc:
            doc["_id"] = str(uuid.uuid4())
        self._index_doc(doc)
        return doc

    # ── Search ─────────────────────────────────────────────────────────────────

    def search(
        self,
        q: Optional[str] = None,
        filters: Optional[Dict] = None,
        size: int = 50,
        sort_desc: bool = True,
        min_risk: Optional[float] = None,
        since_hours: Optional[float] = None,
    ) -> List[Dict]:
        """
        Full-text + field search.

        q       — plain text or KQL-like: "jailbreak", "attack_category:jailbreak"
        filters — dict of exact field→value matches
        """
        docs = list(self._docs)

        # Time filter
        if since_hours is not None:
            cutoff = time.time() - since_hours * 3600
            docs = [d for d in docs if d.get("_ts", 0) >= cutoff]

        # Risk filter
        if min_risk is not None:
            docs = [d for d in docs if d.get("risk_score", 0) >= min_risk]

        # Field filters
        if filters:
            for field, value in filters.items():
                if value is not None and value != "":
                    docs = [d for d in docs if self._field_match(d, field, value)]

        # Text query
        if q and q.strip():
            docs = [d for d in docs if self._matches_query(d, q.strip())]

        if sort_desc:
            docs = sorted(docs, key=lambda d: d.get("_ts", 0), reverse=True)

        return docs[:size]

    def get_timeline(
        self,
        hours: float = 24,
        bucket_minutes: int = 30,
        filters: Optional[Dict] = None,
    ) -> List[Dict]:
        """Return time-bucketed event counts."""
        now    = time.time()
        cutoff = now - hours * 3600
        bsec   = bucket_minutes * 60
        docs   = self.search(since_hours=hours, filters=filters, size=MAX_DOCS)

        buckets: Dict[int, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        all_bks: set = set()

        for doc in docs:
            ts = doc.get("_ts", 0)
            bk = int(ts // bsec) * bsec
            all_bks.add(bk)
            buckets[bk]["count"] += 1
            sev = doc.get("event_severity", "low")
            buckets[bk][sev] += 1
            if doc.get("risk_score", 0) > 75:
                buckets[bk]["high_risk"] += 1

        result = []
        cursor = int(cutoff // bsec) * bsec
        while cursor <= now:
            bk_data = buckets.get(cursor, {})
            result.append({
                "timestamp":  cursor,
                "label":      datetime.fromtimestamp(cursor, tz=timezone.utc).strftime("%H:%M"),
                "date_label": datetime.fromtimestamp(cursor, tz=timezone.utc).strftime("%m/%d %H:%M"),
                "count":      bk_data.get("count", 0),
                "critical":   bk_data.get("critical", 0),
                "high":       bk_data.get("high", 0),
                "medium":     bk_data.get("medium", 0),
                "low":        bk_data.get("low", 0),
                "high_risk":  bk_data.get("high_risk", 0),
            })
            cursor += bsec
        return result

    def aggregate(self, field: str, size: int = 10, since_hours: float = 24) -> List[Dict]:
        """Top-N value counts for a field (like Elasticsearch terms aggregation)."""
        docs = self.search(since_hours=since_hours, size=MAX_DOCS)
        counts: Dict[str, int] = defaultdict(int)
        for doc in docs:
            val = doc.get(field)
            if isinstance(val, list):
                for v in val:
                    if v:
                        counts[str(v)] += 1
            elif val is not None and str(val) not in ("", "none", "[]"):
                counts[str(val)] += 1
        return [
            {"key": k, "doc_count": v}
            for k, v in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:size]
        ]

    def get_stats(self, since_hours: float = 24) -> Dict:
        docs  = self.search(since_hours=since_hours, size=MAX_DOCS)
        all_docs = list(self._docs)
        scores = [d.get("risk_score", 0) for d in docs]
        return {
            "total_indexed":   len(all_docs),
            "recent_count":    len(docs),
            "high_risk_count": sum(1 for d in docs if d.get("risk_score", 0) > 75),
            "critical_count":  sum(1 for d in docs if d.get("risk_score", 0) > 90),
            "avg_risk_score":  round(sum(scores) / len(scores), 1) if scores else 0,
            "peak_risk":       round(max(scores), 1) if scores else 0,
            "with_obfuscation": sum(1 for d in docs if d.get("obfuscation_type")),
            "event_type_dist": self._count_field(docs, "event_type"),
            "severity_dist":   self._count_field(docs, "event_severity"),
            "attack_cat_dist": self._count_field(docs, "attack_category"),
            "obf_type_dist":   self._count_field(docs, "obfuscation_type"),
            "top_tokens":      self._top_tokens(docs, 10),
        }

    def get_all_unique_values(self, field: str, since_hours: float = 24) -> List[str]:
        """Return sorted unique values for a field (for filter dropdowns)."""
        aggs = self.aggregate(field, size=50, since_hours=since_hours)
        return [a["key"] for a in aggs]

    # ── Internal ───────────────────────────────────────────────────────────────

    def _build_doc(self, prompt: str, detection: Dict, action: str) -> Dict:
        risk_score   = detection.get("risk_score", 0)
        attack_types = detection.get("attack_types", [])
        obf_techs    = detection.get("obfuscation_techniques", [])
        primary_cat  = attack_types[0] if attack_types else ""
        primary_obf  = obf_techs[0] if obf_techs else ""
        ev_type      = _EVENT_TYPE_MAP.get(primary_cat, "benign" if not attack_types else "prompt_injection")
        severity     = _severity(risk_score)
        ts_iso       = datetime.now(tz=timezone.utc).isoformat()
        categories   = []
        for a in attack_types:
            categories.extend(_ECS_CATEGORY.get(a, []))
        categories = list(set(categories)) or (["intrusion_detection"] if attack_types else ["audit"])

        return {
            "_id":              str(uuid.uuid4()),
            "_ts":              time.time(),
            "@timestamp":       ts_iso,
            "event_type":       ev_type,
            "event_kind":       "alert" if attack_types else "event",
            "event_category":   categories,
            "event_severity":   severity,
            "event_outcome":    "failure" if attack_types else "success",
            "event_action":     action.lower(),
            "risk_score":       risk_score,
            "attack_category":  primary_cat,
            "attack_categories": attack_types,
            "obfuscation_type": primary_obf,
            "obfuscation_types": obf_techs,
            "host_name":        "aurorasoc-01",
            "host_ip":          "172.31.90.130",
            "rule_score":       detection.get("rule_based_score", 0),
            "ml_score":         detection.get("ml_score", 0),
            "semantic_score":   detection.get("semantic_score", 0),
            "suspicious_tokens": detection.get("suspicious_tokens", []),
            "explanation":      detection.get("explanation", "")[:500],
            "prompt":           prompt[:500],
            "prompt_length":    len(prompt),
            "is_malicious":     detection.get("is_malicious", False),
            "platform":         "AuroraSOC",
            "version":          "2.0",
        }

    def _index_doc(self, doc: Dict):
        self._docs.appendleft(doc)
        doc_id = doc["_id"]
        # Index all string fields for full-text search
        for key, val in doc.items():
            if isinstance(val, str) and val:
                for term in re.findall(r'\w+', val.lower()):
                    if len(term) > 2:
                        self._term_index[term].add(doc_id)
                # Also index field:value
                self._field_index[key][val.lower()].add(doc_id)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str) and item:
                        self._field_index[key][item.lower()].add(doc_id)
                        for term in re.findall(r'\w+', item.lower()):
                            if len(term) > 2:
                                self._term_index[term].add(doc_id)

    def _matches_query(self, doc: Dict, q: str) -> bool:
        """KQL-like query matching: plain text or field:value."""
        q = q.strip().lower()

        # Field:value syntax: attack_category:jailbreak
        m = re.match(r'^(\w[\w.]*?)\s*:\s*(.+)$', q)
        if m:
            field, value = m.group(1), m.group(2).strip()
            # Range: risk_score:>75
            range_m = re.match(r'^([<>]=?)\s*(\d+(?:\.\d+)?)$', value)
            if range_m:
                op, num = range_m.group(1), float(range_m.group(2))
                doc_val = doc.get(field, doc.get(field.replace(".", "_"), 0))
                try:
                    doc_val = float(doc_val)
                    if op == ">":   return doc_val > num
                    if op == ">=":  return doc_val >= num
                    if op == "<":   return doc_val < num
                    if op == "<=":  return doc_val <= num
                except (TypeError, ValueError):
                    return False
            # Exact / partial field match
            return self._field_match(doc, field, value)

        # AND / OR logic
        if " and " in q:
            return all(self._matches_query(doc, part) for part in q.split(" and "))
        if " or " in q:
            return any(self._matches_query(doc, part) for part in q.split(" or "))

        # Plain text — search all string values
        for val in doc.values():
            if isinstance(val, str) and q in val.lower():
                return True
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, str) and q in item.lower():
                        return True
        return False

    def _field_match(self, doc: Dict, field: str, value: str) -> bool:
        doc_val = doc.get(field, doc.get(field.replace(".", "_"), ""))
        value   = str(value).lower()
        if isinstance(doc_val, list):
            return any(value in str(v).lower() for v in doc_val)
        return value in str(doc_val).lower()

    def _count_field(self, docs: List[Dict], field: str) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for doc in docs:
            val = doc.get(field)
            if isinstance(val, list):
                for v in val:
                    if v:
                        counts[str(v)] += 1
            elif val:
                counts[str(val)] += 1
        return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))

    def _top_tokens(self, docs: List[Dict], n: int) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for doc in docs:
            for tok in doc.get("suspicious_tokens", []):
                if tok:
                    counts[tok] += 1
        return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n])


# Singleton
elastic_store = ElasticStore()
