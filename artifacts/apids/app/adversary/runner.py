"""
Adaptive adversary runner — orchestrates multi-iteration attack loops.

Flow per iteration:
  1. Generate attack prompt (AttackGenerator)
  2. Send to /api/analyze_prompt (internal call)
  3. If DETECTED (risk_score > threshold):
       - Mutate prompt using next strategy in rotation
       - Re-detect mutated version (mutation round)
       - Track mutation attempts and final outcome
  4. If BYPASSED (risk_score <= threshold):
       - Log as successful bypass
       - Record prompt as hardest-to-detect
  5. Repeat for N iterations

Metrics tracked per session:
  - total_attacks, detected, bypassed, mutated
  - bypass_rate, detection_rate
  - avg_mutations_per_bypass
  - per_category breakdown
  - per_strategy evasion success rates
  - hardest_prompts (lowest risk score that IS malicious)
  - risk_over_time (detection improvement tracking)
"""

import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests

from .generator import AttackGenerator, AttackPrompt, CATEGORY_WEIGHTS
from .mutator import PromptMutator, MutationStrategy, ALL_STRATEGIES

MAX_MUTATION_ROUNDS = 6
DETECTION_THRESHOLD = 40.0     # Risk score above which we consider "detected"
BYPASS_THRESHOLD    = 40.0     # Risk score at or below which it's a bypass
MAX_SESSIONS        = 10


# ── Data models ────────────────────────────────────────────────────────────────

@dataclass
class IterationResult:
    iteration:       int
    category:        str
    original_prompt: str
    final_prompt:    str
    detected:        bool
    bypassed:        bool
    risk_score:      float
    ml_score:        float
    attack_types:    List[str]
    mutation_rounds: int
    mutation_chain:  List[str]
    mutation_strategies: List[str]
    timestamp:       float = field(default_factory=time.time)
    duration_ms:     float = 0.0

    def to_dict(self) -> Dict:
        return {
            "iteration":         self.iteration,
            "category":          self.category,
            "original_prompt":   self.original_prompt[:200],
            "final_prompt":      self.final_prompt[:200],
            "detected":          self.detected,
            "bypassed":          self.bypassed,
            "risk_score":        self.risk_score,
            "ml_score":          self.ml_score,
            "attack_types":      self.attack_types,
            "mutation_rounds":   self.mutation_rounds,
            "mutation_chain":    self.mutation_chain,
            "mutation_strategies": self.mutation_strategies,
            "timestamp":         self.timestamp,
            "duration_ms":       self.duration_ms,
        }


@dataclass
class AdversarySession:
    id:              str
    config:          Dict
    status:          str          # pending | running | complete | stopped | error
    iterations:      List[IterationResult] = field(default_factory=list)
    started_at:      float = field(default_factory=time.time)
    completed_at:    Optional[float] = None
    error:           Optional[str]  = None
    current_iter:    int  = 0
    total_iters:     int  = 0
    _lock:           threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add_result(self, r: IterationResult):
        with self._lock:
            self.iterations.append(r)
            self.current_iter = len(self.iterations)

    def get_metrics(self) -> Dict:
        with self._lock:
            results = list(self.iterations)

        if not results:
            return self._empty_metrics()

        total       = len(results)
        detected    = sum(1 for r in results if r.detected and not r.bypassed)
        bypassed    = sum(1 for r in results if r.bypassed)
        mutated     = sum(1 for r in results if r.mutation_rounds > 0)
        mut_rounds  = [r.mutation_rounds for r in results if r.mutation_rounds > 0]
        risk_scores = [r.risk_score for r in results]

        # Per-category breakdown
        cat_stats: Dict[str, Dict] = defaultdict(lambda: {"total":0,"detected":0,"bypassed":0})
        for r in results:
            cat_stats[r.category]["total"]    += 1
            cat_stats[r.category]["detected"] += 1 if (r.detected and not r.bypassed) else 0
            cat_stats[r.category]["bypassed"] += 1 if r.bypassed else 0

        # Hardest-to-detect (bypassed prompts with lowest final risk)
        bypassed_results = sorted(
            [r for r in results if r.bypassed],
            key=lambda r: r.risk_score
        )
        hardest = [r.to_dict() for r in bypassed_results[:10]]

        # Risk score over time (rolling avg)
        risk_timeline = []
        window = max(1, total // 20)
        for i in range(0, total, window):
            batch = risk_scores[i:i+window]
            risk_timeline.append({
                "iteration": i + window,
                "avg_risk":  round(sum(batch) / len(batch), 1),
                "min_risk":  round(min(batch), 1),
                "max_risk":  round(max(batch), 1),
            })

        # Mutation strategy effectiveness
        strat_stats: Dict[str, Dict] = defaultdict(lambda: {"attempts":0,"successes":0})
        for r in results:
            for si, strat in enumerate(r.mutation_strategies):
                strat_stats[strat]["attempts"] += 1
                # If the last strategy led to bypass, count it as success
                if r.bypassed and si == len(r.mutation_strategies) - 1:
                    strat_stats[strat]["successes"] += 1
        strat_list = [
            {
                "strategy":     k,
                "attempts":     v["attempts"],
                "successes":    v["successes"],
                "success_rate": round(v["successes"] / max(v["attempts"], 1) * 100, 1),
            }
            for k, v in sorted(strat_stats.items(), key=lambda x: x[1]["successes"], reverse=True)
        ]

        # Evolution: track how bypass rate changes over time in chunks
        chunk = max(1, total // 10)
        evolution = []
        for i in range(0, total, chunk):
            batch = results[i:i+chunk]
            b_cnt = sum(1 for r in batch if r.bypassed)
            evolution.append({
                "window_start":  i + 1,
                "window_end":    i + len(batch),
                "bypass_count":  b_cnt,
                "bypass_rate":   round(b_cnt / len(batch) * 100, 1),
                "avg_risk":      round(sum(r.risk_score for r in batch) / len(batch), 1),
            })

        return {
            "total":              total,
            "detected":           detected,
            "bypassed":           bypassed,
            "mutated":            mutated,
            "bypass_rate":        round(bypassed / total * 100, 1) if total else 0,
            "detection_rate":     round(detected / total * 100, 1) if total else 0,
            "avg_risk_score":     round(sum(risk_scores) / len(risk_scores), 1),
            "min_risk_score":     round(min(risk_scores), 1),
            "max_risk_score":     round(max(risk_scores), 1),
            "avg_mutations_per_bypass": round(sum(mut_rounds) / len(mut_rounds), 1) if mut_rounds else 0,
            "max_mutation_rounds":MAX_MUTATION_ROUNDS,
            "per_category":       dict(cat_stats),
            "hardest_prompts":    hardest,
            "risk_timeline":      risk_timeline,
            "mutation_strategies": strat_list,
            "evolution":          evolution,
            "elapsed_sec":        round(time.time() - self.started_at, 1),
        }

    def to_status_dict(self) -> Dict:
        return {
            "id":            self.id,
            "status":        self.status,
            "current_iter":  self.current_iter,
            "total_iters":   self.total_iters,
            "progress_pct":  round(self.current_iter / max(self.total_iters, 1) * 100, 1),
            "started_at":    self.started_at,
            "completed_at":  self.completed_at,
            "error":         self.error,
            "config":        self.config,
        }

    def _empty_metrics(self) -> Dict:
        return {
            "total": 0, "detected": 0, "bypassed": 0, "mutated": 0,
            "bypass_rate": 0, "detection_rate": 0, "avg_risk_score": 0,
            "hardest_prompts": [], "risk_timeline": [], "evolution": [],
            "mutation_strategies": [], "per_category": {},
        }


# ── Runner ─────────────────────────────────────────────────────────────────────

class AdversaryRunner:
    def __init__(self, api_base: str = "http://localhost:6000"):
        self._api_base   = api_base
        self._sessions:  Dict[str, AdversarySession] = {}
        self._active_id: Optional[str] = None
        self._lock = threading.Lock()

    def start_session(self, config: Dict) -> str:
        """
        Start a new adversary session in a background thread.
        Returns session_id.
        """
        sid = str(uuid.uuid4())[:8]
        total_iters = min(max(int(config.get("iterations", 20)), 5), 100)
        categories  = config.get("categories", list(CATEGORY_WEIGHTS.keys()))
        complexity  = config.get("complexity", "medium")
        mutation_delay = float(config.get("delay_ms", 200)) / 1000

        session = AdversarySession(
            id          = sid,
            config      = {**config, "iterations": total_iters},
            status      = "pending",
            total_iters = total_iters,
        )
        with self._lock:
            # Stop active session if running
            if self._active_id and self._active_id in self._sessions:
                old = self._sessions[self._active_id]
                if old.status == "running":
                    old.status = "stopped"
            self._sessions[sid] = session
            self._active_id = sid
            # Evict oldest if over cap
            if len(self._sessions) > MAX_SESSIONS:
                oldest = next(iter(self._sessions))
                del self._sessions[oldest]

        t = threading.Thread(
            target=self._run_loop,
            args=(session, categories, complexity, mutation_delay),
            daemon=True
        )
        t.start()
        return sid

    def stop_session(self, sid: str) -> bool:
        with self._lock:
            s = self._sessions.get(sid)
            if s and s.status == "running":
                s.status = "stopped"
                return True
        return False

    def get_session(self, sid: str) -> Optional[AdversarySession]:
        return self._sessions.get(sid)

    def get_active(self) -> Optional[AdversarySession]:
        with self._lock:
            if self._active_id:
                return self._sessions.get(self._active_id)
        return None

    def list_sessions(self) -> List[Dict]:
        with self._lock:
            sessions = list(self._sessions.values())
        return [s.to_status_dict() for s in reversed(sessions)]

    # ── Internal loop ──────────────────────────────────────────────────────────

    def _run_loop(
        self,
        session: AdversarySession,
        categories: List[str],
        complexity: str,
        delay: float,
    ):
        session.status = "running"
        gen    = AttackGenerator(seed=42)
        mutator = PromptMutator(seed=99)
        strat_cycle = list(ALL_STRATEGIES)

        try:
            for i in range(session.total_iters):
                if session.status in ("stopped", "error"):
                    break

                t_start = time.time()
                cat = categories[i % len(categories)]
                attack = gen.generate(category=cat, complexity=complexity)
                prompt = attack.text

                # Initial detection
                risk, ml_score, attack_types, detected = self._detect(prompt)

                mutation_chain    = [prompt[:100]]
                mutation_strategies = []
                mutation_rounds   = 0
                bypassed          = False
                used_strategies: List[MutationStrategy] = []

                # Mutate loop if detected
                if detected:
                    for mround in range(MAX_MUTATION_ROUNDS):
                        if session.status in ("stopped", "error"):
                            break

                        # Pick next strategy (rotate through all)
                        avail = [s for s in strat_cycle if s not in used_strategies]
                        if not avail:
                            avail = strat_cycle
                            used_strategies = []
                        strategy = avail[0]
                        used_strategies.append(strategy)

                        mutated_prompt = mutator.mutate(prompt, strategy)
                        mutation_chain.append(mutated_prompt[:100])
                        mutation_strategies.append(strategy.value)
                        mutation_rounds += 1

                        m_risk, m_ml, m_types, m_detected = self._detect(mutated_prompt)

                        if not m_detected:
                            # BYPASS achieved after mutation
                            mutator.record_success(strategy)
                            risk         = m_risk
                            ml_score     = m_ml
                            attack_types = m_types
                            prompt       = mutated_prompt
                            bypassed     = True
                            break
                        else:
                            # Still detected — update prompt and try another strategy
                            prompt = mutated_prompt
                            risk   = m_risk

                        if delay > 0:
                            time.sleep(delay)
                else:
                    # Not detected on first try — bypass
                    bypassed = True

                result = IterationResult(
                    iteration        = i + 1,
                    category         = cat,
                    original_prompt  = attack.text,
                    final_prompt     = prompt,
                    detected         = not bypassed,
                    bypassed         = bypassed,
                    risk_score       = risk,
                    ml_score         = ml_score,
                    attack_types     = attack_types,
                    mutation_rounds  = mutation_rounds,
                    mutation_chain   = mutation_chain,
                    mutation_strategies = mutation_strategies,
                    duration_ms      = round((time.time() - t_start) * 1000, 1),
                )
                session.add_result(result)

                if delay > 0:
                    time.sleep(delay)

        except Exception as e:
            session.status = "error"
            session.error  = str(e)
            return

        if session.status != "stopped":
            session.status = "complete"
        session.completed_at = time.time()

    def _detect(self, prompt: str) -> tuple:
        """Call local detect endpoint. Returns (risk_score, ml_score, attack_types, is_detected)."""
        try:
            resp = requests.post(
                f"{self._api_base}/api/analyze_prompt",
                json={"prompt": prompt},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                risk    = float(data.get("risk_score", 0))
                ml      = float(data.get("ml_score", 0))
                types   = data.get("attack_types", [])
                return risk, ml, types, risk > DETECTION_THRESHOLD
        except Exception:
            pass
        return 0.0, 0.0, [], False


# Singleton
adversary_runner = AdversaryRunner(api_base="http://localhost:6000")
