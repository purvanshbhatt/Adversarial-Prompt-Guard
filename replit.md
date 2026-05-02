# Workspace

## Overview

pnpm workspace monorepo (TypeScript) + Python-based Adversarial Prompt Injection Detection System.

## Stack

- **Monorepo tool**: pnpm workspaces
- **Node.js version**: 24
- **Package manager**: pnpm
- **TypeScript version**: 5.9
- **API framework**: Express 5 (Node) / FastAPI (Python)
- **Database**: PostgreSQL + Drizzle ORM
- **Validation**: Zod (`zod/v4`), `drizzle-zod`
- **API codegen**: Orval (from OpenAPI spec)
- **Build**: esbuild (CJS bundle)

## Key Commands

- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)

---

## AuroraSOC — Multi-Agent AI Security Platform

Located at: `artifacts/apids/`  (upgraded from APIDS v1 to AuroraSOC v2)

**Workflow:** `APIDS Dashboard`
- FastAPI backend: `http://localhost:6000/api` (legacy) + `/soc` (AuroraSOC)
- Streamlit dashboard: `http://localhost:8099`

### Module Structure

```
artifacts/apids/
├── app/
│   ├── main.py                     # All FastAPI routes (legacy /api + new /soc)
│   ├── models.py                   # Pydantic schemas
│   ├── agents/                     # AuroraSOC Multi-Agent System
│   │   ├── __init__.py
│   │   ├── shared_memory.py        # EventStore (JSON-persisted), SecurityEvent dataclass
│   │   ├── base.py                 # AgentBase ABC
│   │   ├── prompt_security_agent.py    # Wraps existing detection pipeline
│   │   ├── threat_correlation_agent.py # Pattern/velocity/escalation correlation
│   │   ├── risk_scoring_agent.py       # Enterprise score = base × behavior × correlation
│   │   ├── adversary_simulation_agent.py # Red-team generator feeding detection
│   │   ├── forensics_agent.py          # EventStore writes, timeline, investigation report
│   │   └── orchestrator.py             # SOCOrchestrator — coordinates all 5 agents
│   ├── preprocessing.py            # Normalize, tokenize, hidden-instruction scan
│   ├── obfuscation.py              # 7-technique obfuscation detector & generator
│   ├── multiturn.py                # Multi-turn priming/escalation/context-poisoning detector
│   ├── benchmark.py                # 5-layer benchmark runner
│   ├── report.py                   # Auto-generates Markdown research report
│   ├── detection/
│   │   ├── rule_based.py           # Regex + heuristics (30+ patterns, 3 categories)
│   │   ├── ml_classifier.py        # TF-IDF + Logistic Regression
│   │   └── semantic_similarity.py  # all-MiniLM-L6-v2 (lazy-loaded in background thread)
│   ├── training/
│   │   ├── dataset.py              # Synthetic dataset generator
│   │   └── trainer.py              # Train + evaluate, saves classifier.pkl
│   ├── logging_module/
│   │   └── logger.py               # JSON prompt log, aggregated stats
│   ├── metrics/
│   │   ├── isr.py                  # Injection Success Rate metric
│   │   └── pivs.py                 # Prompt Injection Vulnerability Score metric
│   └── adversarial/
│       ├── strategies.py           # 32 attack templates across 4 strategies
│       ├── mutation.py             # 9 mutation operators
│       ├── generator.py            # Template + LLM attack generation
│       └── rl_loop.py              # Adaptive RL-style attack loop
├── dashboard/
│   └── streamlit_app.py            # 16-page Streamlit UI (5 SOC + 11 original)
├── data/                           # Logs, eval/benchmark/ISR/PIVS, soc_events.json
└── saved_models/                   # classifier.pkl (after training)
```

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | System health (ML trained?, semantic loaded?) |
| POST | `/api/analyze_prompt` | Full multi-layer analysis → risk score 0–100 |
| POST | `/api/train_model` | Generate dataset + train ML classifier |
| GET | `/api/logs` | Paginated analysis history |
| DELETE | `/api/logs` | Clear logs |
| GET | `/api/stats` | Aggregated stats |
| GET | `/api/evaluation` | ML vs rule-based metrics (post-training) |
| GET | `/api/test_cases` | Pre-built attack/bypass/benign test cases |
| GET | `/api/dataset_info` | Check dataset file availability |
| POST | `/api/analyze_obfuscation` | Detect obfuscation techniques only |
| POST | `/api/generate_obfuscated` | Generate 6 obfuscated variants + test each |
| POST | `/api/analyze_conversation` | Multi-turn context carry-over detection |
| POST | `/api/metrics/isr` | Compute Injection Success Rate |
| POST | `/api/metrics/pivs` | Compute PIVS from ISR data |
| POST | `/api/benchmark` | 5-layer benchmark → ISR + PIVS |
| GET | `/api/report` | Generate full Markdown research report (with generalization gap) |
| POST | `/api/upload_dataset` | Upload external CSV dataset for real-world eval |
| POST | `/api/upload_dataset/sample` | Load built-in curated 60-prompt jailbreak corpus |
| GET | `/api/upload_dataset/info` | Metadata for currently loaded real-world dataset |
| DELETE | `/api/upload_dataset` | Remove uploaded dataset |
| POST | `/api/realworld_benchmark` | Run APIDS on real-world + synthetic, return comparison + gap |
| GET | `/api/export_comparison` | Download CSV: comparison table + per-prompt results |

### Detection Pipeline

```
risk_score (ML trained)    = rule × 0.32 + ml × 0.38 + semantic × 0.20 + obfuscation × 0.10
risk_score (ML untrained)  = rule × 0.60 + semantic × 0.30 + obfuscation × 0.10

Threshold: ≥ 35 (trained) / ≥ 28 (untrained) → malicious
```

### Novel Research Metrics

- **ISR (Injection Success Rate)** = missed_attacks / total_attacks; measures bypass rate with/without protection
- **PIVS (Prompt Injection Vulnerability Score)** = 100 × (0.45·DC + 0.20·FPB + 0.25·OR + 0.10·BDP); composite vulnerability index

### AuroraSOC Agent Pipeline

```
Prompt → Prompt Security Agent → [Risk Scoring Agent + Threat Correlation Agent] → Forensics Agent → Verdict
                                                                       ↑
                                                          Adversary Simulation Agent (independent /soc/simulate)
```

**5 Agents:**
1. **Prompt Security** — multi-layer detection (rule + ML + semantic + obfuscation)
2. **Threat Correlation** — detects velocity spikes, repeated patterns, multi-vector attacks, score escalation
3. **Risk Scoring** — enterprise score = `base × behavior_modifier + correlation_bonus` (modifier 1.0–1.5×)
4. **Adversary Simulation** — generates attacks via 4 strategies × 32 templates, feeds to detection
5. **Forensics** — stores SecurityEvents in `data/soc_events.json`, builds timeline, generates investigation report

**Shared Memory:** `EventStore` singleton (in-process, persisted to `data/soc_events.json`, max 1000 events)

### AuroraSOC API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/soc/analyze` | Full 4-agent pipeline → enterprise verdict + correlation insights |
| GET | `/soc/correlate` | Global threat correlation state: patterns, velocity, threat level |
| GET | `/soc/report` | Forensic investigation report (Markdown, optionally scoped by session) |
| GET | `/soc/timeline` | Chronological event list from forensics store (limit 1–200) |
| POST | `/soc/simulate` | Run Adversary Simulation Agent, store all events in forensics |
| GET | `/soc/agents/status` | Live status of all 5 agents |
| DELETE | `/soc/events` | Clear the forensics event store |

### Streamlit Dashboard Pages (16 total)

**SOC Command:**
1. 🔮 SOC Command Center — enterprise metrics, agent status row, multi-agent analyze form, recent events
2. 🕐 Attack Timeline — filterable event table, severity breakdown chart, JSON export
3. 🤝 Correlation Engine — threat level banner, velocity, attack pattern heatmap, top sessions
4. 🔄 Simulation Mode — run full attack lifecycle, see bypass list, stored in forensics
5. 🧠 Agent Network — 5 agent cards + pipeline architecture diagram

**Detection Tools (original 11 pages):**
6. 🔍 Analyze Prompt — real-time analysis with gauge + layer breakdown + token highlighting
7. 📊 Dashboard — attack pie chart, risk distribution, activity table
8. 🧪 Test Cases — run attack simulations, bypass tests, benign FP checks
9. 🔓 Obfuscation Lab — generate/test 6 evasion variants (leet, homoglyph, zero-width, etc.)
10. 💬 Multi-Turn Analysis — detect priming, escalation, context poisoning across conversation turns
11. 🌐 Real-World Eval — upload CSV / use sample corpus; side-by-side comparison; generalization gap chart
12. ⚔️ Attack Generator — generate attacks, run adaptive RL loop, Hall of Fame
13. 🤖 Train Model — configure + train ML classifier, view comparison chart
14. 📋 Logs — paginated log viewer with malicious filter
15. 📈 Benchmark & Metrics — 5-layer radar chart, ISR table, PIVS gauge + sub-scores
16. 📄 Research Report — arXiv-ready Markdown report with generalization gap section + download

### New: Real-World Evaluation Module

- `app/evaluation/realworld.py` — core evaluation logic
  - `SAMPLE_PROMPTS` — 60 curated prompts from public jailbreak taxonomies (DAN/STAN/DUDE, instruction override, data exfiltration, indirect injection, benign)
  - `run_realworld_evaluation()` — full ensemble scoring → Accuracy/Precision/Recall/F1/ISR/PIVS
  - `compute_generalization_gap()` — ΔF1, per-metric delta, diagnosis, contributing factors
  - `export_comparison_csv()` — summary table + research metrics + per-prompt rows
- `data/uploaded_dataset.csv` — user-uploaded or sample dataset (if loaded)
- `data/comparison_results.json` — latest synthetic vs real-world comparison

### AI-Powered Adversarial Attack Generator

Located at `app/adversarial/` — 4 files.

**`strategies.py`** — Template library (32 hand-crafted templates)
- 4 strategies × 8 templates each, difficulty 1–5
- `roleplay_jailbreak`: DAN/STAN/DUDE personas, nested simulations, grandmother exploit
- `instruction_override`: direct, fake system resets, authority claims, recursive nesting
- `data_exfiltration`: direct requests, translation/summarize pretexts, reflective prompts
- `indirect_injection`: document/email/markdown/metadata/database injection, instruction smuggling
- Variable pools: 12 personas, 7 fictional frames, 6 authority claims, 5 extract targets, 6 override directives

**`mutation.py`** — 9 mutation operators (applied in escalating order)
1. `synonym_swap` — replace trigger words (ignore→disregard, reveal→expose…)
2. `prefix_benign` — friendly preamble to reduce suspicion
3. `suffix_justify` — research/ethics justification suffix
4. `framing_escalate` — direct→hypothetical→fictional→research→debug framing
5. `structural_paraphrase` — question form, conditional form restructure
6. `fragment` — split attack into softer-sounding sentences
7. `authority_inject` — fake admin/operator/red-team prefix
8. `obfuscate_light` — zero-width spaces inside trigger words
9. `obfuscate_case` — mixed-case obfuscation on trigger words

**`generator.py`** — Dual-mode attack generator
- Template mode: always available, offline; uses strategy templates + mutation diversity
- LLM mode: uses OpenAI API if `OPENAI_API_KEY` env var is set; auto-falls back to template mode on error
- `generate_attacks(strategy, n, goal, difficulty_min, difficulty_max, use_llm)`
- `mutate_attack(prompt, mutations)` — apply one or more operators

**`rl_loop.py`** — Reinforcement-style adaptive loop
- `run_adaptive_loop()`: iterates max N times; if detected → mutate; if bypassed → escalate difficulty
- Convergence: stops early if `convergence_patience` consecutive bypasses (default 3)
- Saves: `data/adversarial_results.json` (latest slim summary), `data/adversarial_history.json` (last 100 runs)
- Outputs: `evolution[]`, `mutation_effectiveness{}`, `robustness_score`, `hardest_to_detect`, `easiest_bypasses`

**New API Endpoints**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/adversarial/strategies` | All strategies, template list, mutation operators, LLM status |
| POST | `/api/adversarial/generate` | Generate N attack prompts for a strategy |
| POST | `/api/adversarial/mutate` | Apply mutation operators to a prompt, return variants |
| POST | `/api/adversarial/run_loop` | Run full adaptive RL loop, return evolution + stats |
| GET | `/api/adversarial/results` | Latest loop run summary |
| GET | `/api/adversarial/history` | Last 100 run summaries |

**Empirical results (template mode, no ML training)**
- Roleplay jailbreaks: 100% detected (robustness 100/100) — rule + semantic layers effective
- High-difficulty data exfiltration (diff 3–5): high bypass rate — indirect encoding tricks evade pattern matching
- This gap is intentional and researchable: shows where additional training data is needed

### Python Dependencies

fastapi, uvicorn[standard], streamlit, scikit-learn, sentence-transformers, pandas, numpy, plotly, requests, python-multipart
