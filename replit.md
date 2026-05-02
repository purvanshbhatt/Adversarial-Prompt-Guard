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

## APIDS — Adversarial Prompt Injection Detection System

Located at: `artifacts/apids/`

**Workflow:** `APIDS Dashboard`
- FastAPI backend: `http://localhost:6000/api`
- Streamlit dashboard: `http://localhost:8099`

### Module Structure

```
artifacts/apids/
├── app/
│   ├── main.py                     # All FastAPI routes
│   ├── models.py                   # Pydantic schemas
│   ├── preprocessing.py            # Normalize, tokenize, hidden-instruction scan
│   ├── obfuscation.py              # 7-technique obfuscation detector & generator
│   ├── multiturn.py                # Multi-turn priming/escalation/context-poisoning detector
│   ├── benchmark.py                # 5-layer benchmark runner (keyword→rule→ML→semantic→ensemble)
│   ├── report.py                   # Auto-generates Markdown research report
│   ├── detection/
│   │   ├── rule_based.py           # Regex + heuristics (30+ patterns, 3 categories)
│   │   ├── ml_classifier.py        # TF-IDF + Logistic Regression
│   │   └── semantic_similarity.py  # all-MiniLM-L6-v2 (lazy-loaded in background thread)
│   ├── training/
│   │   ├── dataset.py              # Synthetic dataset generator (1000 samples, 4 categories)
│   │   └── trainer.py              # Train + evaluate, saves classifier.pkl
│   ├── logging_module/
│   │   └── logger.py               # JSON prompt log, aggregated stats
│   └── metrics/
│       ├── isr.py                  # Injection Success Rate metric
│       └── pivs.py                 # Prompt Injection Vulnerability Score metric
├── dashboard/
│   └── streamlit_app.py            # 9-page Streamlit UI
├── data/                           # Generated datasets, logs, eval/benchmark/ISR/PIVS JSONs
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
| GET | `/api/report` | Generate full Markdown research report |

### Detection Pipeline

```
risk_score (ML trained)    = rule × 0.32 + ml × 0.38 + semantic × 0.20 + obfuscation × 0.10
risk_score (ML untrained)  = rule × 0.60 + semantic × 0.30 + obfuscation × 0.10

Threshold: ≥ 35 (trained) / ≥ 28 (untrained) → malicious
```

### Novel Research Metrics

- **ISR (Injection Success Rate)** = missed_attacks / total_attacks; measures bypass rate with/without protection
- **PIVS (Prompt Injection Vulnerability Score)** = 100 × (0.45·DC + 0.20·FPB + 0.25·OR + 0.10·BDP); composite vulnerability index

### Streamlit Dashboard Pages

1. 🔍 Analyze Prompt — real-time analysis with gauge + layer breakdown + token highlighting
2. 📊 Dashboard — attack pie chart, risk distribution, activity table
3. 🧪 Test Cases — run attack simulations, bypass tests, benign FP checks
4. 🔓 Obfuscation Lab — generate/test 6 evasion variants (leet, homoglyph, zero-width, etc.)
5. 💬 Multi-Turn Analysis — detect priming, escalation, context poisoning across conversation turns
6. 🤖 Train Model — configure + train ML classifier, view comparison chart
7. 📋 Logs — paginated log viewer with malicious filter
8. 📈 Benchmark & Metrics — 5-layer radar chart, ISR table, PIVS gauge + sub-scores
9. 📄 Research Report — generate arXiv-ready Markdown report with all live metrics + download

### Python Dependencies

fastapi, uvicorn[standard], streamlit, scikit-learn, sentence-transformers, pandas, numpy, plotly, requests, python-multipart
