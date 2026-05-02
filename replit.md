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
- `pnpm --filter @workspace/api-server run dev` — run API server locally

## APIDS — Adversarial Prompt Injection Detection System

Located at: `artifacts/apids/`

### Architecture

```
artifacts/apids/
├── app/                        # FastAPI backend (port 6000)
│   ├── main.py                 # API routes: /analyze_prompt, /train_model, /logs, /evaluation
│   ├── models.py               # Pydantic request/response models
│   ├── preprocessing.py        # Text normalization, tokenization, hidden-instruction detection
│   ├── detection/
│   │   ├── rule_based.py       # Regex + heuristic detector (3 attack categories)
│   │   ├── ml_classifier.py    # TF-IDF + Logistic Regression classifier
│   │   └── semantic_similarity.py  # Sentence-Transformer similarity (all-MiniLM-L6-v2)
│   ├── training/
│   │   ├── dataset.py          # Synthetic dataset generator (instruction_override, jailbreak, data_exfiltration, benign)
│   │   └── trainer.py          # Model training, evaluation, ML vs rule-based comparison
│   └── logging_module/
│       └── logger.py           # JSON-based prompt log with stats
├── dashboard/
│   └── streamlit_app.py        # Streamlit UI (port 8099)
├── data/                       # Generated datasets + logs
└── saved_models/               # Trained classifier (pickle)
```

### Workflows

- `APIDS Dashboard` — runs `bash artifacts/apids/run.sh`
  - FastAPI backend: `http://localhost:6000/api`
  - Streamlit dashboard: `http://localhost:8099`

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/analyze_prompt` | Analyze a prompt for injection attacks |
| POST | `/api/train_model` | Train ML classifier on synthetic dataset |
| GET | `/api/logs` | Retrieve analysis log with stats |
| DELETE | `/api/logs` | Clear logs |
| GET | `/api/stats` | Aggregated statistics |
| GET | `/api/evaluation` | ML vs rule-based comparison metrics |
| GET | `/api/test_cases` | Pre-built attack/benign test cases |
| GET | `/api/dataset_info` | Check if dataset files exist |
| GET | `/api/health` | System health check |

### Detection Pipeline

Risk score = `rule_based × 0.35 + ml × 0.40 + semantic × 0.25` (when ML trained)
            = `rule_based × 0.55 + semantic × 0.45` (before training)

Threshold: risk_score ≥ 35 → malicious

### Python Dependencies

fastapi, uvicorn, streamlit, scikit-learn, sentence-transformers, pandas, numpy, plotly, requests, python-multipart
