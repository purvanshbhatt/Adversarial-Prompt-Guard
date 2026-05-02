# LLM Shield — Installation Guide

Real-time prompt injection detection for ChatGPT, Claude, and Gemini.

---

## Prerequisites

- Google Chrome (or any Chromium-based browser)
- AuroraSOC backend running locally (`bash artifacts/apids/run.sh`)

---

## Load the Extension (30 seconds)

1. Open Chrome and go to `chrome://extensions`
2. Enable **Developer mode** (toggle, top-right corner)
3. Click **Load unpacked**
4. Select the `artifacts/llm-shield/` folder
5. The LLM Shield icon appears in your toolbar

That's it. No build step, no npm install.

---

## Configure

Click the shield icon → **Settings** (or go to the options page directly).

| Setting         | Default                   | Notes                                  |
|-----------------|---------------------------|----------------------------------------|
| API Endpoint    | `http://localhost:6000`   | Your AuroraSOC backend URL             |
| Risk Threshold  | `35`                      | 0–100. Lower = more sensitive          |
| Enable          | On                        | Toggle protection per-session          |

Click **Test connection** to verify the backend is reachable.

---

## How It Works

```
You type a prompt
       │
       ▼
[Content Script intercepts Enter / Send click]
       │
       ▼
[Background Service Worker → POST /api/analyze_prompt]
       │
       ├── Risk score < threshold  →  prompt submitted normally
       │
       └── Risk score ≥ threshold  →  Warning overlay appears
                                           │
                                           ├── "Edit my prompt"  →  focus returns to input
                                           └── "Proceed anyway"  →  prompt submitted as-is
```

---

## Warning Overlay

When a threat is detected you'll see:

- **Risk badge** — CRITICAL / HIGH / MEDIUM / LOW
- **Risk score bar** — 0–100
- **Attack type** — jailbreak, data exfiltration, instruction override, indirect injection
- **Explanation** — what was detected and why
- **Suspicious phrases** — the exact tokens that triggered detection
- Input field highlighted with a colored outline matching severity

---

## Privacy

- Prompts are **never stored locally** by the extension
- Each prompt is sent to your configured backend (default: `localhost` — stays on your machine)
- No telemetry, no third-party requests
- Extension permissions: `storage` only (saves your settings)

---

## Supported Sites

| Site                    | Input Type        | Status  |
|-------------------------|-------------------|---------|
| `chat.openai.com`       | Textarea + Lexical| ✅ Supported |
| `claude.ai`             | ProseMirror       | ✅ Supported |
| `gemini.google.com`     | Quill editor      | ✅ Supported |

---

## Troubleshooting

**Warning never appears even for obvious attacks**
- Click the shield icon and check protection is **Active**
- Open Settings → Test Connection to verify the API is running
- Lower the risk threshold (try 20)

**"Connection failed" in settings**
- Make sure AuroraSOC is running: `bash artifacts/apids/run.sh`
- Check the endpoint URL — no trailing slash

**Extension not intercepting on a site**
- Go to `chrome://extensions` → LLM Shield → Details
- Confirm the site is in the allowed host list
- Reload the tab after installing the extension

**Submit button still fires before analysis**
- This is a race condition on some SPA route changes — reload the tab
