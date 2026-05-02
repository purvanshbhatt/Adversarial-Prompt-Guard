'use strict';

const SITE_CONFIG = {
  'chat.openai.com': {
    inputSelectors: [
      '#prompt-textarea',
      'div[contenteditable="true"][data-lexical-editor]',
      'div[contenteditable="true"][aria-label="Message ChatGPT"]',
    ],
    submitSelectors: [
      'button[data-testid="send-button"]',
      'button[aria-label="Send prompt"]',
      'button[aria-label="Send message"]',
    ],
  },
  'claude.ai': {
    inputSelectors: [
      'div[contenteditable="true"].ProseMirror',
      'div[contenteditable="true"][aria-label]',
      'div[contenteditable="true"][data-placeholder]',
    ],
    submitSelectors: [
      'button[aria-label="Send message"]',
      'button[aria-label="Send Message"]',
      'button[type="submit"]',
    ],
  },
  'gemini.google.com': {
    inputSelectors: [
      'div.ql-editor[contenteditable="true"]',
      'rich-textarea div[contenteditable="true"]',
      'div[contenteditable="true"][aria-label]',
    ],
    submitSelectors: [
      'button.send-button',
      'button[aria-label="Send message"]',
      'button[aria-label="Send"]',
    ],
  },
};

const host = location.hostname;
const siteKey = Object.keys(SITE_CONFIG).find((k) => host.includes(k));
if (!siteKey) throw new Error('[LLMShield] unsupported host, exiting');

const config = SITE_CONFIG[siteKey];

let inputEl    = null;
let submitEl   = null;
let pendingText = '';
let overlayEl  = null;
let bypassNext = false;
let sessionScanned = 0;
let sessionBlocked = 0;

function getInputEl() {
  for (const sel of config.inputSelectors) {
    const el = document.querySelector(sel);
    if (el) return el;
  }
  return null;
}

function getSubmitEl() {
  for (const sel of config.submitSelectors) {
    const el = document.querySelector(sel);
    if (el) return el;
  }
  return null;
}

function extractText(el) {
  if (!el) return '';
  if (el.tagName === 'TEXTAREA') return el.value.trim();
  return (el.innerText || el.textContent || '').trim();
}

async function analyzePrompt(text) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ action: 'analyze', prompt: text }, resolve);
  });
}

async function handleSubmitAttempt(e) {
  if (bypassNext) {
    bypassNext = false;
    return;
  }

  inputEl  = getInputEl();
  submitEl = getSubmitEl();
  const text = extractText(inputEl);

  if (!text || text.length < 3) return;

  e.preventDefault();
  e.stopImmediatePropagation();

  pendingText = text;

  showLoadingOverlay();

  const result = await analyzePrompt(text);

  sessionScanned++;
  chrome.storage.local.set({ sessionScanned, sessionBlocked });

  if (!result || result.skipped || result.apiError) {
    closeOverlay();
    proceedWithSubmit();
    return;
  }

  if (result.shouldWarn) {
    sessionBlocked++;
    chrome.storage.local.set({ sessionScanned, sessionBlocked });
    highlightInput(inputEl, result.severity);
    showResultOverlay(result);
  } else {
    closeOverlay();
    proceedWithSubmit();
  }
}

function proceedWithSubmit() {
  bypassNext = true;
  clearHighlight(inputEl);

  if (submitEl) {
    submitEl.click();
  } else {
    inputEl = getInputEl();
    if (inputEl) {
      inputEl.dispatchEvent(
        new KeyboardEvent('keydown', {
          key: 'Enter', code: 'Enter', keyCode: 13,
          bubbles: true, cancelable: true,
        })
      );
    }
  }
}

function highlightInput(el, severity) {
  if (!el) return;
  const colorMap = {
    CRITICAL: '#ef4444',
    HIGH:     '#f97316',
    MEDIUM:   '#eab308',
    LOW:      '#22c55e',
  };
  const color = colorMap[severity] || '#eab308';
  el.style.outline        = `2px solid ${color}`;
  el.style.outlineOffset  = '2px';
  el.style.borderRadius   = '8px';
  el.style.transition     = 'outline 0.2s';
}

function clearHighlight(el) {
  if (!el) return;
  el.style.outline       = '';
  el.style.outlineOffset = '';
}

function showLoadingOverlay() {
  closeOverlay();
  const el = document.createElement('div');
  el.id = 'llmshield-overlay';
  el.innerHTML = `
    <div id="llmshield-card" style="padding:32px;text-align:center;">
      <div style="font-size:28px;margin-bottom:12px;animation:llmshield-spin 1s linear infinite;display:inline-block;">🔍</div>
      <div style="font-size:14px;font-weight:600;color:#e6edf3;">Scanning prompt…</div>
      <div style="font-size:12px;color:#8b949e;margin-top:4px;">Checking for injection attacks</div>
      <style>
        @keyframes llmshield-spin { from { transform:rotate(0deg); } to { transform:rotate(360deg); } }
      </style>
    </div>`;
  document.body.appendChild(el);
  overlayEl = el;
}

function showResultOverlay(result) {
  closeOverlay();

  const severityMeta = {
    CRITICAL: { icon: '🚨', label: 'Critical Risk',   cls: 'critical' },
    HIGH:     { icon: '⚠️', label: 'High Risk',       cls: 'high'     },
    MEDIUM:   { icon: '🟡', label: 'Medium Risk',     cls: 'medium'   },
    LOW:      { icon: '🟢', label: 'Low Risk',        cls: 'low'      },
  };
  const meta = severityMeta[result.severity] || severityMeta.MEDIUM;

  const attackTypesHtml = (result.attackTypes && result.attackTypes.length)
    ? result.attackTypes.map((t) => `<span class="llmshield-tag">${escHtml(formatTag(t))}</span>`).join('')
    : '<span class="llmshield-tag">Unknown</span>';

  const tokensHtml = (result.suspiciousTokens && result.suspiciousTokens.length)
    ? result.suspiciousTokens.map((t) => `<span class="llmshield-token">${escHtml(t)}</span>`).join('')
    : '';

  const tokensSection = tokensHtml
    ? `<div class="llmshield-section">
         <div class="llmshield-section-label">Suspicious Phrases</div>
         <div id="llmshield-tokens">${tokensHtml}</div>
       </div>`
    : '';

  const scoreW = Math.round(Math.min(result.riskScore, 100));

  const el = document.createElement('div');
  el.id = 'llmshield-overlay';
  el.innerHTML = `
    <div id="llmshield-card">
      <div id="llmshield-header">
        <div id="llmshield-icon" class="${meta.cls}">${meta.icon}</div>
        <div id="llmshield-title-group">
          <p id="llmshield-title">Prompt Injection Detected</p>
          <p id="llmshield-subtitle">AuroraSOC · LLM Shield</p>
        </div>
        <span id="llmshield-badge" class="${meta.cls}">${meta.label}</span>
      </div>

      <div id="llmshield-body">
        <div id="llmshield-score-row">
          <span id="llmshield-score-label">Risk score</span>
          <div id="llmshield-score-bar-wrap">
            <div id="llmshield-score-bar" class="${meta.cls}" style="width:${scoreW}%"></div>
          </div>
          <span id="llmshield-score-num">${Math.round(result.riskScore)}</span>
        </div>

        <div class="llmshield-section">
          <div class="llmshield-section-label">Attack Type</div>
          <div id="llmshield-attack-tags">${attackTypesHtml}</div>
        </div>

        <div class="llmshield-section">
          <div class="llmshield-section-label">Explanation</div>
          <div id="llmshield-explanation">${escHtml(result.explanation || 'Potential adversarial content detected.')}</div>
        </div>

        ${tokensSection}
      </div>

      <div id="llmshield-footer">
        <button id="llmshield-btn-proceed">Proceed anyway</button>
        <button id="llmshield-btn-edit">✏ Edit my prompt</button>
      </div>
      <div id="llmshield-powered">Powered by AuroraSOC v2.0</div>
    </div>`;

  document.body.appendChild(el);
  overlayEl = el;

  el.querySelector('#llmshield-btn-proceed').addEventListener('click', () => {
    closeOverlay();
    proceedWithSubmit();
  });

  el.querySelector('#llmshield-btn-edit').addEventListener('click', () => {
    closeOverlay();
    clearHighlight(inputEl);
    if (inputEl) {
      inputEl.focus();
      if (inputEl.tagName === 'TEXTAREA') {
        const len = inputEl.value.length;
        inputEl.setSelectionRange(len, len);
      }
    }
  });

  el.addEventListener('click', (e) => {
    if (e.target === el) {
      closeOverlay();
      clearHighlight(inputEl);
    }
  });
}

function closeOverlay() {
  if (overlayEl) {
    overlayEl.remove();
    overlayEl = null;
  }
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatTag(s) {
  return s.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

function attachListeners() {
  inputEl  = getInputEl();
  submitEl = getSubmitEl();

  if (inputEl) {
    inputEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        handleSubmitAttempt(e);
      }
    }, true);
  }

  if (submitEl) {
    submitEl.addEventListener('click', handleSubmitAttempt, true);
  }
}

function init() {
  attachListeners();

  const observer = new MutationObserver(() => {
    const newInput  = getInputEl();
    const newSubmit = getSubmitEl();
    if (newInput !== inputEl || newSubmit !== submitEl) {
      inputEl  = newInput;
      submitEl = newSubmit;
      attachListeners();
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });
}

chrome.storage.local.get({ sessionScanned: 0, sessionBlocked: 0 }, (data) => {
  sessionScanned = data.sessionScanned;
  sessionBlocked = data.sessionBlocked;
});

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
