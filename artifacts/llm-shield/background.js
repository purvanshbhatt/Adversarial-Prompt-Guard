const DEFAULT_SETTINGS = {
  apiEndpoint: 'http://localhost:6000',
  riskThreshold: 35,
  enabled: true,
};

async function getSettings() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(DEFAULT_SETTINGS, resolve);
  });
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.sync.get(DEFAULT_SETTINGS, (existing) => {
    chrome.storage.sync.set({ ...DEFAULT_SETTINGS, ...existing });
  });
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.action === 'analyze') {
    handleAnalyze(message.prompt).then(sendResponse).catch((err) => {
      sendResponse({ error: err.message });
    });
    return true;
  }

  if (message.action === 'getSettings') {
    getSettings().then(sendResponse);
    return true;
  }

  if (message.action === 'getStatus') {
    getSettings().then((s) => sendResponse({ enabled: s.enabled }));
    return true;
  }
});

async function handleAnalyze(prompt) {
  const settings = await getSettings();

  if (!settings.enabled) {
    return { skipped: true };
  }

  let data;
  try {
    const res = await fetch(`${settings.apiEndpoint}/api/analyze_prompt`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt }),
    });

    if (!res.ok) {
      throw new Error(`API error ${res.status}`);
    }
    data = await res.json();
  } catch (err) {
    return { apiError: err.message };
  }

  const riskScore      = data.risk_score ?? 0;
  const isMalicious    = data.is_malicious ?? false;
  const attackTypes    = data.attack_types ?? [];
  const explanation    = data.explanation ?? '';
  const suspiciousTokens = data.suspicious_tokens ?? [];
  const obfuscation    = data.obfuscation_techniques ?? [];
  const mlConfidence   = data.ml_confidence ?? 0;

  let severity;
  if (riskScore >= 75)      severity = 'CRITICAL';
  else if (riskScore >= 50) severity = 'HIGH';
  else if (riskScore >= 25) severity = 'MEDIUM';
  else                      severity = 'LOW';

  const shouldWarn = riskScore >= settings.riskThreshold && isMalicious;

  return {
    riskScore,
    severity,
    isMalicious,
    attackTypes,
    explanation,
    suspiciousTokens,
    obfuscation,
    mlConfidence,
    shouldWarn,
    threshold: settings.riskThreshold,
  };
}
