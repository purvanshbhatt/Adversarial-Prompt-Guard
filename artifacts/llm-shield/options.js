'use strict';

const DEFAULT_SETTINGS = {
  apiEndpoint: 'http://localhost:6000',
  riskThreshold: 35,
  enabled: true,
};

function $(id) { return document.getElementById(id); }

function showStatus(msg, type) {
  const el = $('status');
  el.textContent = msg;
  el.className   = type;
  el.style.display = 'block';
  setTimeout(() => { el.style.display = 'none'; }, 3500);
}

chrome.storage.sync.get(DEFAULT_SETTINGS, (settings) => {
  $('apiEndpoint').value  = settings.apiEndpoint;
  $('threshold').value    = settings.riskThreshold;
  $('enabled').checked    = settings.enabled;
});

$('btnSave').addEventListener('click', () => {
  const endpoint  = $('apiEndpoint').value.trim();
  const threshold = parseInt($('threshold').value, 10);
  const enabled   = $('enabled').checked;

  if (!endpoint) {
    showStatus('API endpoint is required.', 'err');
    return;
  }

  try { new URL(endpoint); } catch {
    showStatus('Invalid URL — example: http://localhost:6000', 'err');
    return;
  }

  if (isNaN(threshold) || threshold < 0 || threshold > 100) {
    showStatus('Threshold must be between 0 and 100.', 'err');
    return;
  }

  chrome.storage.sync.set(
    { apiEndpoint: endpoint, riskThreshold: threshold, enabled },
    () => { showStatus('Settings saved.', 'ok'); }
  );
});

$('btnTest').addEventListener('click', async () => {
  const endpoint = $('apiEndpoint').value.trim();
  $('btnTest').textContent = 'Testing…';
  $('btnTest').disabled    = true;

  try {
    const res = await fetch(`${endpoint}/api/health`, { signal: AbortSignal.timeout(5000) });
    if (res.ok) {
      const data = await res.json();
      showStatus(
        `Connected — AuroraSOC · ML trained: ${data.ml_trained ? 'Yes' : 'No'} · Semantic: ${data.semantic_loaded ? 'Ready' : 'Loading'}`,
        'ok'
      );
    } else {
      showStatus(`Server responded with HTTP ${res.status}`, 'err');
    }
  } catch (err) {
    showStatus(`Connection failed: ${err.message}`, 'err');
  } finally {
    $('btnTest').textContent = 'Test connection';
    $('btnTest').disabled    = false;
  }
});
