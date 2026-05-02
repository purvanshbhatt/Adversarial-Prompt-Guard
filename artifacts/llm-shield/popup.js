'use strict';

const DEFAULT_SETTINGS = {
  apiEndpoint: 'http://localhost:6000',
  riskThreshold: 35,
  enabled: true,
};

function $(id) { return document.getElementById(id); }

function applyStatus(enabled) {
  const pill    = $('statusPill');
  const btnTgl  = $('btnToggle');
  if (enabled) {
    pill.textContent = 'Active';
    pill.className   = 'status-pill on';
    btnTgl.textContent  = 'Disable';
    btnTgl.className    = 'btn-toggle';
  } else {
    pill.textContent = 'Disabled';
    pill.className   = 'status-pill off';
    btnTgl.textContent  = 'Enable';
    btnTgl.className    = 'btn-toggle off';
  }
}

chrome.storage.sync.get(DEFAULT_SETTINGS, (settings) => {
  applyStatus(settings.enabled);
  $('statThreshold').textContent = settings.riskThreshold;

  try {
    const url = new URL(settings.apiEndpoint);
    $('statEndpoint').textContent      = '✓';
    $('statEndpointLabel').textContent = url.host;
  } catch {
    $('statEndpoint').textContent      = '✗';
    $('statEndpointLabel').textContent = 'Not configured';
  }
});

chrome.storage.local.get({ sessionScanned: 0, sessionBlocked: 0 }, (data) => {
  $('statScanned').textContent = data.sessionScanned;
  $('statBlocked').textContent = data.sessionBlocked;
});

$('btnToggle').addEventListener('click', () => {
  chrome.storage.sync.get(DEFAULT_SETTINGS, (settings) => {
    const next = !settings.enabled;
    chrome.storage.sync.set({ enabled: next }, () => {
      applyStatus(next);
    });
  });
});

$('btnSettings').addEventListener('click', () => {
  chrome.runtime.openOptionsPage();
});
