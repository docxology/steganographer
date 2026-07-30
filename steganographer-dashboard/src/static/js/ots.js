/**
 * ots.js — OpenTimestamps dashboard UI component.
 *
 * Shows the OTS attestation status, last timestamp, proof count, and a
 * "Stamp Now" button that triggers POST /ots/stamp. All failures degrade
 * gracefully: if the OTS server is down the indicator shows "unavailable"
 * rather than throwing.
 */
(function () {
  'use strict';

  const REFRESH_MS = 15000;

  /** Build the OTS panel DOM and insert it into the given container. */
  function buildPanel(container) {
    container.innerHTML = `
      <div class="ots-panel" id="ots-panel">
        <div class="ots-header">
          <span class="ots-indicator" id="ots-indicator">●</span>
          <span class="ots-label">OpenTimestamps</span>
          <span class="ots-status" id="ots-status">checking…</span>
        </div>
        <div class="ots-body">
          <div class="ots-row">
            <span class="ots-key">Last timestamp</span>
            <span class="ots-val" id="ots-last-ts">—</span>
          </div>
          <div class="ots-row">
            <span class="ots-key">Proofs</span>
            <span class="ots-val" id="ots-proofs-count">0</span>
          </div>
          <div class="ots-row">
            <span class="ots-key">Verified</span>
            <span class="ots-val" id="ots-verified">—</span>
          </div>
        </div>
        <button class="ots-stamp-btn" id="ots-stamp-btn" disabled>Stamp Now</button>
      </div>
    `;
  }

  /** Format a Unix-seconds timestamp into a human-readable UTC string. */
  function formatTimestamp(unixSecs) {
    if (!unixSecs || unixSecs === 0) return '—';
    const d = new Date(unixSecs * 1000);
    if (isNaN(d.getTime())) return '—';
    return d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  }

  /** Update the UI from a status JSON payload. */
  function applyStatus(data) {
    const indicator = document.getElementById('ots-indicator');
    const statusEl = document.getElementById('ots-status');
    const stampBtn = document.getElementById('ots-stamp-btn');

    const enabled = data.enabled;
    const available = data.available;
    const status = data.status || 'unknown';

    // Status indicator colour
    const colours = {
      ready: '#4caf50',
      disabled: '#888',
      unavailable: '#f44336',
    };
    indicator.style.color = colours[status] || '#888';
    statusEl.textContent = status;

    if (enabled && available) {
      stampBtn.disabled = false;
    } else {
      stampBtn.disabled = true;
    }
  }

  /** Update OTS metric fields from a WebSocket / API metrics payload. */
  function applyMetrics(metrics) {
    if (!metrics) return;
    const proofs = metrics.ots_proofs_generated ?? metrics.ots_proofs_count ?? 0;
    const lastTs = metrics.ots_last_timestamp ?? 0;
    const verified = metrics.ots_last_verified ?? metrics.ots_verified ?? null;

    const proofsEl = document.getElementById('ots-proofs-count');
    const tsEl = document.getElementById('ots-last-ts');
    const verifiedEl = document.getElementById('ots-verified');

    if (proofsEl) proofsEl.textContent = proofs;
    if (tsEl) tsEl.textContent = formatTimestamp(lastTs);
    if (verifiedEl) {
      if (verified === null || verified === undefined) {
        verifiedEl.textContent = '—';
      } else {
        verifiedEl.textContent = verified ? '✓ yes' : '✗ no';
        verifiedEl.style.color = verified ? '#4caf50' : '#f44336';
      }
    }
  }

  /** Fetch GET /ots/status and refresh the panel. */
  async function refreshStatus() {
    try {
      const resp = await fetch('/ots/status');
      if (!resp.ok) {
        applyStatus({ enabled: false, available: false, status: 'unavailable' });
        return;
      }
      const data = await resp.json();
      applyStatus(data);
    } catch (_e) {
      applyStatus({ enabled: false, available: false, status: 'unavailable' });
    }
  }

  /** Trigger POST /ots/stamp. */
  async function stampNow() {
    const btn = document.getElementById('ots-stamp-btn');
    if (!btn || btn.disabled) return;
    btn.disabled = true;
    btn.textContent = 'Stamping…';
    try {
      const resp = await fetch('/ots/stamp', { method: 'POST' });
      const data = await resp.json().catch(() => ({}));
      if (resp.ok && data.status === 'stamped') {
        btn.textContent = '✓ Stamped';
        refreshStatus();
      } else if (data.kind === 'unavailable' || data.kind === 'unreachable') {
        btn.textContent = 'Unavailable';
      } else {
        btn.textContent = '✗ Failed';
      }
    } catch (_e) {
      btn.textContent = 'Unavailable';
    }
    setTimeout(() => {
      btn.textContent = 'Stamp Now';
      refreshStatus();
    }, 2500);
  }

  /** Expose a hook so app.js / app.js can feed live WS metrics into the panel. */
  window.OtsPanel = {
    applyMetrics: applyMetrics,
    refreshStatus: refreshStatus,
  };

  /** Initialise the panel when the DOM is ready. */
  function init() {
    const container = document.getElementById('ots-container');
    if (!container) return; // OTS panel not present in this page
    buildPanel(container);
    document.getElementById('ots-stamp-btn').addEventListener('click', stampNow);
    refreshStatus();
    setInterval(refreshStatus, REFRESH_MS);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
