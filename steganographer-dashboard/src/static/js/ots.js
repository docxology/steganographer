/** Real current-media OpenTimestamps status. A calendar receipt is not Bitcoin verification. */
(function () {
    'use strict';
    let initialized = false, busy = false, refreshPromise = null, refreshAgain = false, timer = null;
    let currentStatus = null, outcome = null;
    const node = id => document.getElementById(id);
    function render() {
        if (!initialized) return;
        const status = currentStatus;
        node('ots-status').textContent = !status ? 'checking…' : status.status || 'unknown';
        node('ots-stamp-btn').disabled = busy || !status?.enabled || !status?.available || !status?.can_stamp || !status?.has_media;
        node('ots-stamp-btn').textContent = busy ? 'Stamping…' : 'Stamp current signed media';
        node('ots-media-digest').textContent = status?.media_digest || 'No signed media available';
        node('ots-media-digest').title = status?.media_digest || '';
        const proof = status?.proof || outcome;
        const matches = proof?.digest && proof.digest === status?.media_digest;
        const verified = matches && (status?.verified === true || proof?.verified === true);
        const pending = matches && (status?.pending === true || proof?.pending === true);
        node('ots-verified').textContent = verified ? 'Bitcoin commitment verified (trusted explorer)' :
            pending ? 'Pending — not Bitcoin-confirmed/verified' : matches ? 'Receipt saved — not verified' : 'No proof verified for current media';
        node('ots-indicator').style.color = verified ? '#4caf50' : pending ? '#e9a426' : '#888';
        if (status && !status.has_media) node('ots-status').textContent = status.enabled ? 'Waiting for signed media' : 'disabled';
        else if (status?.enabled && status.available && !status.can_stamp) node('ots-status').textContent = 'Stamp interval not yet elapsed';
    }
    function applyMetrics(metrics) {
        if (!initialized || !metrics) return;
        const count = metrics.ots_proofs_generated ?? metrics.ots_proofs_count;
        if (count != null) node('ots-proofs-count').textContent = String(count);
        // Only /ots/status binds a proof to the latest exact media digest.
        // An aggregate false metric is not a failed verification.
    }
    async function refreshStatus() {
        if (!initialized) return;
        if (refreshPromise) { refreshAgain = true; return refreshPromise; }
        refreshPromise = (async () => {
            do {
                refreshAgain = false;
                try {
                    const response = await fetch('/ots/status', { headers: authHeaders(), signal: AbortSignal.timeout(5000) });
                    if (!response.ok) throw new Error(`HTTP ${response.status}`);
                    currentStatus = await response.json(); render(); applyMetrics(currentStatus);
                } catch (_) {
                    currentStatus = { status: 'unavailable', enabled: false, available: false };
                    render();
                }
            } while (refreshAgain);
        })();
        try { await refreshPromise; } finally { refreshPromise = null; }
    }
    async function stampNow() {
        if (busy || node('ots-stamp-btn').disabled) return;
        busy = true; render();
        try {
            // Empty body explicitly requests the backend's latest signed-media SHA256.
            // The backend rejects missing media; it never substitutes session uptime.
            const response = await fetch('/ots/stamp', { method: 'POST', headers: authHeaders(), signal: AbortSignal.timeout(30000) });
            const data = await response.json();
            if (!response.ok || !['pending', 'stamped', 'verified'].includes(data.status) || !/^[0-9a-f]{64}$/i.test(data.digest || '')) {
                throw new Error(data.message || `Stamp rejected: ${data.status || response.status}`);
            }
            outcome = data;
            showToast(data.verified === true ? 'Bitcoin commitment verified' : 'Calendar receipt saved — Bitcoin verification pending', 'info');
        } catch (error) { showToast('Timestamp not obtained: ' + error.message, 'error'); }
        finally { busy = false; await refreshStatus(); render(); }
    }
    function init() {
        const container = node('ots-container');
        if (!container || initialized) return;
        container.innerHTML = `<div class="ots-panel"><div class="ots-header"><span id="ots-indicator">●</span>
            <strong>OpenTimestamps — current signed artifact</strong><span id="ots-status">checking…</span></div>
            <div class="ots-row"><span>SHA256 commitment</span><code id="ots-media-digest">—</code></div>
            <div class="ots-row"><span>Calendar receipts (session)</span><span id="ots-proofs-count">0</span></div>
            <div class="ots-row"><span id="ots-verified">No proof verified for current media</span></div>
            <p>Stamps the latest exact signed PNG or PCM artifact held by the server. A pending receipt is not Bitcoin verification or independent proof of authorship.</p>
            <button id="ots-stamp-btn" disabled>Stamp current signed media</button></div>`;
        initialized = true; node('ots-stamp-btn').addEventListener('click', stampNow);
        refreshStatus(); timer = setInterval(refreshStatus, 15000);
        window.addEventListener('pagehide', () => clearInterval(timer));
    }
    window.OtsPanel = { applyMetrics, refreshStatus };
    document.readyState === 'loading' ? document.addEventListener('DOMContentLoaded', init) : init();
})();
