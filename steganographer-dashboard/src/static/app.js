/**
 * Steganographer Dashboard — Client Application
 *
 * Architecture:
 * - LEFT:  Raw webcam via requestAnimationFrame + QR metadata overlay
 * - SERVER: Signs ~1 frame/sec via WebSocket
 * - RIGHT: Verification data + live config controls
 *
 * The QR overlay renders a data matrix on every frame with:
 *   Frame index, BLAKE3 hash prefix, timestamp, backend, overlay text
 * Opacity slider controls the QR overlay visibility (0=invisible, 1=opaque).
 */

// ─── Configuration ────────────────────────────────────────────────────────────

const WS_RECONNECT_DELAY_MS = 2000;
const WS_HEARTBEAT_INTERVAL_MS = 15000;
let SIGN_INTERVAL_MS = 1000;
const JPEG_QUALITY = 0.80;
const DECODE_POLL_INTERVAL_MS = 300;
const MAX_LOG_ENTRIES = 20;
const QR_MODULE_SIZE = 4;     // default px per QR module (overridden by qrScale)
const QR_MARGIN = 8;          // px margin from corner
const QR_GRID_CELLS = 15;     // data matrix grid dimension (for 20-byte payload)
const TOAST_DURATION_MS = 2500; // default toast auto-dismiss time

// ─── State ────────────────────────────────────────────────────────────────────

let encodeWs = null;
let decodeWs = null;
let webcamStream = null;
let signInterval = null;
let decodePollInterval = null;
let drawLoopId = null;
let metamaskAccount = null;
let cameraActive = false;
let awaitingSignResponse = false;
let frameCounter = 0;

// Latest verification data from server (for QR overlay)
let lastVerifyData = {
    frameIndex: 0,
    hash: '0000000000000000',
    backend: 'ed25519',
    verified: false,
    signLatencyUs: 0,
};

// Live config state (mirrored to server)
let liveConfig = {
    opacity: 1.0,
    lsbBits: 1,
    signingBackend: 'ed25519',
    overlayText: 'CONFIDENTIAL',
    signRateMs: 1000,
    width: 640,
    height: 480,
    qrScale: 10,        // % of video width (10=small corner, 100=full frame)
    resolution: '640x480',
};

// ─── DOM References ───────────────────────────────────────────────────────────

const el = {
    statusDot: document.getElementById('status-dot'),
    statusText: document.getElementById('status-text'),
    identityValue: document.getElementById('identity-value'),
    encodeOverlay: document.getElementById('encode-overlay'),
    encodeCanvas: document.getElementById('encode-canvas'),
    webcamVideo: document.getElementById('webcam-video'),
    startCameraBtn: document.getElementById('start-camera-btn'),
    metamaskBtn: document.getElementById('metamask-btn'),
    metamaskLabel: document.getElementById('metamask-label'),
    signIndicator: document.getElementById('sign-indicator'),
    // Verification
    verifyWaiting: document.getElementById('verify-waiting'),
    verifyResult: document.getElementById('verify-result'),
    verifyStatusBanner: document.getElementById('verify-status-banner'),
    verifyStatusIcon: document.getElementById('verify-status-icon'),
    verifyStatusText: document.getElementById('verify-status-text'),
    fieldFrameIndex: document.getElementById('field-frame-index'),
    fieldHash: document.getElementById('field-hash'),
    fieldSigPreview: document.getElementById('field-sig-preview'),
    fieldBackend: document.getElementById('field-backend'),
    fieldVerifyLatency: document.getElementById('field-verify-latency'),
    verifyLog: document.getElementById('verify-log'),
    // Config
    cfgOpacity: document.getElementById('cfg-opacity'),
    cfgOpacityVal: document.getElementById('cfg-opacity-val'),
    cfgLsbBits: document.getElementById('cfg-lsb-bits'),
    cfgLsbBitsVal: document.getElementById('cfg-lsb-bits-val'),
    cfgSignBackend: document.getElementById('cfg-sign-backend'),
    cfgOverlayText: document.getElementById('cfg-overlay-text'),
    cfgSignRate: document.getElementById('cfg-sign-rate'),
    cfgSignRateVal: document.getElementById('cfg-sign-rate-val'),
    cfgQrScale: document.getElementById('cfg-qr-scale'),
    cfgQrScaleVal: document.getElementById('cfg-qr-scale-val'),
    cfgResolution: document.getElementById('cfg-resolution'),
    // Stego info
    infoPayloadSize: document.getElementById('info-payload-size'),
    infoHashAlgo: document.getElementById('info-hash-algo'),
    infoSigAlgo: document.getElementById('info-sig-algo'),
    infoCapacity: document.getElementById('info-capacity'),
    infoUtilization: document.getElementById('info-utilization'),
    // Stats
    valFrames: document.getElementById('val-frames'),
    valFps: document.getElementById('val-fps'),
    valSignLatency: document.getElementById('val-sign-latency'),
    valVerifiedOk: document.getElementById('val-verified-ok'),
    valVerifiedFail: document.getElementById('val-verified-fail'),
    valVerifyLatency: document.getElementById('val-verify-latency'),
    footerBackendValue: document.getElementById('footer-backend-value'),
    footerUptimeValue: document.getElementById('footer-uptime-value'),
    footerResolutionValue: document.getElementById('footer-resolution-value'),
    signingBackend: document.getElementById('signing-backend'),
};

// ═══════════════════════════════════════════════════════════════════════════════
// QR DATA MATRIX OVERLAY
// ═══════════════════════════════════════════════════════════════════════════════
//
// Encodes metadata as a visual data matrix (binary grid) on the video canvas.
// Each "module" is a small colored square. The data encoded is:
//   - Frame counter (local)
//   - Server frame index (from last signing)
//   - BLAKE3 hash prefix (first 8 bytes)
//   - Timestamp (seconds since epoch, low 16 bits)
//   - Backend ID (1 byte)
//   - Verification status (1 byte)
//
// This is a simplified data matrix — not a full QR code — but visually
// resembles one and is fully roundtrippable: any reader that knows the
// format can extract the data from a screenshot.

/**
 * Encode a byte array into a 2D binary grid for rendering as a data matrix.
 * Returns { grid: boolean[][], size: number }
 */
function encodeDataMatrix(bytes) {
    const totalBits = bytes.length * 8;
    // Grid size = ceil(sqrt(totalBits)) + 2 for finder pattern
    const innerSize = Math.ceil(Math.sqrt(totalBits));
    const size = innerSize + 2; // +2 for border
    const grid = Array.from({ length: size }, () => Array(size).fill(false));

    // Finder pattern: solid border on top and left, alternating on bottom and right
    for (let i = 0; i < size; i++) {
        grid[0][i] = true;                     // top solid
        grid[i][0] = true;                     // left solid
        grid[size - 1][i] = (i % 2 === 0);    // bottom alternating
        grid[i][size - 1] = (i % 2 === 0);    // right alternating
    }

    // Data area: fill inner grid with bits
    let bitIndex = 0;
    for (let row = 1; row < size - 1 && bitIndex < totalBits; row++) {
        for (let col = 1; col < size - 1 && bitIndex < totalBits; col++) {
            const byteIdx = Math.floor(bitIndex / 8);
            const bitPos = 7 - (bitIndex % 8);
            grid[row][col] = ((bytes[byteIdx] >> bitPos) & 1) === 1;
            bitIndex++;
        }
    }

    return { grid, size };
}

/**
 * Build the metadata byte array for the current frame.
 * Format (20 bytes):
 *   [0..3]   Local frame counter (u32 LE)
 *   [4..7]   Server frame index (u32 LE)
 *   [8..15]  BLAKE3 hash prefix (8 bytes from hex)
 *   [16..17] Timestamp low 16 bits (u16 LE)
 *   [18]     Backend ID: 0=ed25519, 1=ethereum
 *   [19]     Status: 1=verified, 0=unverified
 */
function buildMetadataBytes() {
    const buf = new Uint8Array(20);
    const view = new DataView(buf.buffer);

    // Local frame counter
    view.setUint32(0, frameCounter & 0xFFFFFFFF, true);

    // Server frame index
    view.setUint32(4, (lastVerifyData.frameIndex || 0) & 0xFFFFFFFF, true);

    // BLAKE3 hash prefix (first 16 hex chars → 8 bytes)
    const hashHex = (lastVerifyData.hash || '0000000000000000').slice(0, 16);
    for (let i = 0; i < 8; i++) {
        buf[8 + i] = parseInt(hashHex.slice(i * 2, i * 2 + 2), 16) || 0;
    }

    // Timestamp low 16 bits
    view.setUint16(16, (Date.now() / 1000) & 0xFFFF, true);

    // Backend ID
    buf[18] = liveConfig.signingBackend === 'ethereum' ? 1 : 0;

    // Verified flag
    buf[19] = lastVerifyData.verified ? 1 : 0;

    return buf;
}

/**
 * Render the data matrix QR overlay onto a canvas context.
 * Position: bottom-right corner of the video.
 */
function renderQrOverlay(ctx, canvasW, canvasH) {
    const opacity = liveConfig.opacity;
    if (opacity <= 0.01) return; // Skip if fully transparent

    const metaBytes = buildMetadataBytes();
    const { grid, size } = encodeDataMatrix(metaBytes);

    // Dynamic module size from qrScale (% of canvas width)
    const targetPx = Math.max(20, (liveConfig.qrScale / 100) * canvasW);
    const modSize = Math.max(1, Math.floor(targetPx / size));
    const totalPx = size * modSize;

    // Position: centered if large, bottom-right if small
    let x0, y0;
    if (liveConfig.qrScale >= 80) {
        // Center the overlay when covering most of the frame
        x0 = Math.floor((canvasW - totalPx) / 2);
        y0 = Math.floor((canvasH - totalPx) / 2);
    } else {
        // Bottom-right corner
        x0 = canvasW - totalPx - QR_MARGIN;
        y0 = canvasH - totalPx - QR_MARGIN;
    }

    ctx.save();
    ctx.globalAlpha = opacity;

    // Background
    ctx.fillStyle = 'rgba(0, 0, 0, 0.6)';
    ctx.fillRect(x0 - 4, y0 - 4, totalPx + 8, totalPx + 8);

    // Modules
    for (let row = 0; row < size; row++) {
        for (let col = 0; col < size; col++) {
            ctx.fillStyle = grid[row][col] ? '#dc2626' : '#1a1a1a';
            ctx.fillRect(x0 + col * modSize, y0 + row * modSize, modSize, modSize);
        }
    }

    // Overlay text label (above QR) — scale font with QR size
    const fontSize = Math.max(9, Math.floor(modSize * 2.5));
    ctx.font = `${fontSize}px "JetBrains Mono", monospace`;
    ctx.fillStyle = '#dc2626';
    ctx.textAlign = liveConfig.qrScale >= 80 ? 'center' : 'right';
    const labelX = liveConfig.qrScale >= 80 ? canvasW / 2 : canvasW - QR_MARGIN;
    ctx.fillText(liveConfig.overlayText, labelX, y0 - fontSize - 4);

    // Frame counter + timestamp label
    ctx.fillStyle = '#888';
    const smallFontSize = Math.max(8, Math.floor(modSize * 2));
    ctx.font = `${smallFontSize}px "JetBrains Mono", monospace`;
    const now = new Date();
    const ts = now.toTimeString().slice(0, 8); // HH:MM:SS
    const ms = String(now.getMilliseconds()).padStart(3, '0');
    const datePart = now.toISOString().slice(0, 10); // YYYY-MM-DD
    ctx.fillText(`F:${frameCounter} | ${liveConfig.signingBackend.toUpperCase()} | ${datePart} ${ts}.${ms}`, labelX, y0 - fontSize - smallFontSize - 8);

    ctx.restore();
}

// ─── Webcam ───────────────────────────────────────────────────────────────────

async function startCamera() {
    const [rw, rh] = liveConfig.resolution.split('x').map(Number);
    try {
        // Stop existing stream if restarting
        if (webcamStream) {
            webcamStream.getTracks().forEach(t => t.stop());
            webcamStream = null;
        }
        webcamStream = await navigator.mediaDevices.getUserMedia({
            video: { width: { ideal: rw || 640 }, height: { ideal: rh || 480 }, facingMode: 'user' },
            audio: false,
        });
        el.webcamVideo.srcObject = webcamStream;
        await el.webcamVideo.play();
        cameraActive = true;
        el.encodeOverlay.classList.add('hidden');
        drawWebcamLoop();
        startSigningInterval();
        console.log(`[camera] Webcam started at ${rw}x${rh}`);
    } catch (err) {
        console.error('[camera] Failed:', err);
        el.encodeOverlay.querySelector('.overlay-text').textContent = '❌ Camera denied';
        el.encodeOverlay.querySelector('.overlay-subtext').textContent = err.message || 'Allow camera and reload';
    }
}

function drawWebcamLoop() {
    if (!cameraActive) return;
    const v = el.webcamVideo;
    if (v.readyState >= 2) {
        const c = el.encodeCanvas;
        c.width = v.videoWidth || 640;
        c.height = v.videoHeight || 480;
        liveConfig.width = c.width;
        liveConfig.height = c.height;
        const ctx = c.getContext('2d');

        // Draw webcam frame
        ctx.drawImage(v, 0, 0, c.width, c.height);

        // Render QR data matrix overlay (opacity-controlled)
        renderQrOverlay(ctx, c.width, c.height);

        frameCounter++;
    }
    drawLoopId = requestAnimationFrame(drawWebcamLoop);
}

function startSigningInterval() {
    clearInterval(signInterval);
    signInterval = setInterval(sendFrameForSigning, SIGN_INTERVAL_MS);
}

function sendFrameForSigning() {
    if (!cameraActive || !encodeWs || encodeWs.readyState !== WebSocket.OPEN || awaitingSignResponse) return;
    const v = el.webcamVideo;
    if (v.readyState < 2) return;
    const c = document.createElement('canvas');
    c.width = v.videoWidth || 640;
    c.height = v.videoHeight || 480;
    c.getContext('2d').drawImage(v, 0, 0, c.width, c.height);
    el.signIndicator.classList.remove('hidden');
    c.toBlob((blob) => {
        if (blob && encodeWs && encodeWs.readyState === WebSocket.OPEN) {
            awaitingSignResponse = true;
            blob.arrayBuffer().then(buf => encodeWs.send(buf));
        }
    }, 'image/jpeg', JPEG_QUALITY);
}

// ─── WebSocket ────────────────────────────────────────────────────────────────

function connectEncodeWs() {
    const url = `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ws/encode`;
    encodeWs = new WebSocket(url);
    encodeWs.binaryType = 'arraybuffer';
    let heartbeatId = null;
    encodeWs.onopen = () => {
        console.log('[encode] WS connected');
        updateConnectionStatus(true);
        heartbeatId = setInterval(() => {
            if (encodeWs?.readyState === WebSocket.OPEN) encodeWs.send('ping');
        }, WS_HEARTBEAT_INTERVAL_MS);
    };
    encodeWs.onmessage = (e) => { try { handleEncodeMessage(JSON.parse(e.data)); } catch (err) { } };
    encodeWs.onclose = () => { clearInterval(heartbeatId); updateConnectionStatus(false); setTimeout(connectEncodeWs, WS_RECONNECT_DELAY_MS); };
    encodeWs.onerror = () => encodeWs.close();
}

function connectDecodeWs() {
    const url = `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ws/decode`;
    decodeWs = new WebSocket(url);
    decodeWs.onopen = () => {
        decodePollInterval = setInterval(() => {
            if (decodeWs?.readyState === WebSocket.OPEN) decodeWs.send('poll');
        }, DECODE_POLL_INTERVAL_MS);
    };
    decodeWs.onmessage = (e) => { try { handleDecodeMessage(JSON.parse(e.data)); } catch (err) { } };
    decodeWs.onclose = () => { clearInterval(decodePollInterval); setTimeout(connectDecodeWs, WS_RECONNECT_DELAY_MS); };
    decodeWs.onerror = () => decodeWs.close();
}

// ─── Message Handlers ─────────────────────────────────────────────────────────

function handleEncodeMessage(msg) {
    awaitingSignResponse = false;
    el.signIndicator.classList.add('hidden');
    if (msg.data) updateEncodeMetrics(msg.data);
    if (msg.backend) el.footerBackendValue.textContent = msg.backend;
    if (msg.identity) {
        el.identityValue.textContent = truncateIdentity(msg.identity);
        el.identityValue.title = msg.identity;
    }
    if (msg.width && msg.height) el.footerResolutionValue.textContent = `${msg.width}×${msg.height}`;
}

function handleDecodeMessage(msg) {
    if (msg.type === 'decoded_frame') {
        el.verifyWaiting.classList.add('hidden');
        el.verifyResult.classList.remove('hidden');

        // Update shared verification state (used by QR overlay)
        lastVerifyData.verified = msg.verified;
        lastVerifyData.frameIndex = msg.payload?.frame_index || 0;
        lastVerifyData.hash = msg.payload?.hash || '0000000000000000';
        lastVerifyData.backend = msg.backend || 'ed25519';
        lastVerifyData.signLatencyUs = msg.verify_us || 0;
        lastVerifyData.timestamp = msg.timestamp || new Date().toISOString();

        if (msg.verified) {
            el.verifyStatusBanner.className = 'verify-status-banner status-ok';
            el.verifyStatusIcon.textContent = '✅';
            el.verifyStatusText.textContent = 'Signature Verified';
        } else {
            el.verifyStatusBanner.className = 'verify-status-banner status-fail';
            el.verifyStatusIcon.textContent = '❌';
            el.verifyStatusText.textContent = 'Verification Failed';
        }
        if (msg.payload) {
            el.fieldFrameIndex.textContent = msg.payload.frame_index ?? '—';
            el.fieldHash.textContent = msg.payload.hash ? msg.payload.hash.slice(0, 12) + '…' + msg.payload.hash.slice(-6) : '—';
            el.fieldHash.title = msg.payload.hash || '';
            el.fieldSigPreview.textContent = msg.payload.signature_preview || '—';
            el.fieldSigPreview.title = msg.payload.signature_full || msg.payload.signature_preview || '';
        }
        el.fieldBackend.textContent = msg.backend || '—';
        el.fieldVerifyLatency.textContent = msg.verify_us ? msg.verify_us + ' μs' : '—';
        addLogEntry(msg.verified, msg.payload?.frame_index, msg.verify_us);

        // Update footer verified counter
        const footerVerified = document.getElementById('footer-verified-value');
        if (footerVerified) {
            const ok = parseInt(el.valVerifiedOk.textContent) || 0;
            const fail = parseInt(el.valVerifiedFail.textContent) || 0;
            footerVerified.textContent = `✅ ${ok} / ❌ ${fail}`;
        }
    }
    if (msg.data) updateDecodeMetrics(msg.data);
}

function addLogEntry(verified, frameIndex, verifyUs) {
    const entry = document.createElement('div');
    entry.className = 'log-entry ' + (verified ? 'log-ok' : 'log-fail');
    const t = new Date().toLocaleTimeString();
    const lat = verifyUs ? ` · ${verifyUs}μs` : '';
    entry.innerHTML = `<span class="log-time">${t}</span><span class="log-icon">${verified ? '✅' : '❌'}</span><span class="log-frame">#${frameIndex ?? '?'}</span><span class="log-status">${verified ? 'OK' : 'FAIL'}${lat}</span>`;
    el.verifyLog.insertBefore(entry, el.verifyLog.firstChild);
    while (el.verifyLog.children.length > MAX_LOG_ENTRIES) el.verifyLog.removeChild(el.verifyLog.lastChild);
}

// ─── Metrics ──────────────────────────────────────────────────────────────────

function updateEncodeMetrics(data) {
    el.valFrames.textContent = fmtNum(data.frames_processed || 0);
    el.valFps.textContent = data.average_fps || '0.0';
    el.valSignLatency.textContent = data.avg_sign_latency_us || '0.0';
    el.footerUptimeValue.textContent = fmtUptime(parseFloat(data.uptime_secs || 0));
}

function updateDecodeMetrics(data) {
    el.valVerifiedOk.textContent = fmtNum(data.frames_verified_ok || 0);
    el.valVerifiedFail.textContent = fmtNum(data.frames_verified_fail || 0);
    el.valVerifyLatency.textContent = data.avg_verify_latency_us || '0.0';
}

// ─── Config Controls ──────────────────────────────────────────────────────────

function setupConfigControls() {
    el.cfgOpacity.addEventListener('input', () => {
        liveConfig.opacity = parseInt(el.cfgOpacity.value) / 100;
        el.cfgOpacityVal.textContent = liveConfig.opacity.toFixed(2);
        pushConfigToServer();
    });

    el.cfgLsbBits.addEventListener('input', () => {
        liveConfig.lsbBits = parseInt(el.cfgLsbBits.value);
        el.cfgLsbBitsVal.textContent = liveConfig.lsbBits;
        updateStegoInfo();
        pushConfigToServer();
    });

    el.cfgSignBackend.addEventListener('change', () => {
        liveConfig.signingBackend = el.cfgSignBackend.value;
        updateStegoInfo();
        pushConfigToServer();
    });

    el.cfgOverlayText.addEventListener('change', () => {
        liveConfig.overlayText = el.cfgOverlayText.value;
        pushConfigToServer();
    });

    el.cfgSignRate.addEventListener('input', () => {
        SIGN_INTERVAL_MS = parseInt(el.cfgSignRate.value);
        liveConfig.signRateMs = SIGN_INTERVAL_MS;
        el.cfgSignRateVal.textContent = (1000 / SIGN_INTERVAL_MS).toFixed(1) + '/s';
        if (cameraActive) startSigningInterval();
    });

    // QR Scale slider
    if (el.cfgQrScale) {
        el.cfgQrScale.addEventListener('input', () => {
            liveConfig.qrScale = parseInt(el.cfgQrScale.value);
            el.cfgQrScaleVal.textContent = liveConfig.qrScale + '%';
        });
    }

    // Resolution dropdown
    if (el.cfgResolution) {
        el.cfgResolution.addEventListener('change', () => {
            liveConfig.resolution = el.cfgResolution.value;
            const [rw, rh] = liveConfig.resolution.split('x').map(Number);
            liveConfig.width = rw;
            liveConfig.height = rh;
            updateStegoInfo();
            pushConfigToServer();
            // Restart camera with new resolution
            if (cameraActive) {
                startCamera();
            }
        });
    }

    updateStegoInfo();
}

function updateStegoInfo() {
    const bits = liveConfig.lsbBits;
    const w = liveConfig.width;
    const h = liveConfig.height;
    const capacityBits = w * h * 3 * bits;
    const capacityBytes = Math.floor(capacityBits / 8);

    const isEth = liveConfig.signingBackend === 'ethereum';
    const payloadSize = isEth ? 97 : 104;
    const utilization = capacityBits > 0 ? ((payloadSize * 8 / capacityBits) * 100).toFixed(3) : 0;

    el.infoPayloadSize.textContent = payloadSize + ' bytes';
    el.infoHashAlgo.textContent = 'BLAKE3 (256-bit)';
    el.infoSigAlgo.textContent = isEth ? 'secp256k1 (EIP-191)' : 'Ed25519 (512-bit)';
    el.infoCapacity.textContent = fmtBytes(capacityBytes) + ' (' + fmtNum(capacityBits) + ' bits)';
    el.infoUtilization.textContent = utilization + '%';
}

function pushConfigToServer() {
    fetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(liveConfig),
    })
        .then(r => { if (r.ok) showToast('Config saved', 'success'); else showToast('Config save failed', 'error'); })
        .catch(() => showToast('Config save failed — server unreachable', 'error'));
}

// ─── MetaMask ─────────────────────────────────────────────────────────────────

function detectMetaMask() {
    if (typeof window.ethereum !== 'undefined' && window.ethereum.isMetaMask) {
        el.metamaskBtn.classList.add('metamask-available');
        setupMetaMaskListeners();
    } else {
        el.metamaskBtn.classList.add('metamask-unavailable');
        el.metamaskLabel.textContent = 'No MetaMask';
    }
}

async function connectMetaMask() {
    if (!window.ethereum) { window.open('https://metamask.io/download/', '_blank'); return; }
    try {
        el.metamaskLabel.textContent = 'Connecting...';
        el.metamaskBtn.disabled = true;
        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        if (accounts.length > 0) {
            metamaskAccount = accounts[0];
            el.metamaskLabel.textContent = truncAddr(metamaskAccount);
            el.metamaskBtn.classList.add('metamask-connected');
            el.identityValue.textContent = truncAddr(metamaskAccount);
            el.identityValue.title = metamaskAccount;
            el.signingBackend.value = 'ethereum';
            el.cfgSignBackend.value = 'ethereum';
            liveConfig.signingBackend = 'ethereum';
            el.footerBackendValue.textContent = 'metamask';
            updateStegoInfo();
        }
    } catch (err) { el.metamaskLabel.textContent = 'Connect MetaMask'; }
    finally { el.metamaskBtn.disabled = false; }
}

function disconnectMetaMask() {
    metamaskAccount = null;
    el.metamaskLabel.textContent = 'Connect MetaMask';
    el.metamaskBtn.classList.remove('metamask-connected');
    fetchConfig();
}

function setupMetaMaskListeners() {
    if (!window.ethereum) return;
    window.ethereum.on('accountsChanged', (accts) => {
        if (!accts.length) disconnectMetaMask();
        else { metamaskAccount = accts[0]; el.metamaskLabel.textContent = truncAddr(metamaskAccount); el.identityValue.textContent = truncAddr(metamaskAccount); }
    });
    window.ethereum.on('chainChanged', () => { });
}

// ─── Config Fetch ─────────────────────────────────────────────────────────────

async function fetchConfig() {
    try {
        const r = await fetch('/api/config');
        const c = await r.json();
        if (c.signing_backend && !metamaskAccount) {
            el.signingBackend.value = c.signing_backend;
            el.footerBackendValue.textContent = c.signing_backend;
            el.cfgSignBackend.value = c.signing_backend;
            liveConfig.signingBackend = c.signing_backend;
        }
        if (c.identity && !metamaskAccount) {
            el.identityValue.textContent = truncateIdentity(c.identity);
            el.identityValue.title = c.identity;
        }
        if (c.width && c.height) {
            el.footerResolutionValue.textContent = `${c.width}×${c.height}`;
            liveConfig.width = c.width; liveConfig.height = c.height;
        }
        updateStegoInfo();
    } catch (e) { }
}

// ─── Utilities ────────────────────────────────────────────────────────────────

function updateConnectionStatus(connected) {
    el.statusDot.classList.toggle('connected', connected);
    el.statusDot.classList.toggle('disconnected', !connected);
    el.statusText.textContent = connected ? 'Connected' : 'Reconnecting...';
}

function fmtNum(n) {
    if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
    return String(n);
}

function fmtBytes(b) {
    if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB';
    if (b >= 1024) return (b / 1024).toFixed(1) + ' KB';
    return b + ' B';
}

function fmtUptime(s) {
    if (s < 60) return Math.floor(s) + 's';
    if (s < 3600) return Math.floor(s / 60) + 'm ' + Math.floor(s % 60) + 's';
    return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
}

function truncateIdentity(id) { return (!id || id.length <= 16) ? id : id.slice(0, 8) + '…' + id.slice(-6); }
function truncAddr(a) { return (!a || a.length < 12) ? a : a.slice(0, 6) + '…' + a.slice(-4); }

// ─── Video Recording ──────────────────────────────────────────────────────────

let videoMediaRecorder = null;
let videoRecordedChunks = [];
let videoRecording = false;

function toggleVideoRecording() {
    const btn = document.getElementById('record-video-btn');
    const label = document.getElementById('record-video-label');
    const canvas = document.getElementById('encode-canvas');

    if (!videoRecording) {
        // Start recording
        if (!canvas) {
            console.error('[record] No encode-canvas found');
            return;
        }
        const stream = canvas.captureStream(30);
        videoMediaRecorder = new MediaRecorder(stream, {
            mimeType: 'video/webm; codecs=vp9',
            videoBitsPerSecond: 2500000,
        });
        videoRecordedChunks = [];
        videoMediaRecorder.ondataavailable = (e) => {
            if (e.data.size > 0) videoRecordedChunks.push(e.data);
        };
        videoMediaRecorder.onstop = () => {
            const blob = new Blob(videoRecordedChunks, { type: 'video/webm' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
            a.href = url;
            a.download = `steganographer-video-${ts}.webm`;
            a.click();
            URL.revokeObjectURL(url);
            console.log(`[record] Video saved: ${a.download} (${(blob.size / 1024).toFixed(1)} KB)`);
        };
        videoMediaRecorder.start(1000); // collect chunks every 1s
        videoRecording = true;
        btn.classList.add('recording');
        label.textContent = 'Stop';
        console.log('[record] Video recording started');
    } else {
        // Stop recording
        videoMediaRecorder.stop();
        videoRecording = false;
        btn.classList.remove('recording');
        label.textContent = 'Record';
        console.log('[record] Video recording stopped');
    }
}
// ─── Init ─────────────────────────────────────────────────────────────────────

const SESSION_START = new Date();

function init() {
    console.log('Steganographer Dashboard initializing...');
    fetchConfig();
    connectEncodeWs();
    connectDecodeWs();
    detectMetaMask();
    setupConfigControls();
    el.startCameraBtn.addEventListener('click', startCamera);
    el.metamaskBtn.addEventListener('click', () => metamaskAccount ? disconnectMetaMask() : connectMetaMask());
    setInterval(fetchConfig, 5000);

    const recordVideoBtn = document.getElementById('record-video-btn');
    if (recordVideoBtn) recordVideoBtn.addEventListener('click', toggleVideoRecording);

    // ─── Help Tooltip Positioning (fixed position to escape overflow containers) ──
    initHelpTooltips();

    // ─── Config Preset Buttons ──
    initPresetButtons();

    // ─── Keyboard Shortcuts ──
    document.addEventListener('keydown', handleKeyboardShortcut);

    // ─── Copy-to-Clipboard Buttons ──
    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.dataset.copyTarget;
            const targetEl = document.getElementById(targetId);
            if (!targetEl) return;
            const text = targetEl.title || targetEl.textContent;
            navigator.clipboard.writeText(text).then(() => {
                const orig = btn.textContent;
                btn.textContent = '✓';
                btn.classList.add('copied');
                showToast('Copied to clipboard', 'success');
                setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 1200);
            });
        });
    });

    // ─── Session Export Button ──
    const exportBtn = document.getElementById('session-export-btn');
    if (exportBtn) exportBtn.addEventListener('click', exportSession);

    // ─── Auto-Start Camera ──
    if (new URLSearchParams(window.location.search).has('autostart')) {
        setTimeout(startCamera, 500);
    }
}

function initHelpTooltips() {
    document.querySelectorAll('.help-icon').forEach(icon => {
        const tip = icon.querySelector('.help-tooltip');
        if (!tip) return;
        icon.addEventListener('mouseenter', () => {
            const rect = icon.getBoundingClientRect();

            // Find closest ancestor with a CSS transform — this changes the
            // containing block for position:fixed children, making coordinates
            // relative to that ancestor instead of the viewport.
            let offsetX = 0, offsetY = 0;
            let ancestor = tip.parentElement;
            while (ancestor && ancestor !== document.documentElement) {
                const cs = getComputedStyle(ancestor);
                if (cs.transform && cs.transform !== 'none') {
                    const ar = ancestor.getBoundingClientRect();
                    offsetX = ar.left;
                    offsetY = ar.top;
                    break;
                }
                ancestor = ancestor.parentElement;
            }

            let top = rect.top - 10 - offsetY;
            let left = rect.left + rect.width / 2 - offsetX;
            tip.style.display = 'block';
            tip.style.left = `${left}px`;
            tip.style.top = '0px';
            const tipRect = tip.getBoundingClientRect();
            const tipH = tipRect.height;
            top -= tipH;
            if (top < 8 - offsetY) top = rect.bottom + 10 - offsetY;
            const maxRight = window.innerWidth - offsetX;
            left = Math.max(tipRect.width / 2 + 8, Math.min(left, maxRight - tipRect.width / 2 - 8));
            tip.style.left = `${left}px`;
            tip.style.top = `${top}px`;
            tip.style.transform = 'translateX(-50%)';
        });
        icon.addEventListener('mouseleave', () => {
            tip.style.display = 'none';
        });
    });
}

function handleKeyboardShortcut(e) {
    // Don't trigger if typing in an input/textarea/select
    const tag = e.target.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;

    switch (e.code) {
        case 'Space':
            e.preventDefault();
            if (cameraActive) {
                // Stop camera
                if (webcamStream) webcamStream.getTracks().forEach(t => t.stop());
                cameraActive = false;
                cancelAnimationFrame(drawLoopId);
                clearInterval(signInterval);
                el.encodeOverlay.classList.remove('hidden');
            } else {
                startCamera();
            }
            break;
        case 'KeyR':
            if (!e.ctrlKey && !e.metaKey) toggleVideoRecording();
            break;
        case 'Digit1': switchTab('video'); break;
        case 'Digit2': switchTab('audio'); break;
        case 'Digit3': switchTab('docs'); break;
        case 'Equal': // + key
        case 'NumpadAdd':
            if (liveConfig.lsbBits < 4) {
                liveConfig.lsbBits++;
                el.cfgLsbBits.value = liveConfig.lsbBits;
                el.cfgLsbBitsVal.textContent = liveConfig.lsbBits;
                updateStegoInfo();
                pushConfigToServer();
            }
            break;
        case 'Minus':
        case 'NumpadSubtract':
            if (liveConfig.lsbBits > 1) {
                liveConfig.lsbBits--;
                el.cfgLsbBits.value = liveConfig.lsbBits;
                el.cfgLsbBitsVal.textContent = liveConfig.lsbBits;
                updateStegoInfo();
                pushConfigToServer();
            }
            break;
        case 'KeyE':
            if (!e.ctrlKey && !e.metaKey) exportSession();
            break;
        case 'Slash':  // ? key (Shift+/)
            if (e.shiftKey) { e.preventDefault(); toggleCheatSheet(); }
            break;
        case 'Escape':
            closeCheatSheet();
            break;
    }
}

function switchTab(tabName) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    const btn = document.getElementById(`tab-btn-${tabName}`);
    const content = document.getElementById(`tab-${tabName}`);
    if (btn) btn.classList.add('active');
    if (content) content.classList.add('active');
}

function exportSession() {
    const now = new Date();
    const report = {
        steganographer_version: 'v0.1.0',
        session: {
            start: SESSION_START.toISOString(),
            end: now.toISOString(),
            duration_seconds: Math.round((now - SESSION_START) / 1000),
        },
        config: { ...liveConfig },
        video_metrics: {
            frames_signed: parseInt(el.valFrames.textContent) || 0,
            sign_fps: parseFloat(el.valFps.textContent) || 0,
            avg_sign_latency_us: parseFloat(el.valSignLatency.textContent) || 0,
            verified_ok: parseInt(el.valVerifiedOk.textContent) || 0,
            verified_fail: parseInt(el.valVerifiedFail.textContent) || 0,
            avg_verify_latency_us: parseFloat(el.valVerifyLatency.textContent) || 0,
        },
        last_verification: { ...lastVerifyData },
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const ts = now.toISOString().replace(/[:.]/g, '-').slice(0, 19);
    a.href = url;
    a.download = `steganographer-session-${ts}.json`;
    a.click();
    URL.revokeObjectURL(url);
    console.log(`[export] Session report saved: ${a.download}`);
    showToast(`Session exported: ${a.download}`, 'success');
}

// ─── Toast Notifications ──────────────────────────────────────────────────────

function showToast(message, type = 'info') {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        document.body.appendChild(container);
    }

    const icons = { success: '✓', error: '✗', info: 'ℹ' };
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `<span class="toast-icon">${icons[type] || icons.info}</span>${message}`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('toast-exit');
        toast.addEventListener('animationend', () => toast.remove());
    }, TOAST_DURATION_MS);
}

// ─── Keyboard Shortcut Cheat Sheet ────────────────────────────────────────────

function toggleCheatSheet() {
    const existing = document.getElementById('cheatsheet-overlay');
    if (existing) { existing.remove(); return; }

    const shortcuts = [
        ['Space', 'Start / stop camera'],
        ['R', 'Toggle video recording'],
        ['1 / 2 / 3', 'Switch to Video / Audio / Docs tab'],
        ['+ / −', 'Increase / decrease LSB bits'],
        ['E', 'Export session report'],
        ['?', 'Toggle this cheat sheet'],
        ['Esc', 'Close this overlay'],
    ];

    const overlay = document.createElement('div');
    overlay.id = 'cheatsheet-overlay';
    overlay.innerHTML = `
        <div class="cheatsheet-panel">
            <h3>⌨️ Keyboard Shortcuts</h3>
            <table>
                ${shortcuts.map(([key, desc]) =>
        `<tr><td><kbd>${key}</kbd></td><td>${desc}</td></tr>`
    ).join('')}
            </table>
            <p class="cheatsheet-hint">Press <kbd>?</kbd> or <kbd>Esc</kbd> to close</p>
        </div>
    `;
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) overlay.remove();
    });
    document.body.appendChild(overlay);
}

function closeCheatSheet() {
    const overlay = document.getElementById('cheatsheet-overlay');
    if (overlay) overlay.remove();
}

// ─── Config Presets ─────────────────────────────────────────────────────────────

const CONFIG_PRESETS = {
    low: { lsbBits: 1, opacity: 0.3, signRateMs: 2000, label: 'Low (stealth)' },
    medium: { lsbBits: 2, opacity: 0.7, signRateMs: 1000, label: 'Medium (balanced)' },
    high: { lsbBits: 4, opacity: 1.0, signRateMs: 500, label: 'High (maximum)' },
};

function applyConfigPreset(presetName) {
    const preset = CONFIG_PRESETS[presetName];
    if (!preset) return;

    liveConfig.lsbBits = preset.lsbBits;
    liveConfig.opacity = preset.opacity;
    liveConfig.signRateMs = preset.signRateMs;

    // Update UI controls
    if (el.cfgLsbBits) { el.cfgLsbBits.value = preset.lsbBits; }
    if (el.cfgLsbBitsVal) { el.cfgLsbBitsVal.textContent = preset.lsbBits; }
    if (el.cfgOpacity) { el.cfgOpacity.value = preset.opacity; }
    if (el.cfgOpacityVal) { el.cfgOpacityVal.textContent = preset.opacity.toFixed(1); }
    if (el.cfgSignRate) { el.cfgSignRate.value = preset.signRateMs; }
    if (el.cfgSignRateVal) { el.cfgSignRateVal.textContent = preset.signRateMs + 'ms'; }

    updateStegoInfo();
    pushConfigToServer();
    showToast(`Preset applied: ${preset.label}`, 'success');

    // Highlight active preset button
    document.querySelectorAll('.preset-btn').forEach(b => b.classList.remove('active'));
    const activeBtn = document.querySelector(`.preset-btn[data-preset="${presetName}"]`);
    if (activeBtn) activeBtn.classList.add('active');
}

// Initialize preset buttons if present in DOM
function initPresetButtons() {
    document.querySelectorAll('.preset-btn').forEach(btn => {
        btn.addEventListener('click', () => applyConfigPreset(btn.dataset.preset));
    });
}

document.readyState === 'loading' ? document.addEventListener('DOMContentLoaded', init) : init();

