/** Dashboard client: lossless signed artifacts, explicit lifecycle and server-reported verification. */
'use strict';
const WS_RECONNECT_DELAY_MS = 2000;
const DECODE_POLL_INTERVAL_MS = 300;
const TRANSPORT_STORAGE_KEY = 'stego-transport';
const WEBRTC_CHUNK_MAGIC = 0x5354474f;
const WEBRTC_CHUNK_HEADER_BYTES = 20;
const WEBRTC_CHUNK_PAYLOAD_MAX = 16384 - WEBRTC_CHUNK_HEADER_BYTES;
// The server bounds the complete UTF-8 JSON message, not the decoded PNG.
const WEBRTC_MESSAGE_MAX_BYTES = 4 * 1024 * 1024;
const SESSION_START = new Date();
const $ = id => document.getElementById(id);
function ingestAuthToken() {
    const url = new URL(location.href), token = url.searchParams.get('token');
    if (token) sessionStorage.setItem('auth_token', token);
    if (url.searchParams.has('token')) { url.searchParams.delete('token'); history.replaceState(null, '', url); }
}
function authHeaders() {
    const token = sessionStorage.getItem('auth_token');
    return token ? { Authorization: 'Bearer ' + token } : {};
}
function wsUrl(path) {
    const token = sessionStorage.getItem('auth_token');
    return `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}${path}${token ? '?token=' + encodeURIComponent(token) : ''}`;
}
function showToast(message, type = 'info') {
    let container = $('toast-container');
    if (!container) { container = document.createElement('div'); container.id = 'toast-container'; document.body.append(container); }
    const toast = document.createElement('div');
    toast.className = 'toast toast-' + type; toast.textContent = message; container.append(toast);
    requestAnimationFrame(() => toast.classList.add('show'));
    setTimeout(() => toast.remove(), 5000);
}
function fmtNum(n) { return Number(n).toLocaleString(); }
function fmtUptime(s) { return `${Math.floor(Number(s) / 60)}m ${Math.floor(Number(s) % 60)}s`; }
function truncateIdentity(s) { return s && s.length > 20 ? s.slice(0, 10) + '…' + s.slice(-8) : s || '—'; }
function bytesToChunks(bytes) {
    let text = '';
    for (let i = 0; i < bytes.length; i += 0x8000) text += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return text;
}
function downloadBlob(blob, name) {
    const url = URL.createObjectURL(blob), a = document.createElement('a');
    a.href = url; a.download = name; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
}

// Stored ZIP: no recompression or re-encoding of the signed carrier bytes.
const ARCHIVE_MAX_BYTES = 64 * 1024 * 1024;
const ARCHIVE_MAX_ENTRIES = 300;
const archiveEncoder = new TextEncoder();
const archiveCrcTable = new Uint32Array(256);
for (let n = 0; n < 256; n++) {
    let crc = n;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    archiveCrcTable[n] = crc >>> 0;
}
function archiveCrc(bytes) {
    let crc = 0xffffffff;
    for (const byte of bytes) crc = (crc >>> 8) ^ archiveCrcTable[(crc ^ byte) & 255];
    return (crc ^ 0xffffffff) >>> 0;
}
function decodeArchiveBase64(text) {
    if (typeof text !== 'string' || text.length > 24 * 1024 * 1024) throw new Error('Media exceeds client byte limit');
    return Uint8Array.from(atob(text), char => char.charCodeAt(0));
}
function storedZip(files) {
    const body = [], directory = [];
    let offset = 0, directorySize = 0;
    for (const file of files) {
        const name = archiveEncoder.encode(file.name), bytes = file.bytes, crc = archiveCrc(bytes);
        const local = new Uint8Array(30 + name.length), l = new DataView(local.buffer);
        l.setUint32(0, 0x04034b50, true); l.setUint16(4, 20, true); l.setUint16(6, 0x800, true);
        l.setUint16(12, 33, true); // DOS date: 1980-01-01.
        l.setUint32(14, crc, true); l.setUint32(18, bytes.length, true); l.setUint32(22, bytes.length, true);
        l.setUint16(26, name.length, true); local.set(name, 30);
        const central = new Uint8Array(46 + name.length), c = new DataView(central.buffer);
        c.setUint32(0, 0x02014b50, true); c.setUint16(4, 20, true); c.setUint16(6, 20, true);
        c.setUint16(14, 33, true);
        c.setUint16(8, 0x800, true); c.setUint32(16, crc, true); c.setUint32(20, bytes.length, true);
        c.setUint32(24, bytes.length, true); c.setUint16(28, name.length, true); c.setUint32(42, offset, true);
        central.set(name, 46); body.push(local, bytes); directory.push(central);
        offset += local.length + bytes.length; directorySize += central.length;
    }
    const end = new Uint8Array(22), e = new DataView(end.buffer);
    e.setUint32(0, 0x06054b50, true); e.setUint16(8, files.length, true); e.setUint16(10, files.length, true);
    e.setUint32(12, directorySize, true); e.setUint32(16, offset, true);
    return new Blob([...body, ...directory, end], { type: 'application/zip' });
}
function createSignedArchive(media) {
    if (!serverVersion) throw new Error('Server version is not loaded; wait for dashboard initialization before recording');
    const entries = [], files = [], seen = new Set(), created = new Date().toISOString();
    let used = 0, finished = false;
    return {
        entries,
        add(name, bytes, metadata) {
            if (finished) return false;
            if (seen.has(name)) return true;
            if (!(bytes instanceof Uint8Array) || !/^[\da-f]{64}$/i.test(metadata.public_key || '') ||
                metadata.frame_index == null || !Number.isInteger(metadata.lsb_bits)) throw new Error('Missing signed artifact metadata');
            const meta = { ...metadata, file: name, bytes: bytes.length };
            const cost = bytes.length + archiveEncoder.encode(JSON.stringify(meta, null, 2)).length + name.length * 2 + 512;
            if (entries.length >= ARCHIVE_MAX_ENTRIES || used + cost > ARCHIVE_MAX_BYTES - 65536) return false;
            files.push({ name, bytes }); entries.push(meta); seen.add(name); used += cost;
            return true;
        },
        finish() {
            if (finished) return false;
            if (!entries.length) { showToast('No signed artifacts received during recording', 'error'); return false; }
            const manifest = {
                format: 'steganographer-signed-media', format_version: 1, media,
                steganographer_version: serverVersion, created_at: created,
                recording: 'Sampled signed artifacts only; capture gaps are not filled or authenticated.',
                verification: 'Server results do not independently verify this archive. Verify unchanged carriers with each listed public key and extraction metadata.',
                entries,
            };
            const zip = storedZip([...files, { name: 'manifest.json', bytes: archiveEncoder.encode(JSON.stringify(manifest, null, 2)) }]);
            if (zip.size > ARCHIVE_MAX_BYTES) throw new Error('Archive exceeds byte limit');
            downloadBlob(zip, `steganographer-${media}-${created.replace(/[:.]/g, '-')}.zip`);
            finished = true;
            files.length = 0;
            return true;
        },
    };
}
function pcmWav(pcm, sampleRate, channels) {
    if (!Number.isInteger(sampleRate) || sampleRate < 1 || !Number.isInteger(channels) || channels < 1 ||
        channels > 8 || pcm.length % (channels * 2)) throw new Error('Invalid signed PCM format');
    const bytes = new Uint8Array(44 + pcm.length), v = new DataView(bytes.buffer);
    const text = (offset, s) => bytes.set(archiveEncoder.encode(s), offset);
    text(0, 'RIFF'); v.setUint32(4, 36 + pcm.length, true); text(8, 'WAVE'); text(12, 'fmt ');
    v.setUint32(16, 16, true); v.setUint16(20, 1, true); v.setUint16(22, channels, true);
    v.setUint32(24, sampleRate, true); v.setUint32(28, sampleRate * channels * 2, true);
    v.setUint16(32, channels * 2, true); v.setUint16(34, 16, true); text(36, 'data');
    v.setUint32(40, pcm.length, true); bytes.set(pcm, 44);
    return bytes;
}
window.SignedArchive = { create: createSignedArchive, decodeBase64: decodeArchiveBase64, wav: pcmWav };

let serverVersion = null, serverTransport = 'websocket', rawMetrics = {};
let configHydrated = false, configSaving = false, configPending = false;
let liveConfig = {};
const configFields = { opacity: 'opacity', lsb_bits: 'lsbBits', signing_backend: 'signingBackend',
    overlay_text: 'overlayText', sign_rate_ms: 'signRateMs', qr_scale: 'qrScale', resolution: 'resolution',
    stego_type: 'stegoType', hash_algorithm: 'hashAlgorithm', encrypt: 'encrypt', ecc: 'ecc', transport: 'transport' };
function configWireSnapshot() {
    return Object.fromEntries(Object.entries(configFields).map(([wire, local]) => [wire, liveConfig[local]]));
}
function renderConfigControls() {
    $('cfg-opacity').value = liveConfig.opacity * 100; $('cfg-opacity-val').textContent = liveConfig.opacity.toFixed(2);
    $('encode-canvas').style.opacity = String(liveConfig.opacity);
    $('cfg-lsb-bits').value = liveConfig.lsbBits; $('cfg-lsb-bits-val').textContent = liveConfig.lsbBits;
    $('cfg-sign-rate').value = liveConfig.signRateMs; $('cfg-sign-rate-val').textContent = (1000 / liveConfig.signRateMs).toFixed(1) + '/s';
    $('cfg-qr-scale').value = liveConfig.qrScale; $('cfg-qr-scale-val').textContent = liveConfig.qrScale + '%';
    $('cfg-overlay-text').value = liveConfig.overlayText;
    if (![...$('cfg-resolution').options].some(o => o.value === liveConfig.resolution)) $('cfg-resolution').add(new Option(liveConfig.resolution, liveConfig.resolution));
    $('cfg-resolution').value = liveConfig.resolution;
    $('signing-backend').value = $('cfg-sign-backend').value = liveConfig.signingBackend;
    const [w, h] = liveConfig.resolution.split('x').map(Number), capacity = w * h * 3 * liveConfig.lsbBits;
    $('info-payload-size').textContent = '109 bytes'; $('info-hash-algo').textContent = 'BLAKE3 (256-bit)';
    $('info-sig-algo').textContent = 'Ed25519 (512-bit)'; $('info-capacity').textContent = fmtNum(Math.floor(capacity / 8)) + ' B';
    $('info-utilization').textContent = (87200 / capacity).toFixed(3) + '%';
    if (cameraActive) startSigningInterval();
}
async function fetchConfig() {
    const response = await fetch('/api/config', { headers: authHeaders(), signal: AbortSignal.timeout(5000) });
    if (!response.ok) throw new Error(`Config HTTP ${response.status}`);
    const config = await response.json();
    for (const [wire, local] of Object.entries(configFields)) {
        if (config[wire] === undefined) throw new Error('Incomplete server config: ' + wire);
        liveConfig[local] = config[wire];
    }
    serverTransport = config.default_transport || config.transport;
    $('identity-value').textContent = truncateIdentity(config.public_key || config.identity);
    $('identity-value').title = config.public_key || config.identity;
    $('footer-backend-value').textContent = config.signing_backend;
    renderConfigControls(); configHydrated = true;
}
async function pushConfigToServer() {
    if (!configHydrated) return;
    configPending = true;
    if (configSaving) return;
    configSaving = true;
    try {
        while (configPending) {
            configPending = false;
            const response = await fetch('/api/config', { method: 'POST',
                headers: { 'Content-Type': 'application/json', ...authHeaders() }, body: JSON.stringify(configWireSnapshot()) });
            if (!response.ok) throw new Error(await response.text());
        }
        showToast('Config saved', 'success');
    } catch (err) { showToast('Config not saved: ' + err.message, 'error'); }
    finally { configSaving = false; }
}
const CONFIG_PRESETS = {
    low: { lsbBits: 1, opacity: 0.3, signRateMs: 2000 },
    medium: { lsbBits: 2, opacity: 0.7, signRateMs: 1000 },
    high: { lsbBits: 4, opacity: 1, signRateMs: 500 },
};
function applyConfigPreset(name) {
    if (!configHydrated || !CONFIG_PRESETS[name]) return;
    Object.assign(liveConfig, CONFIG_PRESETS[name]); renderConfigControls(); pushConfigToServer();
    document.querySelectorAll('.preset-btn').forEach(button => button.classList.toggle('active', button.dataset.preset === name));
}
function setupConfigControls() {
    const bind = (id, field, convert, event = 'input') => $(id).addEventListener(event, () => {
        liveConfig[field] = convert($(id).value); renderConfigControls(); pushConfigToServer();
    });
    bind('cfg-opacity', 'opacity', value => Number(value) / 100);
    bind('cfg-lsb-bits', 'lsbBits', Number);
    bind('cfg-sign-rate', 'signRateMs', Number);
    $('cfg-resolution').addEventListener('change', () => {
        liveConfig.resolution = $('cfg-resolution').value; renderConfigControls(); pushConfigToServer();
        if (cameraActive) startCamera();
    });
    document.querySelectorAll('.preset-btn').forEach(button => button.addEventListener('click', () => applyConfigPreset(button.dataset.preset)));
}

// One camera session owns every track, socket, interval and pending operation.
let cameraActive = false, webcamStream = null, cameraGeneration = 0, transportGeneration = 0;
let signInterval = null, pendingVideoSign = null, videoEncodeGeneration = 0;
let encodeWs = null, decodeWs = null, transport = null, transportFallback = false;
let webrtcPc = null, webrtcDc = null, webrtcPollTimer = null, webrtcMsgId = 0;
const wsReconnectTimers = new Set(), socketIntervals = new Set(), webrtcPartial = new Map();
let latestVideoFrame = null, lastVideoVerificationId = null, lastVerifyData = { verified: null };
let diffViewerEnabled = false, diffOverlayEnabled = true, lastOriginalFrameData = null, lastWatermarkedFrameData = null;
let videoRecording = false, videoArchive = null, videoArchiveGeneration = 0;
function clearVideoVerification(text = 'Waiting for a signed frame') {
    lastVerifyData = { verified: null, status: text };
    $('verify-waiting').classList.add('hidden'); $('verify-result').classList.remove('hidden');
    $('verify-status-banner').className = 'verify-status-banner status-pending';
    $('verify-status-icon').textContent = '…'; $('verify-status-text').textContent = text;
    ['field-frame-index', 'field-hash', 'field-sig-preview', 'field-backend', 'field-verify-latency'].forEach(id => { $(id).textContent = '—'; $(id).title = ''; });
}
function clearSigningRequest(request = pendingVideoSign) {
    if (request !== pendingVideoSign) return;
    if (request) clearTimeout(request.timeout);
    pendingVideoSign = null;
    $('sign-indicator').classList.add('hidden');
}
function invalidateVideoTarget(text) {
    ++videoEncodeGeneration;
    latestVideoFrame = null;
    clearVideoVerification(text);
}
function updateConnectionStatus(connected, label) {
    $('status-dot').classList.toggle('connected', connected); $('status-dot').classList.toggle('disconnected', !connected);
    $('status-text').textContent = label || (connected ? 'Connected' : 'Reconnecting…');
}
function teardownWebRtcTransport() {
    clearInterval(webrtcPollTimer); webrtcPollTimer = null;
    if (webrtcDc) { webrtcDc.onclose = webrtcDc.onerror = webrtcDc.onmessage = null; webrtcDc.close(); webrtcDc = null; }
    if (webrtcPc) { webrtcPc.onconnectionstatechange = null; webrtcPc.close(); webrtcPc = null; }
    webrtcPartial.clear();
}
function stopTransport() {
    ++transportGeneration;
    wsReconnectTimers.forEach(clearTimeout); wsReconnectTimers.clear();
    socketIntervals.forEach(clearInterval); socketIntervals.clear();
    for (const socket of [encodeWs, decodeWs]) {
        if (socket) { socket.onopen = socket.onclose = socket.onerror = socket.onmessage = null; socket.close(); }
    }
    encodeWs = decodeWs = null; teardownWebRtcTransport(); transport = null; clearSigningRequest();
    updateConnectionStatus(false, 'Stopped');
    invalidateVideoTarget('Transport stopped — previous results are historical');
}
function stopCamera() {
    ++cameraGeneration; cameraActive = false; clearInterval(signInterval); signInterval = null;
    if (webcamStream) webcamStream.getTracks().forEach(track => track.stop());
    webcamStream = null; $('webcam-video').srcObject = null; stopTransport();
    latestVideoFrame = null; lastVideoVerificationId = null; lastOriginalFrameData = lastWatermarkedFrameData = null;
    if (videoRecording) toggleVideoRecording();
    $('encode-overlay').classList.remove('hidden'); $('encode-overlay').querySelector('.overlay-text').textContent = 'Camera stopped';
    $('encode-overlay').querySelector('.overlay-subtext').textContent = 'Start camera to resume signed snapshots';
    $('stop-camera-btn').disabled = true; clearVideoVerification('Stopped — previous results are historical');
}
async function startCamera() {
    if (!configHydrated) return;
    stopCamera(); const generation = cameraGeneration;
    const [width, height] = liveConfig.resolution.split('x').map(Number);
    const video = { width: { ideal: width }, height: { ideal: height } };
    if ($('camera-select').value) video.deviceId = { exact: $('camera-select').value };
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ video, audio: false });
        if (generation !== cameraGeneration) { stream.getTracks().forEach(track => track.stop()); return; }
        webcamStream = stream; $('webcam-video').srcObject = stream; await $('webcam-video').play();
        if (generation !== cameraGeneration) return;
        cameraActive = true; $('encode-overlay').classList.add('hidden'); $('stop-camera-btn').disabled = false;
        $('encode-canvas').getContext('2d').clearRect(0, 0, $('encode-canvas').width, $('encode-canvas').height);
        clearVideoVerification(); transportFallback = false; connectTransport(); startSigningInterval(); enumerateCameras();
    } catch (err) {
        if (generation !== cameraGeneration) return;
        stopCamera(); $('encode-overlay').querySelector('.overlay-text').textContent = 'Camera unavailable';
        $('encode-overlay').querySelector('.overlay-subtext').textContent = err.message || 'Try starting again';
    }
}
async function enumerateCameras() {
    try {
        const selected = $('camera-select').value, devices = await navigator.mediaDevices.enumerateDevices();
        $('camera-select').replaceChildren(new Option('Default camera', ''));
        devices.filter(device => device.kind === 'videoinput').forEach((device, index) => $('camera-select').add(new Option(device.label || `Camera ${index + 1}`, device.deviceId)));
        $('camera-select').value = selected;
    } catch (_) { /* Camera permission can be requested with the default device. */ }
}
function startSigningInterval() { clearInterval(signInterval); signInterval = setInterval(sendFrameForSigning, liveConfig.signRateMs); }
function transportIsConnected() { return transport === 'webrtc' ? webrtcDc?.readyState === 'open' : encodeWs?.readyState === WebSocket.OPEN; }
function sendFrameForSigning() {
    const video = $('webcam-video');
    if (!cameraActive || pendingVideoSign || !transportIsConnected() || video.readyState < 2) return;
    const canvas = document.createElement('canvas'); canvas.width = video.videoWidth; canvas.height = video.videoHeight;
    const ctx = canvas.getContext('2d'); ctx.drawImage(video, 0, 0);
    const request = {
        cameraGeneration, transportGeneration, encodeGeneration: videoEncodeGeneration,
        original: diffViewerEnabled ? ctx.getImageData(0, 0, canvas.width, canvas.height) : null,
        archive: videoRecording ? videoArchive : null, archiveGeneration: videoArchiveGeneration,
        rtcId: null, replyReceived: false, timeout: null,
    };
    pendingVideoSign = request;
    const current = () => cameraActive && pendingVideoSign === request &&
        request.cameraGeneration === cameraGeneration && request.transportGeneration === transportGeneration &&
        request.encodeGeneration === videoEncodeGeneration;
    $('sign-indicator').classList.remove('hidden');
    request.timeout = setTimeout(() => {
        if (!current()) return;
        showToast('Signing timed out — reconnecting transport', 'error'); stopTransport(); if (cameraActive) connectTransport();
    }, 10000);
    // PNG input avoids JPEG motion/quantization being mislabeled as embedding differences.
    canvas.toBlob(async blob => {
        if (!current()) return;
        try {
            if (!blob || blob.size > 4 * 1024 * 1024) throw new Error('Frame exceeds 4 MiB; choose a smaller resolution');
            const bytes = await blob.arrayBuffer(); if (!current()) return;
            if (!transportIsConnected()) throw new Error('Signing transport disconnected');
            if (transport === 'webrtc') {
                request.rtcId = ++webrtcMsgId;
                webRtcSendChunked(request.rtcId, new TextEncoder().encode(JSON.stringify({
                    kind: 'encode', msg_id: request.rtcId, sent_unix_ms: Date.now(), jpeg_b64: btoa(bytesToChunks(new Uint8Array(bytes))),
                })));
            } else encodeWs.send(bytes);
        } catch (err) { if (current()) { clearSigningRequest(request); showToast(err.message, 'error'); } }
    }, 'image/png');
}
function connectVideoSocket(kind) {
    if (!cameraActive) return;
    const generation = transportGeneration, socket = new WebSocket(wsUrl('/ws/' + kind));
    if (kind === 'encode') encodeWs = socket; else decodeWs = socket;
    if (kind === 'encode') {
        clearSigningRequest();
        invalidateVideoTarget('Encode connected anew — waiting for a new signed frame; previous results are historical');
    }
    let pollTimer = null;
    const current = () => cameraActive && generation === transportGeneration && socket === (kind === 'encode' ? encodeWs : decodeWs);
    socket.onopen = () => {
        if (!current()) return socket.close();
        if (kind === 'encode') { clearSigningRequest(); updateConnectionStatus(true, 'Connected (WebSocket)'); }
        else {
            pollTimer = setInterval(() => { if (socket.readyState === WebSocket.OPEN) socket.send('poll'); }, DECODE_POLL_INTERVAL_MS);
            socketIntervals.add(pollTimer);
        }
    };
    socket.onmessage = event => {
        if (!current()) return;
        try { const msg = JSON.parse(event.data); if (kind === 'encode') handleEncodeMessage(msg); else handleDecodeMessage(msg); }
        catch (_) {
            if (kind === 'encode') clearSigningRequest();
            else clearVideoVerification('Invalid verification reply — no current verdict');
        }
    };
    socket.onclose = () => {
        clearInterval(pollTimer); socketIntervals.delete(pollTimer);
        if (!current()) return;
        if (kind === 'encode') {
            clearSigningRequest();
            invalidateVideoTarget('Encode disconnected — previous results are historical');
            updateConnectionStatus(false);
        } else clearVideoVerification('Verification channel disconnected — no current verdict');
        const timer = setTimeout(() => { wsReconnectTimers.delete(timer); if (current()) connectVideoSocket(kind); }, WS_RECONNECT_DELAY_MS);
        wsReconnectTimers.add(timer);
    };
    socket.onerror = () => socket.close();
}
function resolveTransportPreference() {
    const query = new URL(location.href).searchParams.get('transport');
    if (['auto', 'websocket', 'webrtc'].includes(query)) return query;
    const saved = localStorage.getItem(TRANSPORT_STORAGE_KEY);
    return ['auto', 'websocket', 'webrtc'].includes(saved) ? saved : serverTransport;
}
function connectWsTransport() { transport = 'websocket'; connectVideoSocket('encode'); connectVideoSocket('decode'); }
function connectTransport() {
    const preference = resolveTransportPreference();
    if (preference === 'webrtc' || (preference === 'auto' && !transportFallback)) connectWebRtcTransport();
    else connectWsTransport();
}
function fallbackToWs(reason) {
    ++transportGeneration;
    teardownWebRtcTransport(); clearSigningRequest();
    invalidateVideoTarget('Transport changed — previous results are historical');
    if (!cameraActive) return;
    if (resolveTransportPreference() !== 'auto') {
        transport = null; updateConnectionStatus(false, 'Pinned WebRTC unavailable');
        clearVideoVerification('WebRTC unavailable — no fallback in pinned mode'); showToast(String(reason), 'error'); return;
    }
    transportFallback = true;
    if (transport !== 'websocket') connectWsTransport();
}
function parseIceServersForBrowser(urls) {
    return urls.flatMap(url => {
        if (!/^turns?:|^stuns?:/.test(url)) return [];
        const match = url.match(/^(turns?):([^:]+):([^@]+)@(.+)$/);
        return [match ? { urls: match[1] + ':' + match[4], username: match[2], credential: match[3] } : { urls: url }];
    });
}
async function connectWebRtcTransport() {
    invalidateVideoTarget('WebRTC connecting — waiting for a new signed frame; previous results are historical');
    const generation = transportGeneration, current = () => cameraActive && generation === transportGeneration;
    let pc = null, answerTimer = null;
    try {
        const configResponse = await fetch('/api/webrtc/config', { headers: authHeaders(), signal: AbortSignal.timeout(5000) });
        if (!configResponse.ok) throw new Error(`WebRTC config HTTP ${configResponse.status}`);
        const config = await configResponse.json(); if (!current()) return;
        pc = new RTCPeerConnection({ iceServers: parseIceServersForBrowser(config.ice_servers || []) }); webrtcPc = pc;
        const dc = pc.createDataChannel('frames', { ordered: true }); webrtcDc = dc; dc.binaryType = 'arraybuffer';
        dc.onmessage = event => { if (current()) handleWebRtcMessage(event.data); };
        const opened = new Promise((resolve, reject) => {
            answerTimer = setTimeout(() => reject(new Error('WebRTC connection timed out')), 10000);
            dc.onopen = resolve; dc.onclose = dc.onerror = () => reject(new Error('WebRTC closed before opening'));
        });
        // Keep early rejection handled while signaling is still pending.
        opened.catch(() => {});
        await pc.setLocalDescription(await pc.createOffer());
        if (pc.iceGatheringState !== 'complete') await new Promise(resolve => {
            const done = () => { clearTimeout(timer); pc.removeEventListener('icegatheringstatechange', changed); resolve(); };
            const changed = () => { if (pc.iceGatheringState === 'complete') done(); };
            const timer = setTimeout(done, 1000); pc.addEventListener('icegatheringstatechange', changed);
        });
        if (!current()) { pc.close(); return; }
        const response = await fetch('/api/webrtc/offer', { method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() },
            body: JSON.stringify({ sdp: pc.localDescription.sdp, type: 'offer' }), signal: AbortSignal.timeout(5000) });
        if (!response.ok) throw new Error(`WebRTC offer HTTP ${response.status}`);
        const answer = await response.json(); if (!current()) { pc.close(); return; }
        await pc.setRemoteDescription({ type: 'answer', sdp: answer.sdp }); await opened;
        if (!current()) { pc.close(); return; }
        dc.onclose = () => { if (current()) fallbackToWs('WebRTC channel closed'); };
        dc.onerror = () => { if (current()) fallbackToWs('WebRTC channel failed'); };
        pc.onconnectionstatechange = () => { if (current() && ['failed', 'disconnected'].includes(pc.connectionState)) fallbackToWs('WebRTC disconnected'); };
        transport = 'webrtc'; updateConnectionStatus(true, 'Connected (WebRTC)');
        webrtcPollTimer = setInterval(() => { if (dc.readyState === 'open') dc.send(JSON.stringify({ kind: 'decode_poll', msg_id: ++webrtcMsgId })); }, DECODE_POLL_INTERVAL_MS);
    } catch (err) { if (current()) fallbackToWs(err.message); else pc?.close(); }
    finally { clearTimeout(answerTimer); }
}
function webRtcSendChunked(id, bytes) {
    if (bytes.byteLength > WEBRTC_MESSAGE_MAX_BYTES) {
        throw new Error(`WebRTC transport limit: serialized request is ${fmtNum(bytes.byteLength)} bytes; maximum is ${fmtNum(WEBRTC_MESSAGE_MAX_BYTES)} bytes including JSON/base64. Choose a smaller camera resolution or select WebSocket transport.`);
    }
    const count = Math.max(1, Math.ceil(bytes.length / WEBRTC_CHUNK_PAYLOAD_MAX));
    for (let index = 0; index < count; index++) {
        const slice = bytes.subarray(index * WEBRTC_CHUNK_PAYLOAD_MAX, (index + 1) * WEBRTC_CHUNK_PAYLOAD_MAX);
        const chunk = new Uint8Array(20 + slice.length), view = new DataView(chunk.buffer);
        view.setUint32(0, WEBRTC_CHUNK_MAGIC); view.setBigUint64(4, BigInt(id));
        view.setUint32(12, index); view.setUint32(16, count); chunk.set(slice, 20); webrtcDc.send(chunk);
    }
}
function handleWebRtcMessage(data) {
    let payload = data;
    if (typeof data !== 'string') {
        const bytes = new Uint8Array(data); if (bytes.length < 20) return;
        const view = new DataView(bytes.buffer), id = view.getBigUint64(4), index = view.getUint32(12), count = view.getUint32(16);
        if (view.getUint32(0) !== WEBRTC_CHUNK_MAGIC || !count || count > 1024 || index >= count) return;
        const now = Date.now();
        for (const [key, part] of webrtcPartial) if (now - part.created > 10000) webrtcPartial.delete(key);
        if (!webrtcPartial.has(id) && webrtcPartial.size >= 4) return;
        const part = webrtcPartial.get(id) || { chunks: new Array(count), received: 0, bytes: 0, created: now };
        if (part.chunks.length !== count) { webrtcPartial.delete(id); return; }
        if (!part.chunks[index]) { part.chunks[index] = bytes.slice(20); part.received++; part.bytes += bytes.length - 20; }
        if (part.bytes > 16 * 1024 * 1024) { webrtcPartial.delete(id); return; }
        if (part.received !== count) { webrtcPartial.set(id, part); return; }
        webrtcPartial.delete(id); const joined = new Uint8Array(part.bytes); let offset = 0;
        for (const chunk of part.chunks) { joined.set(chunk, offset); offset += chunk.length; }
        payload = new TextDecoder().decode(joined);
    }
    try {
        const msg = JSON.parse(payload);
        if (['encoded_frame', 'metrics', 'error', 'encode_error'].includes(msg.type) &&
            pendingVideoSign?.rtcId === msg.msg_id) handleEncodeMessage(msg);
        else handleDecodeMessage(msg);
    } catch (_) { clearVideoVerification('Invalid transport reply — no current verdict'); }
}
async function handleEncodeMessage(msg) {
    if (msg.ots) window.OtsPanel?.applyMetrics(msg.ots);
    if (msg.data) applyMetrics(msg.data);
    if (['error', 'encode_error'].includes(msg.type)) {
        if (!pendingVideoSign) return;
        clearSigningRequest(); clearVideoVerification('Encoding failed — no new signed frame');
        showToast(msg.message || msg.error || 'Encoding failed', 'error'); return;
    }
    if (msg.type !== 'encoded_frame' || !cameraActive || !pendingVideoSign || pendingVideoSign.replyReceived) return;
    const request = pendingVideoSign, original = request.original;
    request.replyReceived = true;
    const current = () => cameraActive && pendingVideoSign === request &&
        request.cameraGeneration === cameraGeneration && request.transportGeneration === transportGeneration &&
        request.encodeGeneration === videoEncodeGeneration;
    try {
        if (msg.image_mime !== 'image/png' || !msg.frame || !/^[\da-f]{64}$/i.test(msg.public_key || '') ||
            msg.frame_index == null || msg.cache_revision == null || !Number.isInteger(msg.lsb_bits)) throw new Error('Server did not return lossless signed media with extraction metadata');
        const bytes = decodeArchiveBase64(msg.frame), image = await createImageBitmap(new Blob([bytes], { type: 'image/png' }));
        if (!current()) { image.close(); return; }
        const canvas = $('encode-canvas'); canvas.width = image.width; canvas.height = image.height;
        canvas.getContext('2d').drawImage(image, 0, 0); image.close();
        latestVideoFrame = { cameraGeneration, transportGeneration, encodeGeneration: videoEncodeGeneration,
            frame_index: msg.frame_index, cache_revision: msg.cache_revision,
            public_key: msg.public_key, lsb_bits: msg.lsb_bits, stego_type: 'video', kernel: 'lsb', signing_backend: 'ed25519',
            width: msg.width, height: msg.height, payload: msg.payload, media_digest: msg.media_digest, received_at: new Date().toISOString() };
        $('identity-value').textContent = truncateIdentity(msg.public_key); $('identity-value').title = msg.public_key;
        $('footer-resolution-value').textContent = `${msg.width}×${msg.height}`;
        clearVideoVerification('Signed frame received — server verification pending');
        if (videoRecording && request.archive === videoArchive && request.archiveGeneration === videoArchiveGeneration &&
            !request.archive.add(`frame-${msg.frame_index}-revision-${msg.cache_revision}.png`, bytes, latestVideoFrame)) {
            showToast('Recording limit reached (64 MiB / 300 frames); archive stopped before next frame', 'error'); toggleVideoRecording();
        }
        if (diffViewerEnabled && original && original.width === canvas.width && original.height === canvas.height) {
            lastOriginalFrameData = original; lastWatermarkedFrameData = canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height); renderDiffViewer();
        }
        window.OtsPanel?.refreshStatus();
    } catch (err) {
        if (current()) {
            clearVideoVerification('Signed artifact unavailable'); showToast(err.message, 'error');
        }
    }
    finally { if (current()) clearSigningRequest(request); }
}
function handleDecodeMessage(msg) {
    if (msg.ots) window.OtsPanel?.applyMetrics(msg.ots); if (msg.data) applyMetrics(msg.data);
    if (!cameraActive) return;
    if (msg.type === 'error') { clearVideoVerification('Verification failed — no current verdict'); return; }
    if (msg.waiting || msg.verified_stale || msg.payload?.stale) { clearVideoVerification(msg.waiting ? 'Waiting for signed media' : 'Server verification pending'); return; }
    if (msg.type !== 'decoded_frame') return;
    if (typeof msg.verified !== 'boolean') { clearVideoVerification('Server verification pending'); return; }
    const id = msg.frame_index ?? msg.payload?.frame_index;
    if (!latestVideoFrame || latestVideoFrame.cameraGeneration !== cameraGeneration ||
        latestVideoFrame.transportGeneration !== transportGeneration || latestVideoFrame.encodeGeneration !== videoEncodeGeneration ||
        msg.cache_revision == null ||
        String(msg.cache_revision) !== String(latestVideoFrame.cache_revision) || String(id) !== String(latestVideoFrame.frame_index)) return;
    lastVerifyData = { frame_index: id, cache_revision: msg.cache_revision, verified: msg.verified, hash: msg.payload?.hash, backend: msg.backend, verify_us: msg.verify_us };
    $('verify-waiting').classList.add('hidden'); $('verify-result').classList.remove('hidden');
    $('verify-status-banner').className = 'verify-status-banner ' + (msg.verified ? 'status-ok' : 'status-fail');
    $('verify-status-icon').textContent = msg.verified ? '✅' : '❌';
    $('verify-status-text').textContent = msg.verified ? 'Server verified this signed frame' : 'Server verification INVALID';
    $('field-frame-index').textContent = id; $('field-hash').textContent = truncateIdentity(msg.payload?.hash); $('field-hash').title = msg.payload?.hash || '';
    $('field-sig-preview').textContent = msg.payload?.signature_preview || '—'; $('field-sig-preview').title = msg.payload?.signature_full || '';
    $('field-backend').textContent = msg.backend || 'ed25519'; $('field-verify-latency').textContent = `${msg.verify_us || 0} μs`;
    if (lastVideoVerificationId !== String(msg.cache_revision)) {
        const entry = document.createElement('div'); entry.className = 'log-entry ' + (msg.verified ? 'log-ok' : 'log-fail');
        entry.textContent = `History · ${new Date().toLocaleTimeString()}  #${id}  ${msg.verified ? 'OK' : 'INVALID'} · ${msg.verify_us || 0} μs`;
        entry.title = 'Historical server-reported result, not the current encode target or independent archive verification.';
        $('verify-log').prepend(entry); while ($('verify-log').children.length > 20) $('verify-log').lastChild.remove();
        lastVideoVerificationId = String(msg.cache_revision);
    }
}
function toggleVideoRecording() {
    if (videoRecording || videoArchive) {
        videoRecording = false;
        $('record-video-btn').classList.remove('recording');
        try {
            if (!videoArchive.entries.length || videoArchive.finish()) videoArchive = null;
        } catch (err) { showToast('Archive export failed: ' + err.message + ' — click Export archive to retry', 'error'); }
        $('record-video-label').textContent = videoArchive ? 'Export archive' : 'Record';
        return;
    }
    if (!cameraActive) { showToast('Start camera before recording signed snapshots', 'error'); return; }
    if (!serverVersion) { showToast('Wait for dashboard initialization before recording', 'error'); return; }
    videoArchive = createSignedArchive('video');
    ++videoArchiveGeneration;
    videoRecording = true;
    $('record-video-btn').classList.add('recording');
    $('record-video-label').textContent = 'Stop & save ZIP';
}
function renderDiffViewer() {
    if (!diffViewerEnabled || !lastOriginalFrameData || !lastWatermarkedFrameData) return;
    const original = lastOriginalFrameData, signed = lastWatermarkedFrameData;
    for (const id of ['diff-original-canvas', 'diff-watermarked-canvas', 'diff-heatmap-canvas']) { $(id).width = original.width; $(id).height = original.height; }
    $('diff-original-canvas').getContext('2d').putImageData(original, 0, 0);
    $('diff-watermarked-canvas').getContext('2d').putImageData(signed, 0, 0);
    const ctx = $('diff-heatmap-canvas').getContext('2d'), heat = ctx.createImageData(original.width, original.height);
    for (let i = 0; i < original.data.length; i += 4) {
        const delta = Math.abs(original.data[i] - signed.data[i]) + Math.abs(original.data[i + 1] - signed.data[i + 1]) + Math.abs(original.data[i + 2] - signed.data[i + 2]);
        heat.data[i] = diffOverlayEnabled ? Math.min(255, delta * 16) : signed.data[i];
        heat.data[i + 1] = diffOverlayEnabled ? (delta ? 0 : 35) : signed.data[i + 1];
        heat.data[i + 2] = diffOverlayEnabled ? 0 : signed.data[i + 2]; heat.data[i + 3] = 255;
    }
    ctx.putImageData(heat, 0, 0);
}

let metricsPollInterval = null, metricsPolling = false;
const metricsHistory = [];
function applyMetrics(data) {
    rawMetrics = { ...rawMetrics, ...data }; window.OtsPanel?.applyMetrics(data);
    $('val-frames').textContent = fmtNum(rawMetrics.frames_processed || 0); $('val-fps').textContent = rawMetrics.average_fps || '0.0';
    $('val-sign-latency').textContent = rawMetrics.avg_sign_latency_us || '0.0';
    $('val-verified-ok').textContent = fmtNum(rawMetrics.frames_verified_ok || 0); $('val-verified-fail').textContent = fmtNum(rawMetrics.frames_verified_fail || 0);
    $('val-verify-latency').textContent = rawMetrics.avg_verify_latency_us || '0.0'; $('footer-uptime-value').textContent = fmtUptime(rawMetrics.uptime_secs || 0);
    $('footer-verified-value').textContent = `✅ ${rawMetrics.frames_verified_ok || 0} / ❌ ${rawMetrics.frames_verified_fail || 0} (all media)`;
}
async function pollMetrics() {
    if (metricsPolling) return; metricsPolling = true;
    try {
        const response = await fetch('/api/metrics', { headers: authHeaders(), signal: AbortSignal.timeout(5000) });
        if (!response.ok) return;
        const data = await response.json(); applyMetrics(data); metricsHistory.push(data); if (metricsHistory.length > 60) metricsHistory.shift();
        for (const [id, keys] of [['chart-fps', ['average_fps']], ['chart-sign-latency', ['avg_sign_latency_us']], ['chart-verify-latency', ['avg_verify_latency_us']], ['chart-verify-counts', ['frames_verified_ok', 'frames_verified_fail']]]) {
            const canvas = $(id), ctx = canvas.getContext('2d'), max = Math.max(1, ...metricsHistory.flatMap(row => keys.map(key => Number(row[key]) || 0)));
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            keys.forEach((key, series) => { ctx.strokeStyle = series ? '#ef4444' : '#3b82f6'; ctx.beginPath();
                metricsHistory.forEach((row, i) => { const x = i * canvas.width / 59, y = canvas.height - (Number(row[key]) || 0) / max * (canvas.height - 10); if (!i) ctx.moveTo(x, y); else ctx.lineTo(x, y); }); ctx.stroke(); });
        }
    } catch (_) { /* Polling is observational, not a verification result. */ }
    finally { metricsPolling = false; }
}
async function exportSession() {
    if (!serverVersion) { showToast('Wait for dashboard initialization before exporting', 'error'); return; }
    try {
        const response = await fetch('/api/session', { headers: authHeaders(), signal: AbortSignal.timeout(5000) });
        if (!response.ok) throw new Error(`Session HTTP ${response.status}`);
        const report = { steganographer_version: serverVersion, exported_at: new Date().toISOString(), browser_session_start: SESSION_START.toISOString(),
            server_session: await response.json(), aggregate_media_metrics: { ...rawMetrics },
            metrics_scope: 'Server counters may include video and audio; never parsed from formatted labels.', last_video_verification: lastVerifyData };
        downloadBlob(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }), `steganographer-session-${Date.now()}.json`);
    } catch (err) { showToast('Export failed: ' + err.message, 'error'); }
}
function switchTab(name) {
    if (!['video', 'audio', 'docs'].includes(name)) return;
    document.querySelectorAll('.tab-btn').forEach(button => { const selected = button.dataset.tab === name; button.classList.toggle('active', selected); button.setAttribute('aria-selected', String(selected)); });
    document.querySelectorAll('.tab-content').forEach(panel => { const selected = panel.id === 'tab-' + name; panel.classList.toggle('hidden', !selected); panel.style.display = selected ? '' : 'none'; });
    if (name === 'docs' && typeof initDocsTab === 'function') initDocsTab();
}
function toggleCheatSheet() {
    const existing = $('cheatsheet-overlay');
    if (existing) { existing.remove(); return; }
    const overlay = document.createElement('div');
    overlay.id = 'cheatsheet-overlay';
    overlay.innerHTML = '<div class="cheatsheet-panel" role="dialog" aria-label="Keyboard shortcuts"><h3>Keyboard shortcuts</h3>' +
        '<table><tr><td>1 / 2 / 3</td><td>Video / Audio / Docs</td></tr><tr><td>Space</td><td>Start / stop camera</td></tr>' +
        '<tr><td>R</td><td>Record / export active media archive</td></tr><tr><td>+ / −</td><td>Video LSB depth</td></tr>' +
        '<tr><td>E</td><td>Export session JSON</td></tr><tr><td>?</td><td>Shortcut help</td></tr></table><button type="button">Close</button></div>';
    const close = () => overlay.remove();
    overlay.addEventListener('click', event => { if (event.target === overlay) close(); });
    overlay.querySelector('button').addEventListener('click', close);
    document.body.append(overlay); overlay.querySelector('button').focus();
}
function handleKeyboardShortcut(event) {
    if (event.code === 'Escape') { $('cheatsheet-overlay')?.remove(); return; }
    if (event.target.closest('input,textarea,select,button,a,[contenteditable="true"],[role="button"]') || event.ctrlKey || event.metaKey || event.altKey) return;
    if (event.code === 'Digit1') switchTab('video'); else if (event.code === 'Digit2') switchTab('audio'); else if (event.code === 'Digit3') switchTab('docs');
    else if (event.code === 'Space') { event.preventDefault(); if (cameraActive) stopCamera(); else startCamera(); }
    else if (event.code === 'KeyR') { if (!$('tab-audio').classList.contains('hidden') && typeof toggleAudioRecording === 'function') toggleAudioRecording(); else toggleVideoRecording(); }
    else if (event.code === 'KeyE') exportSession();
    else if (event.code === 'Slash' && event.shiftKey) { event.preventDefault(); toggleCheatSheet(); }
    else if (event.code === 'Equal' || event.code === 'Minus') {
        if (!configHydrated) return;
        liveConfig.lsbBits = Math.max(1, Math.min(4, liveConfig.lsbBits + (event.code === 'Equal' ? 1 : -1))); renderConfigControls(); pushConfigToServer();
    }
}
async function init() {
    ingestAuthToken();
    document.querySelectorAll('.tab-btn').forEach(button => button.addEventListener('click', () => switchTab(button.dataset.tab)));
    document.addEventListener('keydown', handleKeyboardShortcut);
    $('start-camera-btn').addEventListener('click', startCamera); $('stop-camera-btn').addEventListener('click', stopCamera);
    $('record-video-btn').addEventListener('click', toggleVideoRecording); $('session-export-btn').addEventListener('click', exportSession);
    $('camera-select').addEventListener('change', () => { if (cameraActive) startCamera(); });
    $('cfg-transport').addEventListener('change', () => {
        localStorage.setItem(TRANSPORT_STORAGE_KEY, $('cfg-transport').value);
        const url = new URL(location.href); url.searchParams.delete('transport'); history.replaceState(null, '', url);
        stopTransport(); transportFallback = false; if (cameraActive) connectTransport();
    });
    $('diff-toggle-btn').addEventListener('click', () => { diffViewerEnabled = !diffViewerEnabled; $('diff-viewer').classList.toggle('hidden', !diffViewerEnabled); $('diff-toggle-btn').textContent = diffViewerEnabled ? 'Hide Diff' : 'Show Diff'; });
    $('diff-overlay-toggle').addEventListener('click', () => { diffOverlayEnabled = !diffOverlayEnabled; $('diff-overlay-toggle').textContent = diffOverlayEnabled ? 'Heatmap ON' : 'Heatmap OFF'; renderDiffViewer(); });
    $('perf-panel-header').addEventListener('click', () => { const hidden = $('perf-panel-body').classList.toggle('hidden'); $('perf-collapse-icon').textContent = hidden ? '▶' : '▼'; });
    const theme = localStorage.getItem('stego-theme') || 'dark'; document.body.setAttribute('data-theme', theme);
    $('theme-toggle-btn').addEventListener('click', () => { const next = document.body.getAttribute('data-theme') === 'light' ? 'dark' : 'light'; document.body.setAttribute('data-theme', next); localStorage.setItem('stego-theme', next); });
    document.querySelectorAll('.copy-btn').forEach(button => button.addEventListener('click', async () => { const node = $(button.dataset.copyTarget); try { await navigator.clipboard.writeText(node.title || node.textContent); showToast('Copied', 'success'); } catch (_) { showToast('Clipboard unavailable', 'error'); } }));
    document.querySelectorAll('.help-icon').forEach(icon => icon.addEventListener('mouseenter', () => {
        const tooltip = icon.querySelector('.help-tooltip');
        if (!tooltip) return;
        const rect = icon.getBoundingClientRect(), width = tooltip.offsetWidth || 300;
        tooltip.style.left = Math.max(8, Math.min(innerWidth - width - 8, rect.left - width / 2)) + 'px';
        tooltip.style.top = Math.max(8, rect.top - tooltip.offsetHeight - 10) + 'px';
    }));
    window.addEventListener('pagehide', () => { stopCamera(); if (typeof stopMicrophone === 'function') stopMicrophone(); clearInterval(metricsPollInterval); });
    const controls = [...document.querySelectorAll('.config-controls input, .config-controls select, .preset-btn')];
    controls.forEach(control => control.disabled = true); $('start-camera-btn').disabled = true;
    try {
        await fetchConfig();
        const response = await fetch('/api/version', { headers: authHeaders(), signal: AbortSignal.timeout(5000) }); if (!response.ok) throw new Error('Version unavailable');
        serverVersion = (await response.json()).version; $('version-badge').textContent = 'v' + serverVersion;
        const capabilityResponse = await fetch('/api/webrtc/config', { headers: authHeaders(), signal: AbortSignal.timeout(5000) });
        if (capabilityResponse.ok) serverTransport = (await capabilityResponse.json()).default_transport || serverTransport;
        controls.forEach(control => control.disabled = false); $('start-camera-btn').disabled = false;
        // Not implemented by this dashboard; never imply these affect signed output.
        ['signing-backend', 'cfg-sign-backend', 'audio-cfg-sign-backend', 'cfg-qr-scale', 'cfg-overlay-text'].forEach(id => $(id).disabled = true);
        $('cfg-transport').value = resolveTransportPreference(); setupConfigControls(); enumerateCameras();
        metricsPollInterval = setInterval(pollMetrics, 1000); pollMetrics();
        if (new URL(location.href).searchParams.has('autostart')) startCamera();
    } catch (err) { showToast('Initialization failed: ' + err.message + ' — reload to retry', 'error'); }
}
document.readyState === 'loading' ? document.addEventListener('DOMContentLoaded', init) : init();
