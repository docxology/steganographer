/**
 * Steganographer Dashboard — Audio Tab
 *
 * Architecture:
 * - LEFT:  Microphone capture via Web Audio API, real-time waveform + spectrum
 * - SERVER: Signs audio chunks via WebSocket (/ws/audio/encode, /ws/audio/decode)
 * - RIGHT: Verification data + audio config controls
 *
 * Uses AnalyserNode for visualization and ScriptProcessorNode for PCM extraction.
 */

// ─── Audio State ──────────────────────────────────────────────────────────────

let audioCtx = null;
let analyserNode = null;
let processorNode = null;
let micStream = null;
let audioEncodeWs = null;
let audioDecodeWs = null;
let audioSignInterval = null;
let audioDrawLoopId = null;
let audioChunkCounter = 0;
let audioMicActive = false;
let audioAwaitingSigning = false;
let audioStartTime = 0;

let audioConfig = {
    lsbBits: 1,
    signingBackend: 'ed25519',
    signRateMs: 1000,
    bufferSize: 2048,
    sampleRate: 44100,
};

let lastAudioVerify = {
    chunkIndex: 0,
    hash: '0000000000000000',
    backend: 'ed25519',
    verified: false,
    signLatencyUs: 0,
};

let audioStats = {
    chunks: 0,
    verifiedOk: 0,
    verifiedFail: 0,
    signLatencyUs: 0,
    verifyLatencyUs: 0,
};

// ─── Audio DOM References ─────────────────────────────────────────────────────

const audioEl = {
    waveformCanvas: document.getElementById('audio-waveform-canvas'),
    spectrumCanvas: document.getElementById('audio-spectrum-canvas'),
    overlay: document.getElementById('audio-overlay'),
    startMicBtn: document.getElementById('start-mic-btn'),
    // Config
    cfgLsbBits: document.getElementById('audio-cfg-lsb-bits'),
    cfgLsbBitsVal: document.getElementById('audio-cfg-lsb-bits-val'),
    cfgSignBackend: document.getElementById('audio-cfg-sign-backend'),
    cfgSignRate: document.getElementById('audio-cfg-sign-rate'),
    cfgSignRateVal: document.getElementById('audio-cfg-sign-rate-val'),
    cfgBufferSize: document.getElementById('audio-cfg-buffer-size'),
    cfgSampleRate: document.getElementById('audio-cfg-sample-rate'),
    // Verify
    verifyWaiting: document.getElementById('audio-verify-waiting'),
    verifyResult: document.getElementById('audio-verify-result'),
    verifyStatusBanner: document.getElementById('audio-verify-status-banner'),
    verifyStatusIcon: document.getElementById('audio-verify-status-icon'),
    verifyStatusText: document.getElementById('audio-verify-status-text'),
    fieldChunkIndex: document.getElementById('audio-field-chunk-index'),
    fieldHash: document.getElementById('audio-field-hash'),
    fieldSigPreview: document.getElementById('audio-field-sig-preview'),
    fieldBackend: document.getElementById('audio-field-backend'),
    fieldVerifyLatency: document.getElementById('audio-field-verify-latency'),
    verifyLog: document.getElementById('audio-verify-log'),
    // Stats
    valChunks: document.getElementById('val-audio-chunks'),
    valRate: document.getElementById('val-audio-rate'),
    valSignLatency: document.getElementById('val-audio-sign-latency'),
    valVerifiedOk: document.getElementById('val-audio-verified-ok'),
    valVerifiedFail: document.getElementById('val-audio-verified-fail'),
    valVerifyLatency: document.getElementById('val-audio-verify-latency'),
    // Info
    infoPayloadSize: document.getElementById('audio-info-payload-size'),
    infoHashAlgo: document.getElementById('audio-info-hash-algo'),
    infoSigAlgo: document.getElementById('audio-info-sig-algo'),
    infoCapacity: document.getElementById('audio-info-capacity'),
    infoUtilization: document.getElementById('audio-info-utilization'),
    infoChannels: document.getElementById('audio-info-channels'),
};

// ═══════════════════════════════════════════════════════════════════════════════
// WAVEFORM & SPECTRUM VISUALIZATION
// ═══════════════════════════════════════════════════════════════════════════════

function drawAudioWaveform() {
    if (!audioMicActive || !analyserNode) return;

    const canvas = audioEl.waveformCanvas;
    const ctx = canvas.getContext('2d');
    const w = canvas.width = canvas.clientWidth * (window.devicePixelRatio || 1);
    const h = canvas.height = canvas.clientHeight * (window.devicePixelRatio || 1);

    const bufLen = analyserNode.fftSize;
    const dataArray = new Uint8Array(bufLen);
    analyserNode.getByteTimeDomainData(dataArray);

    // Background
    ctx.fillStyle = '#0d0d0d';
    ctx.fillRect(0, 0, w, h);

    // Center line
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.06)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(0, h / 2);
    ctx.lineTo(w, h / 2);
    ctx.stroke();

    // Waveform
    ctx.lineWidth = 2;
    ctx.strokeStyle = '#dc2626';
    ctx.shadowColor = 'rgba(220, 38, 38, 0.3)';
    ctx.shadowBlur = 6;
    ctx.beginPath();

    const sliceWidth = w / bufLen;
    let x = 0;
    for (let i = 0; i < bufLen; i++) {
        const v = dataArray[i] / 128.0;
        const y = (v * h) / 2;
        if (i === 0) {
            ctx.moveTo(x, y);
        } else {
            ctx.lineTo(x, y);
        }
        x += sliceWidth;
    }
    ctx.lineTo(w, h / 2);
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Labels
    ctx.font = '10px "JetBrains Mono", monospace';
    ctx.fillStyle = '#555';
    ctx.textAlign = 'left';
    ctx.fillText('WAVEFORM', 8, 16);

    ctx.textAlign = 'right';
    const elapsed = audioMicActive ? ((Date.now() - audioStartTime) / 1000).toFixed(1) : '0.0';
    ctx.fillText(`${audioConfig.sampleRate} Hz | ${elapsed}s`, w - 8, 16);

    // Draw spectrum
    drawAudioSpectrum();

    audioDrawLoopId = requestAnimationFrame(drawAudioWaveform);
}

function drawAudioSpectrum() {
    if (!analyserNode) return;

    const canvas = audioEl.spectrumCanvas;
    const ctx = canvas.getContext('2d');
    const w = canvas.width = canvas.clientWidth * (window.devicePixelRatio || 1);
    const h = canvas.height = canvas.clientHeight * (window.devicePixelRatio || 1);

    const bufLen = analyserNode.frequencyBinCount;
    const freqData = new Uint8Array(bufLen);
    analyserNode.getByteFrequencyData(freqData);

    // Background
    ctx.fillStyle = '#0a0a0a';
    ctx.fillRect(0, 0, w, h);

    // Bars
    const barCount = Math.min(bufLen, 128);
    const barWidth = w / barCount;
    const step = Math.floor(bufLen / barCount);

    for (let i = 0; i < barCount; i++) {
        const value = freqData[i * step];
        const barH = (value / 255) * h;
        const intensity = value / 255;

        // Gradient from dark red to bright red
        const r = Math.floor(100 + 156 * intensity);
        const g = Math.floor(10 + 28 * intensity);
        const b = Math.floor(10 + 28 * intensity);
        ctx.fillStyle = `rgb(${r}, ${g}, ${b})`;
        ctx.fillRect(i * barWidth, h - barH, barWidth - 1, barH);
    }

    // Labels
    ctx.font = '10px "JetBrains Mono", monospace';
    ctx.fillStyle = '#555';
    ctx.textAlign = 'left';
    ctx.fillText('SPECTRUM (FFT)', 8, 14);
}

// ═══════════════════════════════════════════════════════════════════════════════
// MICROPHONE CAPTURE
// ═══════════════════════════════════════════════════════════════════════════════

async function startMicrophone() {
    try {
        // Stop existing if restarting
        if (micStream) {
            micStream.getTracks().forEach(t => t.stop());
        }
        if (audioCtx) {
            await audioCtx.close();
        }

        audioCtx = new (window.AudioContext || window.webkitAudioContext)({
            sampleRate: audioConfig.sampleRate,
        });

        micStream = await navigator.mediaDevices.getUserMedia({
            audio: {
                channelCount: 1,
                sampleRate: { ideal: audioConfig.sampleRate },
                echoCancellation: false,
                noiseSuppression: false,
                autoGainControl: false,
            },
        });

        const source = audioCtx.createMediaStreamSource(micStream);

        // Analyser for visualization
        analyserNode = audioCtx.createAnalyser();
        analyserNode.fftSize = 2048;
        analyserNode.smoothingTimeConstant = 0.8;

        // Script processor for PCM extraction (sends to server)
        processorNode = audioCtx.createScriptProcessor(audioConfig.bufferSize, 1, 1);
        processorNode.onaudioprocess = handleAudioProcess;

        // Connect: source → analyser → processor → destination
        source.connect(analyserNode);
        analyserNode.connect(processorNode);
        processorNode.connect(audioCtx.destination);

        audioMicActive = true;
        audioStartTime = Date.now();
        audioEl.overlay.classList.add('hidden');

        // Start visualization
        drawAudioWaveform();

        // Connect WebSockets
        connectAudioWebSockets();

        // Start signing interval
        startAudioSigningInterval();

        // Update info display
        updateAudioStegoInfo();

        console.log(`[audio] Microphone started at ${audioCtx.sampleRate} Hz, buffer=${audioConfig.bufferSize}`);
    } catch (err) {
        console.error('[audio] Microphone failed:', err);
        audioEl.overlay.querySelector('.overlay-text').textContent = '❌ Microphone denied';
        audioEl.overlay.querySelector('.overlay-subtext').textContent = err.message || 'Allow microphone and reload';
    }
}

function stopMicrophone() {
    audioMicActive = false;
    if (audioDrawLoopId) cancelAnimationFrame(audioDrawLoopId);
    if (micStream) micStream.getTracks().forEach(t => t.stop());
    if (processorNode) processorNode.disconnect();
    if (audioCtx) audioCtx.close();
    if (audioSignInterval) clearInterval(audioSignInterval);
    if (audioEncodeWs) audioEncodeWs.close();
    if (audioDecodeWs) audioDecodeWs.close();
    micStream = null;
    audioCtx = null;
    analyserNode = null;
    processorNode = null;
    console.log('[audio] Microphone stopped');
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUDIO PCM → SERVER (WebSocket)
// ═══════════════════════════════════════════════════════════════════════════════

let lastPcmChunk = null;

function handleAudioProcess(event) {
    if (!audioMicActive) return;
    const inputData = event.inputBuffer.getChannelData(0);

    // Convert Float32 → Int16 PCM
    const pcm16 = new Int16Array(inputData.length);
    for (let i = 0; i < inputData.length; i++) {
        const s = Math.max(-1, Math.min(1, inputData[i]));
        pcm16[i] = s < 0 ? s * 0x8000 : s * 0x7FFF;
    }
    lastPcmChunk = pcm16;
    audioChunkCounter++;

    // Collect for recording (if active)
    collectAudioChunk(pcm16);
}

function sendAudioChunkForSigning() {
    if (!lastPcmChunk || !audioEncodeWs || audioEncodeWs.readyState !== WebSocket.OPEN) return;
    if (audioAwaitingSigning) return;

    audioAwaitingSigning = true;

    const msg = JSON.stringify({
        type: 'audio_frame',
        chunk_index: audioChunkCounter,
        sample_rate: audioConfig.sampleRate,
        channels: 1,
        buffer_size: audioConfig.bufferSize,
        lsb_bits: audioConfig.lsbBits,
        // Send PCM as base64-encoded Int16 array
        pcm_base64: arrayBufferToBase64(lastPcmChunk.buffer),
    });

    audioEncodeWs.send(msg);
}

function startAudioSigningInterval() {
    if (audioSignInterval) clearInterval(audioSignInterval);
    audioSignInterval = setInterval(sendAudioChunkForSigning, audioConfig.signRateMs);
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUDIO WEBSOCKETS
// ═══════════════════════════════════════════════════════════════════════════════

function connectAudioWebSockets() {
    const wsProto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsBase = `${wsProto}//${location.host}`;

    // Encode WebSocket
    audioEncodeWs = new WebSocket(`${wsBase}/ws/audio/encode`);
    audioEncodeWs.onopen = () => console.log('[audio-ws] Encode connected');
    audioEncodeWs.onmessage = handleAudioEncodeMessage;
    audioEncodeWs.onclose = () => {
        console.log('[audio-ws] Encode disconnected');
        if (audioMicActive) setTimeout(connectAudioWebSockets, 2000);
    };

    // Decode WebSocket
    audioDecodeWs = new WebSocket(`${wsBase}/ws/audio/decode`);
    audioDecodeWs.onopen = () => {
        console.log('[audio-ws] Decode connected');
        startAudioDecodePolling();
    };
    audioDecodeWs.onmessage = handleAudioDecodeMessage;
    audioDecodeWs.onclose = () => console.log('[audio-ws] Decode disconnected');
}

function handleAudioEncodeMessage(event) {
    try {
        const msg = JSON.parse(event.data);
        audioAwaitingSigning = false;

        if (msg.type === 'audio_signed') {
            audioStats.chunks++;
            audioStats.signLatencyUs = msg.sign_us || 0;

            // Update stats display
            audioEl.valChunks.textContent = audioStats.chunks;
            audioEl.valSignLatency.textContent = audioStats.signLatencyUs.toFixed(1);

            // Estimate samples/sec
            const elapsed = (Date.now() - audioStartTime) / 1000;
            const rate = elapsed > 0 ? Math.floor((audioStats.chunks * audioConfig.bufferSize) / elapsed) : 0;
            audioEl.valRate.textContent = rate.toLocaleString();
        }
    } catch (e) {
        console.error('[audio-ws] Parse error:', e);
        audioAwaitingSigning = false;
    }
}

function startAudioDecodePolling() {
    // Send periodic decode requests
    setInterval(() => {
        if (audioDecodeWs && audioDecodeWs.readyState === WebSocket.OPEN) {
            audioDecodeWs.send(JSON.stringify({ type: 'decode_request' }));
        }
    }, 300);
}

function handleAudioDecodeMessage(event) {
    try {
        const msg = JSON.parse(event.data);
        if (msg.type !== 'audio_verify') return;

        // Show verification result
        audioEl.verifyWaiting.classList.add('hidden');
        audioEl.verifyResult.classList.remove('hidden');

        lastAudioVerify.verified = msg.verified;
        lastAudioVerify.chunkIndex = msg.payload?.chunk_index || 0;
        lastAudioVerify.hash = msg.payload?.hash || '0000000000000000';
        lastAudioVerify.backend = msg.backend || 'ed25519';
        lastAudioVerify.signLatencyUs = msg.verify_us || 0;

        if (msg.verified) {
            audioStats.verifiedOk++;
            audioEl.verifyStatusBanner.className = 'verify-status-banner verified';
            audioEl.verifyStatusIcon.textContent = '✅';
            audioEl.verifyStatusText.textContent = 'Audio Signature Verified';
        } else {
            audioStats.verifiedFail++;
            audioEl.verifyStatusBanner.className = 'verify-status-banner failed';
            audioEl.verifyStatusIcon.textContent = '❌';
            audioEl.verifyStatusText.textContent = 'Verification Failed';
        }

        audioEl.fieldChunkIndex.textContent = lastAudioVerify.chunkIndex;
        audioEl.fieldHash.textContent = lastAudioVerify.hash.slice(0, 16) + '…' + lastAudioVerify.hash.slice(-6);
        audioEl.fieldSigPreview.textContent = msg.payload?.signature_preview || '—';
        audioEl.fieldSigPreview.title = msg.payload?.signature_preview ? 'First 16 bytes of ' + (msg.backend || 'ed25519') + ' audio signature' : '';
        audioEl.fieldBackend.textContent = lastAudioVerify.backend;
        audioEl.fieldVerifyLatency.textContent = lastAudioVerify.signLatencyUs.toFixed(0) + ' μs';

        audioEl.valVerifiedOk.textContent = audioStats.verifiedOk;
        audioEl.valVerifiedFail.textContent = audioStats.verifiedFail;
        audioEl.valVerifyLatency.textContent = (msg.verify_us || 0).toFixed(1);

        // Add to log
        addAudioVerifyLogEntry(msg);
    } catch (e) {
        console.error('[audio-ws] Decode parse error:', e);
    }
}

function addAudioVerifyLogEntry(msg) {
    const entry = document.createElement('div');
    entry.className = `verify-log-entry ${msg.verified ? 'ok' : 'fail'}`;

    const time = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const icon = msg.verified ? '✅' : '❌';
    const hash = (msg.payload?.hash || '').slice(0, 8);
    const latency = (msg.verify_us || 0).toFixed(0);

    entry.innerHTML = `
        <span class="log-time">${time}</span>
        <span class="log-icon">${icon}</span>
        <span class="log-hash">${msg.payload?.chunk_index || 0}</span>
        <span class="log-bar"><span class="log-bar-fill" style="width:${Math.min(100, (msg.verify_us || 0) / 100)}%"></span></span>
        <span class="log-latency">${latency}μs</span>
    `;

    if (audioEl.verifyLog.children.length >= 20) {
        audioEl.verifyLog.removeChild(audioEl.verifyLog.lastChild);
    }
    audioEl.verifyLog.insertBefore(entry, audioEl.verifyLog.firstChild);
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUDIO CONFIG
// ═══════════════════════════════════════════════════════════════════════════════

function updateAudioStegoInfo() {
    const bits = audioConfig.lsbBits;
    const bufSize = audioConfig.bufferSize;
    const channels = 1;
    const capacityBits = bufSize * channels * bits;
    const capacityBytes = Math.floor(capacityBits / 8);

    const isEth = audioConfig.signingBackend === 'ethereum';
    const payloadSize = isEth ? 97 : 104;
    const utilization = capacityBits > 0 ? ((payloadSize * 8 / capacityBits) * 100).toFixed(3) : 0;

    audioEl.infoPayloadSize.textContent = payloadSize + ' bytes';
    audioEl.infoHashAlgo.textContent = 'BLAKE3 (256-bit)';
    audioEl.infoSigAlgo.textContent = isEth ? 'secp256k1 (EIP-191)' : 'Ed25519 (512-bit)';
    audioEl.infoCapacity.textContent = capacityBytes + ' B (' + capacityBits.toLocaleString() + ' bits)';
    audioEl.infoUtilization.textContent = utilization + '%';
    audioEl.infoChannels.textContent = channels + ' (mono)';
}

function initAudioConfigListeners() {
    if (audioEl.cfgLsbBits) {
        audioEl.cfgLsbBits.addEventListener('input', () => {
            audioConfig.lsbBits = parseInt(audioEl.cfgLsbBits.value);
            audioEl.cfgLsbBitsVal.textContent = audioConfig.lsbBits;
            updateAudioStegoInfo();
        });
    }

    if (audioEl.cfgSignBackend) {
        audioEl.cfgSignBackend.addEventListener('change', () => {
            audioConfig.signingBackend = audioEl.cfgSignBackend.value;
            updateAudioStegoInfo();
        });
    }

    if (audioEl.cfgSignRate) {
        audioEl.cfgSignRate.addEventListener('input', () => {
            audioConfig.signRateMs = parseInt(audioEl.cfgSignRate.value);
            audioEl.cfgSignRateVal.textContent = (1000 / audioConfig.signRateMs).toFixed(1) + '/s';
            if (audioMicActive) startAudioSigningInterval();
        });
    }

    if (audioEl.cfgBufferSize) {
        audioEl.cfgBufferSize.addEventListener('change', () => {
            audioConfig.bufferSize = parseInt(audioEl.cfgBufferSize.value);
            updateAudioStegoInfo();
            // Restart mic with new buffer size
            if (audioMicActive) startMicrophone();
        });
    }

    if (audioEl.cfgSampleRate) {
        audioEl.cfgSampleRate.addEventListener('change', () => {
            audioConfig.sampleRate = parseInt(audioEl.cfgSampleRate.value);
            updateAudioStegoInfo();
            // Restart mic with new sample rate
            if (audioMicActive) startMicrophone();
        });
    }

    updateAudioStegoInfo();
}

// ═══════════════════════════════════════════════════════════════════════════════
// TAB SWITCHING
// ═══════════════════════════════════════════════════════════════════════════════

function initTabSwitching() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = {
        video: document.getElementById('tab-video'),
        audio: document.getElementById('tab-audio'),
        docs: document.getElementById('tab-docs'),
    };

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.dataset.tab;

            // Update button states
            tabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            // Show/hide tab content
            for (const [name, el] of Object.entries(tabContents)) {
                if (!el) continue;
                if (name === target) {
                    el.classList.remove('hidden');
                    el.style.display = '';
                } else {
                    el.classList.add('hidden');
                    el.style.display = 'none';
                }
            }

            console.log(`[tabs] Switched to ${target} tab`);
        });
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUDIO RECORDING (WAV EXPORT)
// ═══════════════════════════════════════════════════════════════════════════════

let audioRecording = false;
let audioRecordedChunks = [];

function toggleAudioRecording() {
    const btn = document.getElementById('record-audio-btn');
    const label = document.getElementById('record-audio-label');

    if (!audioRecording) {
        // Start recording
        audioRecordedChunks = [];
        audioRecording = true;
        btn.classList.add('recording');
        label.textContent = 'Stop';
        console.log('[audio-record] Recording started');
    } else {
        // Stop recording, export WAV
        audioRecording = false;
        btn.classList.remove('recording');
        label.textContent = 'Record';
        exportAudioAsWav();
        console.log('[audio-record] Recording stopped');
    }
}

/**
 * Collect PCM chunks during recording.
 * Called from handleAudioProcess when audioRecording is true.
 */
function collectAudioChunk(pcm16) {
    if (!audioRecording) return;
    audioRecordedChunks.push(new Int16Array(pcm16));
}

/**
 * Export collected PCM chunks as a WAV file and trigger browser download.
 */
function exportAudioAsWav() {
    if (audioRecordedChunks.length === 0) {
        console.warn('[audio-record] No audio data to export');
        return;
    }

    // Concatenate all chunks
    const totalSamples = audioRecordedChunks.reduce((s, c) => s + c.length, 0);
    const combined = new Int16Array(totalSamples);
    let offset = 0;
    for (const chunk of audioRecordedChunks) {
        combined.set(chunk, offset);
        offset += chunk.length;
    }

    const numChannels = 1;
    const sampleRate = audioConfig.sampleRate;
    const bitsPerSample = 16;
    const byteRate = sampleRate * numChannels * (bitsPerSample / 8);
    const blockAlign = numChannels * (bitsPerSample / 8);
    const dataSize = combined.length * (bitsPerSample / 8);
    const fileSize = 44 + dataSize;

    // Build WAV header
    const buffer = new ArrayBuffer(fileSize);
    const view = new DataView(buffer);

    // RIFF header
    writeString(view, 0, 'RIFF');
    view.setUint32(4, fileSize - 8, true);
    writeString(view, 8, 'WAVE');

    // fmt sub-chunk
    writeString(view, 12, 'fmt ');
    view.setUint32(16, 16, true);         // sub-chunk size
    view.setUint16(20, 1, true);          // PCM format
    view.setUint16(22, numChannels, true);
    view.setUint32(24, sampleRate, true);
    view.setUint32(28, byteRate, true);
    view.setUint16(32, blockAlign, true);
    view.setUint16(34, bitsPerSample, true);

    // data sub-chunk
    writeString(view, 36, 'data');
    view.setUint32(40, dataSize, true);

    // Write PCM samples
    const pcmOffset = 44;
    for (let i = 0; i < combined.length; i++) {
        view.setInt16(pcmOffset + i * 2, combined[i], true);
    }

    const blob = new Blob([buffer], { type: 'audio/wav' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    a.href = url;
    a.download = `steganographer-audio-${ts}.wav`;
    a.click();
    URL.revokeObjectURL(url);

    const sizeMB = (blob.size / (1024 * 1024)).toFixed(2);
    const durationS = (totalSamples / sampleRate).toFixed(1);
    console.log(`[audio-record] WAV saved: ${a.download} (${sizeMB} MB, ${durationS}s)`);
    audioRecordedChunks = [];
}

function writeString(view, offset, str) {
    for (let i = 0; i < str.length; i++) {
        view.setUint8(offset + i, str.charCodeAt(i));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    initTabSwitching();
    initAudioConfigListeners();

    // Start Microphone button
    if (audioEl.startMicBtn) {
        audioEl.startMicBtn.addEventListener('click', startMicrophone);
    }

    // Audio Record button
    const recordAudioBtn = document.getElementById('record-audio-btn');
    if (recordAudioBtn) recordAudioBtn.addEventListener('click', toggleAudioRecording);
});

