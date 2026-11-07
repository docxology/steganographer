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

let audioSession = null;
let audioContextClosing = Promise.resolve();
let audioRecording = false;
let audioArchive = null;
let audioRecordingFormat = null;
let audioArchiveLastCaptureEnd = null;
let signedAudioUrl = null;

const AUDIO_REPLY_TIMEOUT_MS = 10000;
const AUDIO_RECONNECT_MS = 2000;

const audioConfig = {
    lsbBits: 1,
    signRateMs: 1000,
    bufferSize: 2048,
    sampleRate: 44100,
};

const audioStats = {
    chunks: 0,
    sampleFrames: 0,
    verifiedOk: 0,
    verifiedFail: 0,
    signLatencyUs: 0,
};

// ─── Audio DOM References ─────────────────────────────────────────────────────

const audioEl = {
    waveformCanvas: document.getElementById('audio-waveform-canvas'),
    spectrumCanvas: document.getElementById('audio-spectrum-canvas'),
    overlay: document.getElementById('audio-overlay'),
    startMicBtn: document.getElementById('start-mic-btn'),
    stopMicBtn: document.getElementById('stop-mic-btn'),
    signedPlayer: document.getElementById('signed-audio-player'),
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

function drawAudioWaveform(session) {
    if (!isCurrentAudioSession(session) || !session.active) return;

    const canvas = audioEl.waveformCanvas;
    const ctx = canvas.getContext('2d');
    const w = canvas.width = canvas.clientWidth * (window.devicePixelRatio || 1);
    const h = canvas.height = canvas.clientHeight * (window.devicePixelRatio || 1);

    const bufLen = session.analyser.fftSize;
    const dataArray = session.waveformData;
    session.analyser.getByteTimeDomainData(dataArray);

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
    ctx.fillText('MIC INPUT — WAVEFORM', 8, 16);

    ctx.textAlign = 'right';
    const elapsed = ((Date.now() - session.startedWallMs) / 1000).toFixed(1);
    ctx.fillText(`${session.context.sampleRate} Hz | ${elapsed}s`, w - 8, 16);

    // Draw spectrum
    drawAudioSpectrum(session);

    session.drawLoop = requestAnimationFrame(() => drawAudioWaveform(session));
}

function drawAudioSpectrum(session) {
    if (!isCurrentAudioSession(session) || !session.analyser) return;

    const canvas = audioEl.spectrumCanvas;
    const ctx = canvas.getContext('2d');
    const w = canvas.width = canvas.clientWidth * (window.devicePixelRatio || 1);
    const h = canvas.height = canvas.clientHeight * (window.devicePixelRatio || 1);

    const bufLen = session.analyser.frequencyBinCount;
    const freqData = session.spectrumData;
    session.analyser.getByteFrequencyData(freqData);

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
    ctx.fillText('MIC INPUT — SPECTRUM (FFT)', 8, 14);
}

// ═══════════════════════════════════════════════════════════════════════════════
// MICROPHONE CAPTURE
// ═══════════════════════════════════════════════════════════════════════════════

function isCurrentAudioSession(session) {
    return audioSession === session && !session.disposed;
}

function createAudioChannel() {
    return { socket: null, reconnectTimer: null, openTimer: null, pollTimer: null, pendingPoll: null };
}

function setAudioOverlay(title, detail) {
    audioEl.overlay.classList.remove('hidden');
    audioEl.overlay.querySelector('.overlay-text').textContent = title;
    audioEl.overlay.querySelector('.overlay-subtext').textContent = detail;
}

function updateAudioCaptureButtons() {
    const active = Boolean(audioSession?.active);
    if (audioEl.startMicBtn) audioEl.startMicBtn.disabled = Boolean(audioSession);
    if (audioEl.stopMicBtn) audioEl.stopMicBtn.disabled = !audioSession;
    const button = document.getElementById('record-audio-btn');
    if (button) {
        button.disabled = !active && !audioArchive;
        button.classList.toggle('recording', audioRecording);
        button.title = 'Archive sampled server-returned signed WAV chunks and extraction metadata. Not a continuous microphone recording; gaps are retained in the manifest. Limit: 64 MiB or 300 entries.';
    }
    const label = document.getElementById('record-audio-label');
    if (label) label.textContent = audioRecording ? 'Stop & export' : audioArchive ? 'Export archive' : 'Record signed chunks';
}

function resetAudioVerification(message = 'Awaiting a signed audio chunk') {
    audioEl.verifyWaiting.classList.remove('hidden');
    audioEl.verifyResult.classList.add('hidden');
    audioEl.verifyWaiting.querySelector('.overlay-text').textContent = message;
    audioEl.verifyWaiting.querySelector('.overlay-subtext').textContent = 'No current verdict. Exported WAVs are not independently verified in this browser.';
    audioEl.verifyStatusBanner.className = 'verify-status-banner';
    audioEl.verifyStatusIcon.textContent = '…';
    audioEl.verifyStatusText.textContent = 'Unknown';
    for (const field of [audioEl.fieldChunkIndex, audioEl.fieldHash, audioEl.fieldSigPreview, audioEl.fieldBackend, audioEl.fieldVerifyLatency]) {
        field.textContent = '—';
        field.title = '';
    }
    audioEl.valVerifyLatency.textContent = '—';
}

function clearSignedAudioPlayer() {
    if (audioEl.signedPlayer) {
        audioEl.signedPlayer.pause();
        audioEl.signedPlayer.removeAttribute('src');
        audioEl.signedPlayer.removeAttribute('data-frame-index');
        audioEl.signedPlayer.title = '';
        audioEl.signedPlayer.load();
        audioEl.signedPlayer.hidden = true;
    }
    if (signedAudioUrl) URL.revokeObjectURL(signedAudioUrl);
    signedAudioUrl = null;
}

function displaySignedAudioChunk(wav, metadata) {
    clearSignedAudioPlayer();
    if (!audioEl.signedPlayer) return;
    signedAudioUrl = URL.createObjectURL(new Blob([wav], { type: 'audio/wav' }));
    const player = audioEl.signedPlayer;
    player.autoplay = false;
    player.controls = true;
    player.preload = 'none';
    player.src = signedAudioUrl;
    player.hidden = false;
    player.classList.remove('hidden');
    player.dataset.frameIndex = String(metadata.frame_index);
    player.setAttribute('aria-label', 'Latest returned signed PCM chunk; manual playback, not continuous microphone audio');
    player.title = `Returned frame ${metadata.frame_index}: ${metadata.sample_rate} Hz, ${metadata.channels} channel(s), ${metadata.duration_ms.toFixed(1)} ms. Ed25519 public key: ${metadata.public_key}. Capture time is a browser callback estimate.`;
}

function clearAudioSigning(session) {
    if (session.pendingSign) clearTimeout(session.pendingSign.timeout);
    session.pendingSign = null;
}

function closeAudioChannel(session, name) {
    const channel = session[name];
    clearTimeout(channel.reconnectTimer);
    clearTimeout(channel.openTimer);
    clearInterval(channel.pollTimer);
    if (channel.pendingPoll) clearTimeout(channel.pendingPoll.timeout);
    channel.reconnectTimer = channel.openTimer = channel.pollTimer = null;
    channel.pendingPoll = null;
    const socket = channel.socket;
    channel.socket = null;
    if (socket) {
        socket.onopen = socket.onmessage = socket.onclose = socket.onerror = null;
        if (socket.readyState < WebSocket.CLOSING) socket.close();
    }
}

function stopMicrophone(reason = 'Microphone stopped; signed-chunk recording stopped.') {
    const session = audioSession;
    audioSession = null;
    if (session) {
        session.disposed = true;
        session.active = false;
        cancelAnimationFrame(session.drawLoop);
        clearInterval(session.signInterval);
        clearAudioSigning(session);
        closeAudioChannel(session, 'encode');
        closeAudioChannel(session, 'decode');
        if (session.processor) {
            session.processor.onaudioprocess = null;
            session.processor.disconnect();
        }
        if (session.source) session.source.disconnect();
        if (session.analyser) session.analyser.disconnect();
        if (session.stream) session.stream.getTracks().forEach(track => track.stop());
        session.lastChunk = session.latestSigned = null;
        if (session.context && session.context.state !== 'closed') {
            audioContextClosing = session.context.close().catch(error => console.error('[audio] Context close failed:', error));
        }
    }
    if (audioRecording) finishAudioRecording(reason);
    clearSignedAudioPlayer();
    resetAudioVerification('Microphone stopped — no current verification');
    setAudioOverlay('🎤 Microphone stopped', 'Start microphone to sign sampled chunks');
    updateAudioCaptureButtons();
}

async function startMicrophone() {
    stopMicrophone('Microphone restarted; exporting the previous signed-chunk archive.');
    const session = {
        active: false, disposed: false, context: null, stream: null, source: null,
        analyser: null, processor: null, drawLoop: null, signInterval: null,
        encode: createAudioChannel(), decode: createAudioChannel(),
        pendingSign: null, lastChunk: null, latestSigned: null,
        captureCount: 0, lastSubmittedCaptureIndex: 0,
        startedWallMs: Date.now(), startedPerfMs: performance.now(),
    };
    audioSession = session;
    updateAudioCaptureButtons();
    setAudioOverlay('🎤 Starting microphone…', 'Allow microphone access; Stop cancels this start');
    resetAudioVerification('Starting microphone — no current verification');
    try {
        await audioContextClosing;
        if (!isCurrentAudioSession(session)) return;
        session.context = new (window.AudioContext || window.webkitAudioContext)({ sampleRate: audioConfig.sampleRate });
        await session.context.resume();
        if (!isCurrentAudioSession(session)) return;
        const stream = await navigator.mediaDevices.getUserMedia({
            audio: {
                channelCount: 1,
                sampleRate: { ideal: audioConfig.sampleRate },
                echoCancellation: false,
                noiseSuppression: false,
                autoGainControl: false,
            },
        });
        if (!isCurrentAudioSession(session)) {
            stream.getTracks().forEach(track => track.stop());
            return;
        }
        session.stream = stream;
        session.source = session.context.createMediaStreamSource(stream);
        session.analyser = session.context.createAnalyser();
        session.analyser.fftSize = 2048;
        session.analyser.smoothingTimeConstant = 0.8;
        session.waveformData = new Uint8Array(session.analyser.fftSize);
        session.spectrumData = new Uint8Array(session.analyser.frequencyBinCount);
        session.processor = session.context.createScriptProcessor(audioConfig.bufferSize, 1, 1);
        session.processor.onaudioprocess = event => handleAudioProcess(session, event);
        session.source.connect(session.analyser);
        session.analyser.connect(session.processor);
        // The processor must be connected to run, but its output is always silence.
        session.processor.connect(session.context.destination);
        stream.getTracks().forEach(track => track.addEventListener('ended', () => {
            if (isCurrentAudioSession(session)) stopMicrophone('Microphone disconnected; exporting signed chunks.');
        }));
        session.active = true;
        session.startedWallMs = Date.now();
        session.startedPerfMs = performance.now();
        Object.assign(audioStats, { chunks: 0, sampleFrames: 0, verifiedOk: 0, verifiedFail: 0, signLatencyUs: 0 });
        audioEl.valChunks.textContent = audioEl.valVerifiedOk.textContent = audioEl.valVerifiedFail.textContent = '0';
        audioEl.valRate.textContent = '0';
        audioEl.valSignLatency.textContent = '0.0';
        audioEl.verifyLog.replaceChildren();
        audioEl.overlay.classList.add('hidden');
        drawAudioWaveform(session);
        connectAudioChannel(session, 'encode');
        connectAudioChannel(session, 'decode');
        startAudioSigningInterval(session);
        updateAudioCaptureButtons();
        updateAudioStegoInfo();
    } catch (error) {
        if (!isCurrentAudioSession(session)) return;
        stopMicrophone('Microphone startup failed; signed-chunk recording stopped.');
        setAudioOverlay('❌ Microphone unavailable', error.message || 'Allow microphone access and try again');
        showToast(error.message || 'Microphone startup failed', 'error');
    }
}

// Only the latest raw input buffer is retained for a sampled signing request.
// Raw microphone samples are never added to an archive or a playback control.
function handleAudioProcess(session, event) {
    event.outputBuffer.getChannelData(0).fill(0);
    if (!isCurrentAudioSession(session) || !session.active) return;
    const input = event.inputBuffer.getChannelData(0);
    const pcm = new Uint8Array(input.length * 2);
    const view = new DataView(pcm.buffer);
    for (let i = 0; i < input.length; i++) {
        const sample = Math.max(-1, Math.min(1, input[i]));
        view.setInt16(i * 2, sample < 0 ? sample * 0x8000 : sample * 0x7fff, true);
    }
    const endOffset = performance.now() - session.startedPerfMs;
    const durationMs = input.length * 1000 / session.context.sampleRate;
    session.lastChunk = {
        pcm, captureIndex: ++session.captureCount, durationMs,
        captureStartOffsetMs: endOffset - durationMs,
        captureEndOffsetMs: endOffset,
        captureStartedAt: new Date(session.startedWallMs + endOffset - durationMs).toISOString(),
        captureEndedAt: new Date(session.startedWallMs + endOffset).toISOString(),
    };
}

function sendAudioChunkForSigning(session) {
    if (!isCurrentAudioSession(session) || !session.active || session.pendingSign) return;
    const socket = session.encode.socket;
    const chunk = session.lastChunk;
    if (!chunk || chunk.captureIndex <= session.lastSubmittedCaptureIndex || !socket || socket.readyState !== WebSocket.OPEN) return;
    const { pcm, ...capture } = chunk;
    const pending = {
        ...capture, byteLength: pcm.byteLength, sampleRate: session.context.sampleRate,
        channels: 1, lsbBits: audioConfig.lsbBits, requestedAt: new Date().toISOString(),
        archive: audioRecording ? audioArchive : null, timeout: null,
    };
    session.pendingSign = pending;
    session.latestSigned = null;
    resetAudioVerification('Signing a sampled chunk — verification pending');
    pending.timeout = setTimeout(() => {
        if (!isCurrentAudioSession(session) || session.pendingSign !== pending) return;
        showToast('Audio signing timed out; reconnecting only the encode channel.', 'error');
        failAudioChannel(session, 'encode', socket);
    }, AUDIO_REPLY_TIMEOUT_MS);
    try {
        socket.send(JSON.stringify({
            type: 'audio_frame',
            chunk_index: capture.captureIndex,
            sample_rate: pending.sampleRate,
            channels: pending.channels,
            buffer_size: pcm.byteLength / 2,
            lsb_bits: pending.lsbBits,
            pcm_base64: arrayBufferToBase64(pcm.buffer),
        }));
        session.lastSubmittedCaptureIndex = capture.captureIndex;
    } catch (error) {
        showToast('Audio signing request failed; reconnecting encode.', 'error');
        failAudioChannel(session, 'encode', socket);
    }
}

function startAudioSigningInterval(session) {
    clearInterval(session.signInterval);
    session.signInterval = setInterval(() => sendAudioChunkForSigning(session), audioConfig.signRateMs);
}

function failAudioChannel(session, name, socket) {
    if (!isCurrentAudioSession(session) || session[name].socket !== socket) return;
    closeAudioChannel(session, name);
    if (name === 'encode') {
        clearAudioSigning(session);
        session.latestSigned = null;
        clearSignedAudioPlayer();
    }
    resetAudioVerification(`Audio ${name} disconnected — reconnecting; no current verdict`);
    session[name].reconnectTimer = setTimeout(() => connectAudioChannel(session, name), AUDIO_RECONNECT_MS);
}

function connectAudioChannel(session, name) {
    if (!isCurrentAudioSession(session) || !session.active) return;
    const channel = session[name];
    clearTimeout(channel.reconnectTimer);
    channel.reconnectTimer = null;
    if (channel.socket) return;
    let socket;
    try {
        socket = new WebSocket(wsUrl(`/ws/audio/${name}`));
    } catch (error) {
        resetAudioVerification(`Audio ${name} unavailable — reconnecting`);
        channel.reconnectTimer = setTimeout(() => connectAudioChannel(session, name), AUDIO_RECONNECT_MS);
        return;
    }
    channel.socket = socket;
    const current = () => isCurrentAudioSession(session) && channel.socket === socket;
    channel.openTimer = setTimeout(() => failAudioChannel(session, name, socket), AUDIO_REPLY_TIMEOUT_MS);
    socket.onopen = () => {
        if (!current()) return;
        clearTimeout(channel.openTimer);
        channel.openTimer = null;
        if (name === 'encode') {
            clearAudioSigning(session);
        } else {
            channel.pollTimer = setInterval(() => pollAudioDecode(session), 300);
            pollAudioDecode(session);
        }
    };
    socket.onmessage = event => {
        if (!current()) return;
        if (name === 'encode') handleAudioEncodeMessage(session, socket, event);
        else handleAudioDecodeMessage(session, socket, event);
    };
    socket.onclose = socket.onerror = () => failAudioChannel(session, name, socket);
}

function audioFrameIdentity(value) {
    if (Number.isSafeInteger(value) && value >= 0) return String(value);
    if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value)) return null;
    if (value.length === 20 && value > '18446744073709551615') return null;
    return value;
}

function signedAudioMetadata(session, msg, pending, pcm) {
    if (audioFrameIdentity(msg.frame_index) === null ||
        audioFrameIdentity(msg.cache_revision) === null ||
        !Number.isInteger(msg.lsb_bits) || msg.lsb_bits !== pending.lsbBits ||
        msg.sample_rate !== pending.sampleRate || msg.channels !== pending.channels ||
        typeof msg.public_key !== 'string' || !/^[0-9a-f]{64}$/i.test(msg.public_key) ||
        typeof msg.embedding_key !== 'string' || !/^[0-9a-f]{64}$/i.test(msg.embedding_key) ||
        (msg.backend !== undefined && msg.backend !== 'ed25519') ||
        pcm.byteLength !== pending.byteLength || pcm.byteLength === 0 ||
        pcm.byteLength % (2 * msg.channels) !== 0) {
        throw new Error('Signed audio reply has missing or inconsistent PCM/extraction metadata; no artifact was recorded.');
    }
    return {
        frame_index: msg.frame_index, public_key: msg.public_key, embedding_key: msg.embedding_key,
        cache_revision: msg.cache_revision,
        lsb_bits: msg.lsb_bits, sample_rate: msg.sample_rate, channels: msg.channels,
        format: 'pcm_s16le', stego_type: 'audio', kernel: 'lsb', signing_backend: 'ed25519',
        sample_count: pcm.byteLength / 2, duration_ms: pending.durationMs,
        capture_index: pending.captureIndex,
        capture_started_at: pending.captureStartedAt, capture_ended_at: pending.captureEndedAt,
        capture_start_offset_ms: pending.captureStartOffsetMs,
        capture_end_offset_ms: pending.captureEndOffsetMs,
        capture_session_started_at: new Date(session.startedWallMs).toISOString(),
        capture_time_source: 'browser_audio_callback_estimate',
        requested_at: pending.requestedAt, received_at: new Date().toISOString(),
        archive_mode: 'sampled_signed_chunks', continuous: false,
    };
}

function rejectSignedAudio(session, message) {
    clearAudioSigning(session);
    session.latestSigned = null;
    clearSignedAudioPlayer();
    resetAudioVerification('Signed audio unavailable — no current verdict');
    if (audioRecording) finishAudioRecording('Invalid signed reply; recording stopped and previous valid chunks exported.');
    showToast(message, 'error');
}

function handleAudioEncodeMessage(session, socket, event) {
    let msg;
    try {
        msg = JSON.parse(event.data);
        if (!msg || typeof msg !== 'object' || Array.isArray(msg)) throw new Error('Invalid audio reply object');
    } catch (error) {
        rejectSignedAudio(session, 'Invalid audio encode reply; recording stopped.');
        failAudioChannel(session, 'encode', socket);
        return;
    }
    if (msg.type === 'error' || msg.type === 'encode_error' || msg.type === 'audio_error') {
        clearAudioSigning(session);
        session.latestSigned = null;
        resetAudioVerification('Audio signing failed — no current verdict');
        showToast(typeof msg.error === 'string' ? msg.error : 'Audio signing failed', 'error');
        return;
    }
    if (msg.type !== 'audio_signed' || !session.pendingSign) return;
    const pending = session.pendingSign;
    clearAudioSigning(session);
    try {
        if (!window.SignedArchive || typeof msg.pcm_s16le !== 'string' ||
            msg.pcm_s16le.length !== 4 * Math.ceil(pending.byteLength / 3)) {
            throw new Error('Signed PCM reply or WAV/archive support is unavailable; no artifact was recorded.');
        }
        const pcm = window.SignedArchive.decodeBase64(msg.pcm_s16le);
        const metadata = signedAudioMetadata(session, msg, pending, pcm);
        const wav = window.SignedArchive.wav(pcm, metadata.sample_rate, metadata.channels);
        displaySignedAudioChunk(wav, metadata);
        const returnedHash = msg.payload?.hash ?? msg.hash;
        session.latestSigned = {
            frameIndex: audioFrameIdentity(msg.frame_index), publicKey: msg.public_key,
            cacheRevision: audioFrameIdentity(msg.cache_revision), lsbBits: msg.lsb_bits,
            hash: typeof returnedHash === 'string' && /^[0-9a-f]{64}$/i.test(returnedHash) ? returnedHash.toLowerCase() : null,
            verificationIdentity: null, countedResult: null,
        };
        audioStats.chunks++;
        audioStats.sampleFrames += pcm.byteLength / (2 * metadata.channels);
        audioStats.signLatencyUs = Number.isFinite(msg.sign_us) && msg.sign_us >= 0 ? msg.sign_us : 0;
        audioEl.valChunks.textContent = audioStats.chunks;
        audioEl.valSignLatency.textContent = audioStats.signLatencyUs.toFixed(1);
        const elapsed = (Date.now() - session.startedWallMs) / 1000;
        audioEl.valRate.textContent = Math.floor(audioStats.sampleFrames / Math.max(elapsed, 0.001)).toLocaleString();
        audioEl.valRate.title = 'Returned signed sample frames per second; not continuous microphone capture';
        recordSignedAudioChunk(wav, metadata, pending.archive);
        resetAudioVerification('Returned signed PCM received — awaiting server verification');
        pollAudioDecode(session);
        if (msg.ots) window.OtsPanel?.applyMetrics(msg.ots);
        window.OtsPanel?.refreshStatus();
    } catch (error) {
        rejectSignedAudio(session, error.message || 'Signed audio reply could not be used; recording stopped.');
    }
}

function pollAudioDecode(session) {
    if (!isCurrentAudioSession(session) || !session.active || !session.latestSigned) return;
    const channel = session.decode;
    const socket = channel.socket;
    if (!socket || socket.readyState !== WebSocket.OPEN || channel.pendingPoll) return;
    const pending = { target: session.latestSigned, timeout: null };
    channel.pendingPoll = pending;
    pending.timeout = setTimeout(() => {
        if (!isCurrentAudioSession(session) || channel.pendingPoll !== pending) return;
        failAudioChannel(session, 'decode', socket);
    }, AUDIO_REPLY_TIMEOUT_MS);
    try {
        socket.send(JSON.stringify({ type: 'decode_request' }));
    } catch (error) {
        failAudioChannel(session, 'decode', socket);
    }
}

function handleAudioDecodeMessage(session, socket, event) {
    let msg;
    try {
        msg = JSON.parse(event.data);
        if (!msg || typeof msg !== 'object' || Array.isArray(msg)) throw new Error('Invalid audio reply object');
    } catch (error) {
        failAudioChannel(session, 'decode', socket);
        return;
    }
    if (msg.type !== 'audio_verify' && msg.type !== 'error') return;
    const pending = session.decode.pendingPoll;
    if (!pending) return;
    clearTimeout(pending.timeout);
    session.decode.pendingPoll = null;
    const target = pending.target;
    if (target !== session.latestSigned) return;
    const payload = msg.payload;
    const frameIndex = audioFrameIdentity(msg.frame_index ?? msg.chunk_index ?? payload?.frame_index ?? payload?.chunk_index);
    const revision = audioFrameIdentity(msg.cache_revision);
    const payloadHash = typeof payload?.hash === 'string' && /^[0-9a-f]{64}$/i.test(payload.hash) ? payload.hash.toLowerCase() : null;
    const matchingRevision = target.cacheRevision !== null && revision === target.cacheRevision;
    if (msg.type === 'error' || msg.waiting || msg.pending || msg.verified_stale || msg.stale ||
        typeof msg.verified !== 'boolean' || frameIndex !== target.frameIndex ||
        !matchingRevision ||
        (msg.verified && (!payloadHash || (target.hash && payloadHash !== target.hash))) ||
        (msg.lsb_bits !== undefined && msg.lsb_bits !== target.lsbBits) ||
        (msg.backend !== undefined && msg.backend !== 'ed25519') ||
        (msg.public_key !== undefined && msg.public_key !== target.publicKey)) {
        resetAudioVerification('Verification waiting, stale, or unknown — no current verdict');
        return;
    }
    // A cache revision identifies the returned carrier even when extraction fails
    // and no payload/hash can be recovered. Per-connection indices alone cannot.
    const hash = payloadHash || target.hash;
    const identity = `revision:${revision}:${frameIndex}:${target.publicKey}`;
    if (target.verificationIdentity && target.verificationIdentity !== identity) {
        resetAudioVerification('Verification identity changed — awaiting the current chunk');
        return;
    }
    target.verificationIdentity = identity;
    if (target.countedResult !== msg.verified) {
        if (target.countedResult !== null) audioStats[target.countedResult ? 'verifiedOk' : 'verifiedFail']--;
        audioStats[msg.verified ? 'verifiedOk' : 'verifiedFail']++;
        target.countedResult = msg.verified;
        addAudioVerifyLogEntry(msg, frameIndex);
    }
    const latency = Number.isFinite(msg.verify_us) && msg.verify_us >= 0 ? msg.verify_us : 0;
    audioEl.verifyWaiting.classList.add('hidden');
    audioEl.verifyResult.classList.remove('hidden');
    audioEl.verifyStatusBanner.className = `verify-status-banner ${msg.verified ? 'verified' : 'failed'}`;
    audioEl.verifyStatusBanner.title = 'Server-reported check of a returned chunk; this is not independent verification of an exported WAV.';
    audioEl.verifyStatusIcon.textContent = msg.verified ? '✅' : '❌';
    audioEl.verifyStatusText.textContent = msg.verified ? 'Server reports valid Ed25519 signature' : 'Server reports invalid audio signature';
    audioEl.fieldChunkIndex.textContent = frameIndex;
    audioEl.fieldHash.textContent = hash ? hash.slice(0, 16) + '…' + hash.slice(-6) : '—';
    audioEl.fieldHash.title = hash || '';
    audioEl.fieldSigPreview.textContent = typeof payload?.signature_preview === 'string' ? payload.signature_preview.slice(0, 128) : '—';
    audioEl.fieldBackend.textContent = 'Ed25519';
    audioEl.fieldBackend.title = `Signer public key: ${target.publicKey}`;
    audioEl.fieldVerifyLatency.textContent = latency.toFixed(0) + ' μs';
    audioEl.valVerifiedOk.textContent = audioStats.verifiedOk;
    audioEl.valVerifiedFail.textContent = audioStats.verifiedFail;
    audioEl.valVerifyLatency.textContent = latency.toFixed(1);
}

function addAudioVerifyLogEntry(msg, frameIndex) {
    const entry = document.createElement('div');
    entry.className = `log-entry ${msg.verified ? 'log-ok' : 'log-fail'}`;
    const values = [
        ['log-time', new Date().toLocaleTimeString('en-US', { hour12: false })],
        ['log-icon', msg.verified ? '✅' : '❌'],
        ['log-frame', `#${frameIndex}`],
        ['log-status', `${msg.verified ? 'OK' : 'INVALID'} · ${(Number.isFinite(msg.verify_us) ? msg.verify_us : 0).toFixed(0)} μs`],
    ];
    for (const [className, text] of values) {
        const span = document.createElement('span');
        span.className = className;
        span.textContent = text;
        entry.appendChild(span);
    }
    if (audioEl.verifyLog.children.length >= 20) audioEl.verifyLog.lastChild.remove();
    audioEl.verifyLog.prepend(entry);
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUDIO CONFIG
// ═══════════════════════════════════════════════════════════════════════════════

function updateAudioStegoInfo() {
    const capacityBits = audioConfig.bufferSize * audioConfig.lsbBits;
    const payloadSize = 109;
    audioEl.infoPayloadSize.textContent = payloadSize + ' bytes';
    audioEl.infoHashAlgo.textContent = 'BLAKE3 (256-bit)';
    audioEl.infoSigAlgo.textContent = 'Ed25519 (512-bit)';
    audioEl.infoCapacity.textContent = Math.floor(capacityBits / 8) + ' B (' + capacityBits.toLocaleString() + ' bits)';
    audioEl.infoUtilization.textContent = ((payloadSize * 8 / capacityBits) * 100).toFixed(3) + '%';
    audioEl.infoChannels.textContent = `1 (mono), ${audioSession?.context?.sampleRate || audioConfig.sampleRate} Hz${audioSession?.active ? ' actual' : ' requested'}`;
}

function changeAudioCaptureSetting(setting, value) {
    const restart = Boolean(audioSession);
    // Stop/export before mutating a requested format; no archive can span restarts.
    stopMicrophone('Capture format changed; exporting signed chunks before restart.');
    audioConfig[setting] = value;
    updateAudioStegoInfo();
    if (restart) startMicrophone();
}

function initAudioConfigListeners() {
    if (audioEl.cfgLsbBits) {
        audioEl.cfgLsbBits.addEventListener('input', () => {
            audioConfig.lsbBits = parseInt(audioEl.cfgLsbBits.value, 10);
            audioEl.cfgLsbBitsVal.textContent = audioConfig.lsbBits;
            updateAudioStegoInfo();
        });
    }
    if (audioEl.cfgSignBackend) {
        audioEl.cfgSignBackend.value = 'ed25519';
        for (const option of audioEl.cfgSignBackend.options) {
            if (option.value !== 'ed25519') option.remove();
        }
        audioEl.cfgSignBackend.disabled = true;
        audioEl.cfgSignBackend.title = 'The dashboard uses its actual Ed25519 signer only.';
    }
    if (audioEl.cfgSignRate) {
        audioEl.cfgSignRate.addEventListener('input', () => {
            audioConfig.signRateMs = parseInt(audioEl.cfgSignRate.value, 10);
            audioEl.cfgSignRateVal.textContent = (1000 / audioConfig.signRateMs).toFixed(1) + '/s';
            if (audioSession?.active) startAudioSigningInterval(audioSession);
        });
    }
    if (audioEl.cfgBufferSize) {
        audioEl.cfgBufferSize.addEventListener('change', () => changeAudioCaptureSetting('bufferSize', parseInt(audioEl.cfgBufferSize.value, 10)));
    }
    if (audioEl.cfgSampleRate) {
        audioEl.cfgSampleRate.addEventListener('change', () => changeAudioCaptureSetting('sampleRate', parseInt(audioEl.cfgSampleRate.value, 10)));
    }
    updateAudioStegoInfo();
}

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

// ═══════════════════════════════════════════════════════════════════════════════
// SAMPLED SIGNED CHUNKS — BOUNDED WAV + MANIFEST ARCHIVE
// ═══════════════════════════════════════════════════════════════════════════════

function toggleAudioRecording() {
    if (audioRecording || audioArchive) {
        finishAudioRecording();
        return;
    }
    if (!audioSession?.active || !window.SignedArchive) {
        showToast('Start the microphone with signed archive support available first.', 'error');
        return;
    }
    try {
        audioArchive = window.SignedArchive.create('audio');
        audioRecordingFormat = { sampleRate: audioSession.context.sampleRate, channels: 1 };
        audioArchiveLastCaptureEnd = null;
        audioRecording = true;
        updateAudioCaptureButtons();
        showToast('Archiving sampled returned signed WAV chunks, not continuous microphone audio. Capture estimates and gaps are in the manifest.', 'info');
    } catch (error) {
        audioArchive = null;
        audioRecordingFormat = null;
        showToast(error.message || 'Could not start signed audio archive', 'error');
    }
}

function recordSignedAudioChunk(wav, metadata, requestedArchive) {
    if (!audioRecording || !audioArchive || requestedArchive !== audioArchive) return;
    if (metadata.sample_rate !== audioRecordingFormat.sampleRate || metadata.channels !== audioRecordingFormat.channels) {
        finishAudioRecording('Audio format changed; recording stopped before any mixed-rate chunk.');
        showToast('Signed chunk format differs from the archive format; chunk not recorded.', 'error');
        return;
    }
    const gapMs = audioArchiveLastCaptureEnd === null ? null : Math.max(0, metadata.capture_start_offset_ms - audioArchiveLastCaptureEnd);
    const name = `chunks/${String(audioArchive.entries.length + 1).padStart(6, '0')}-frame-${metadata.frame_index}-revision-${metadata.cache_revision}.wav`;
    if (!audioArchive.add(name, wav, { ...metadata, gap_before_ms: gapMs })) {
        finishAudioRecording('Archive limit reached (64 MiB / 300 entries); recording stopped and stored signed chunks exported.');
        showToast('Archive cap reached. Recording stopped; the current chunk was not added. Stored chunks were exported or remain available via Export archive.', 'error');
        return;
    }
    audioArchiveLastCaptureEnd = metadata.capture_end_offset_ms;
}

function finishAudioRecording(reason = '') {
    audioRecording = false;
    if (!audioArchive) {
        updateAudioCaptureButtons();
        return;
    }
    if (audioArchive.entries.length === 0) {
        audioArchive = null;
        audioRecordingFormat = null;
        audioArchiveLastCaptureEnd = null;
        updateAudioCaptureButtons();
        showToast('Recording stopped. No signed reply chunks were available to export.', 'info');
        return;
    }
    let exported = false;
    try {
        exported = audioArchive.finish();
    } catch (error) {
        console.error('[audio-record] Signed archive export failed:', error);
    }
    if (exported) {
        audioArchive = null;
        audioRecordingFormat = null;
        audioArchiveLastCaptureEnd = null;
        showToast(reason || 'Sampled signed WAV archive exported; gaps are described in the manifest.', 'info');
    } else {
        showToast('Recording stopped, but archive export failed. Stored signed chunks are retained; use Export archive to retry.', 'error');
    }
    updateAudioCaptureButtons();
}

document.addEventListener('DOMContentLoaded', () => {
    initAudioConfigListeners();
    updateAudioCaptureButtons();
    clearSignedAudioPlayer();
    resetAudioVerification('Start microphone to sign sampled audio chunks');
    if (audioEl.startMicBtn) audioEl.startMicBtn.addEventListener('click', () => startMicrophone());
    if (audioEl.stopMicBtn) audioEl.stopMicBtn.addEventListener('click', () => stopMicrophone());
    const recordAudioBtn = document.getElementById('record-audio-btn');
    if (recordAudioBtn) recordAudioBtn.addEventListener('click', toggleAudioRecording);
});
