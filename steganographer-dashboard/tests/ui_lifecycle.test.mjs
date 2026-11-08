import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

// Controlled browser boundaries exercise the served scripts themselves. These
// tests cover event ownership, not browser rendering, transport interoperability
// or cryptographic verification (those require the real dashboard smoke cases).
function browserHarness() {
    const nodes = new Map(), sockets = [], timers = new Map(), blobs = [];
    let timerId = 0, bitmapFactory = async () => ({ width: 64, height: 64, close() {} });
    function element() {
        const classes = new Set(), attributes = new Map(), children = [];
        const node = {
            children, dataset: {}, style: {}, textContent: '', title: '', className: '',
            readyState: 2, videoWidth: 64, videoHeight: 64, width: 64, height: 64,
            classList: {
                add: (...names) => names.forEach(name => classes.add(name)),
                remove: (...names) => names.forEach(name => classes.delete(name)),
                contains: name => classes.has(name),
                toggle(name, on = !classes.has(name)) { if (on) classes.add(name); else classes.delete(name); return on; },
            },
            setAttribute: (name, value) => attributes.set(name, value),
            removeAttribute: name => attributes.delete(name),
            getAttribute: name => attributes.get(name),
            querySelector: name => { if (!node[name]) node[name] = element(); return node[name]; },
            appendChild(child) { children.push(child); child.parent = node; },
            append(child) { node.appendChild(child); },
            prepend(child) { children.unshift(child); child.parent = node; },
            replaceChildren() { children.length = 0; },
            remove() { if (node.parent) node.parent.children.splice(node.parent.children.indexOf(node), 1); },
            get lastChild() { return children.at(-1); },
            getContext: () => ({ drawImage() {}, clearRect() {}, getImageData: () => ({ width: 64, height: 64 }) }),
            toBlob(callback) { blobs.push(callback); },
            pause() {}, load() {}, click() {}, addEventListener() {},
        };
        return node;
    }
    const get = id => { if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id); };
    class Socket {
        static OPEN = 1;
        static CLOSING = 2;
        constructor(url) { this.url = url; this.readyState = 0; this.sent = []; sockets.push(this); }
        open() { this.readyState = 1; this.onopen?.(); }
        send(data) { this.sent.push(data); }
        close() { if (this.readyState === 3) return; this.readyState = 3; this.onclose?.(); }
    }
    const context = vm.createContext({
        console, Blob, URL, TextEncoder, TextDecoder, Uint8Array, Uint32Array, DataView, ArrayBuffer,
        performance: { now: () => 1000 },
        atob: text => Buffer.from(text, 'base64').toString('binary'),
        btoa: text => Buffer.from(text, 'binary').toString('base64'),
        document: { readyState: 'loading', getElementById: get, createElement: element, addEventListener() {}, body: element() },
        window: { addEventListener() {} },
        location: { protocol: 'http:', host: 'localhost', href: 'http://localhost/?transport=websocket' },
        sessionStorage: { getItem: () => null }, localStorage: { getItem: () => null },
        WebSocket: Socket,
        setTimeout: callback => { timers.set(++timerId, callback); return timerId; },
        clearTimeout: id => timers.delete(id),
        setInterval: callback => { timers.set(++timerId, callback); return timerId; },
        clearInterval: id => timers.delete(id), requestAnimationFrame() {}, cancelAnimationFrame() {},
        createImageBitmap: blob => bitmapFactory(blob),
    });
    const run = code => vm.runInContext(code, context);
    for (const name of ['app.js', 'audio_tab.js']) {
        vm.runInContext(readFileSync(new URL(`../src/static/${name}`, import.meta.url), 'utf8'), context, { filename: name });
    }
    function startVideo() {
        run("serverVersion = 'test'; cameraActive = true; connectWsTransport();");
        sockets.at(-2).open(); sockets.at(-1).open();
    }
    async function submitVideo(bytes = new Uint8Array([1, 2, 3])) {
        run('sendFrameForSigning()');
        await blobs.shift()(new Blob([bytes]));
    }
    function startAudio() {
        run(`audioSession = {
            active: true, disposed: false, encode: createAudioChannel(), decode: createAudioChannel(),
            context: { sampleRate: 44100 }, startedWallMs: Date.now(), captureCount: 1, lastSubmittedCaptureIndex: 0,
            lastChunk: { pcm: new Uint8Array(4096), captureIndex: 1, durationMs: 46,
                captureStartOffsetMs: 0, captureEndOffsetMs: 46 }, pendingSign: null, latestSigned: null,
        }; connectAudioChannel(audioSession, 'encode'); connectAudioChannel(audioSession, 'decode');`);
        sockets.at(-2).open(); sockets.at(-1).open();
    }
    return { run, get, sockets, timers, startVideo, submitVideo, startAudio,
        bitmap(factory) { bitmapFactory = factory; },
    };
}

const encodedReply = JSON.stringify({ type: 'encoded_frame', image_mime: 'image/png', frame: 'AQID',
    public_key: '11'.repeat(32), frame_index: 7, cache_revision: 19, lsb_bits: 1, width: 64, height: 64 });
const decodedReply = JSON.stringify({ type: 'decoded_frame', verified: true, frame_index: 7,
    cache_revision: 19, payload: { hash: '22'.repeat(32) } });

for (const action of ['close', 'error', 'malformed reply', 'server error']) {
    test(`video decode ${action} does not release an encode request`, async () => {
        const h = browserHarness(); h.startVideo(); await h.submitVideo();
        const decode = h.sockets[1];
        if (action === 'close') decode.close();
        else if (action === 'error') decode.onerror();
        else decode.onmessage({ data: action === 'malformed reply' ? '{' : '{"type":"error"}' });
        assert.equal(h.run('pendingVideoSign !== null'), true);
        assert.equal(h.run('encodeWs.sent.length'), 1);
        h.run('sendFrameForSigning()');
        assert.equal(h.run('encodeWs.sent.length'), 1, 'no second encode admitted while first belongs to encode');
        await h.run(`handleEncodeMessage(${encodedReply})`);
        assert.equal(h.run('pendingVideoSign'), null);
        assert.equal(h.run('latestVideoFrame.cache_revision'), 19);
    });
}

test('encode reconnect cannot revive a historical green result', async () => {
    const h = browserHarness(); h.startVideo(); await h.submitVideo();
    await h.run(`handleEncodeMessage(${encodedReply})`);
    h.run(`handleDecodeMessage(${decodedReply})`);
    assert.equal(h.run('lastVerifyData.verified'), true);
    assert.match(h.get('verify-log').children[0].textContent, /History/);
    h.sockets[0].close();
    h.run("connectVideoSocket('encode');"); h.sockets.at(-1).open();
    h.run(`handleDecodeMessage(${decodedReply})`);
    assert.equal(h.run('latestVideoFrame'), null);
    assert.equal(h.run('lastVerifyData.verified'), null);
    assert.notEqual(h.get('verify-status-banner').className, 'verify-status-banner status-ok');
    assert.equal(h.get('verify-log').children.length, 1, 'history remains separately labeled');
});

test('late bitmap from an old encode generation cannot clear or publish into its successor', async () => {
    const h = browserHarness(); h.startVideo(); await h.submitVideo();
    let resolveImage, closed = 0;
    h.bitmap(() => new Promise(resolve => { resolveImage = resolve; }));
    const oldReply = h.run(`handleEncodeMessage(${encodedReply})`);
    h.sockets[0].close();
    h.run("connectVideoSocket('encode');"); h.sockets.at(-1).open();
    await h.submitVideo();
    resolveImage({ width: 64, height: 64, close() { closed++; } });
    await oldReply;
    assert.equal(closed, 1);
    assert.equal(h.run('latestVideoFrame'), null);
    assert.equal(h.run('pendingVideoSign !== null'), true);
});

test('recording started after video submission cannot claim its returned frame', async () => {
    const h = browserHarness(); h.startVideo(); await h.submitVideo();
    h.run('toggleVideoRecording()');
    await h.run(`handleEncodeMessage(${encodedReply})`);
    assert.equal(h.run('videoArchive.entries.length'), 0);
});

test('video archive restart during image decoding cannot claim the previous submission', async () => {
    const h = browserHarness(); h.startVideo(); h.run('toggleVideoRecording()'); await h.submitVideo();
    let resolveImage;
    h.bitmap(() => new Promise(resolve => { resolveImage = resolve; }));
    const reply = h.run(`handleEncodeMessage(${encodedReply})`);
    h.run('toggleVideoRecording(); toggleVideoRecording();');
    resolveImage({ width: 64, height: 64, close() {} }); await reply;
    assert.equal(h.run('videoArchive.entries.length'), 0);
    assert.equal(h.run('videoRecording'), true);
});

test('same video submission archive receives the exact returned bytes once', async () => {
    const h = browserHarness(); h.startVideo(); h.run('toggleVideoRecording()'); await h.submitVideo();
    await h.run(`handleEncodeMessage(${encodedReply})`);
    await h.run(`handleEncodeMessage(${encodedReply})`);
    assert.equal(h.run('videoArchive.entries.length'), 1);
    assert.equal(h.run('videoArchive.entries[0].bytes'), 3);
    assert.equal(h.run('videoArchive.entries[0].cache_revision'), 19);
});

test('RTC errors belonging to decode cannot release the pending encode', async () => {
    const h = browserHarness(); h.startVideo(); await h.submitVideo();
    h.run('pendingVideoSign.rtcId = 40;');
    h.run('handleWebRtcMessage(JSON.stringify({ type: "error", msg_id: 41 }));');
    assert.equal(h.run('pendingVideoSign !== null'), true);
    h.run('handleWebRtcMessage(JSON.stringify({ type: "encode_error", msg_id: 40 }));');
    assert.equal(h.run('pendingVideoSign'), null);
});

test('RTC checks complete serialized request bytes before sending any chunk', () => {
    const h = browserHarness();
    h.run('webrtcDc = { sent: [], send(chunk) { this.sent.push(chunk); } };');
    h.run('webRtcSendChunked(1, new Uint8Array(WEBRTC_MESSAGE_MAX_BYTES));');
    assert.equal(h.run('webrtcDc.sent.length'), Math.ceil(4194304 / (16384 - 20)));
    assert.equal(h.run('webrtcDc.sent.every(chunk => chunk.byteLength <= 16384)'), true);
    h.run('webrtcDc.sent.length = 0;');
    assert.throws(() => h.run('webRtcSendChunked(2, new Uint8Array(WEBRTC_MESSAGE_MAX_BYTES + 1));'), /serialized request.*smaller camera resolution.*WebSocket/);
    assert.equal(h.run('webrtcDc.sent.length'), 0);
    assert.throws(() => h.run(`webRtcSendChunked(3, new TextEncoder().encode(JSON.stringify({
        kind: 'encode', msg_id: 3, sent_unix_ms: 1, jpeg_b64: 'A'.repeat(4 * 1024 * 1024),
    })));`), /including JSON\/base64/);
    assert.equal(h.run('webrtcDc.sent.length'), 0, 'a 3 MiB PNG grows beyond 4 MiB after base64 plus JSON');
});

test('audio decode failure preserves encode ownership and its archive binding', () => {
    const h = browserHarness(); h.startAudio(); h.run("serverVersion = 'test'; toggleAudioRecording(); sendAudioChunkForSigning(audioSession);");
    h.sockets[1].onerror();
    assert.equal(h.run('audioSession.pendingSign !== null'), true);
    assert.equal(h.run('ownsAudioArchive(audioSession.pendingSign)'), true);
    assert.equal(h.run('audioSession.encode.socket.sent.length'), 1);
});

for (const response of ['invalid JSON', 'invalid signed PCM']) {
    test(`audio ${response} from an old submission cannot stop a new archive`, () => {
        const h = browserHarness(); h.startAudio();
        h.run("serverVersion = 'test'; toggleAudioRecording(); sendAudioChunkForSigning(audioSession); toggleAudioRecording(); toggleAudioRecording();");
        h.sockets[0].onmessage({ data: response === 'invalid JSON' ? '{' : '{"type":"audio_signed","pcm_s16le":""}' });
        assert.equal(h.run('audioRecording'), true);
        assert.equal(h.run('audioArchive.entries.length'), 0);
    });
}

test('audio invalid reply stops only its own active submission archive', () => {
    const h = browserHarness(); h.startAudio();
    h.run("serverVersion = 'test'; toggleAudioRecording(); sendAudioChunkForSigning(audioSession);");
    h.sockets[0].onmessage({ data: '{"type":"audio_signed","pcm_s16le":""}' });
    assert.equal(h.run('audioRecording'), false);
    assert.equal(h.run('audioArchive'), null);
});

test('audio archive admission is bound to session, encode generation and archive identity', () => {
    const h = browserHarness(); h.startAudio();
    h.run("serverVersion = 'test'; toggleAudioRecording(); sendAudioChunkForSigning(audioSession); globalThis.submission = audioSession.pendingSign;");
    assert.equal(h.run('ownsAudioArchive(submission)'), true);
    h.run('audioSession.encode.generation++;');
    assert.equal(h.run('ownsAudioArchive(submission)'), false);
    h.run('audioSession.encode.generation--; toggleAudioRecording(); toggleAudioRecording();');
    assert.equal(h.run('ownsAudioArchive(submission)'), false);
    h.run('recordSignedAudioChunk(new Uint8Array([1, 2]), { sample_rate: 44100, channels: 1 }, submission);');
    assert.equal(h.run('audioArchive.entries.length'), 0);
});

test('RTC camera submission surfaces the serialized limit without sending or reconnecting', async () => {
    const h = browserHarness(); h.startVideo();
    h.run("transport = 'webrtc'; webrtcDc = { readyState: 'open', sent: [], send(chunk) { this.sent.push(chunk); } };");
    await h.submitVideo(new Uint8Array(3 * 1024 * 1024));
    assert.equal(h.run('webrtcDc.sent.length'), 0);
    assert.equal(h.run('pendingVideoSign'), null);
    assert.equal(h.run('transport'), 'webrtc', 'transport choice remains pinned until the user changes it');
    assert.match(h.get('toast-container').children.at(-1).textContent, /WebRTC transport limit.*smaller camera resolution.*WebSocket/);
});

test('audio receipt for its submission archive stores returned WAV metadata', () => {
    const h = browserHarness(); h.startAudio();
    h.run("serverVersion = 'test'; toggleAudioRecording(); sendAudioChunkForSigning(audioSession);");
    h.sockets[0].onmessage({ data: JSON.stringify({
        type: 'audio_signed', pcm_s16le: Buffer.alloc(4096).toString('base64'), frame_index: 4,
        cache_revision: 31, lsb_bits: 1, sample_rate: 44100, channels: 1,
        public_key: '11'.repeat(32), embedding_key: '22'.repeat(32), payload: { hash: '33'.repeat(32) },
    }) });
    assert.equal(h.run('audioArchive.entries.length'), 1);
    assert.equal(h.run('audioArchive.entries[0].bytes'), 4096 + 44);
    assert.equal(h.run('audioArchive.entries[0].cache_revision'), 31);
    assert.equal(h.run('audioSession.pendingSign'), null);
});
