'use strict';

// Run only against real --target nodejs output from wasm-bindgen whose CLI
// version exactly matches Cargo.lock. Usage: node tests/bindings.cjs <binding.js>
const assert = require('node:assert/strict');
const path = require('node:path');
if (!process.argv[2]) throw new Error('Supply the generated wasm-bindgen Node module path');
const wasm = require(path.resolve(process.argv[2]));
const payload = Uint8Array.from([0, 1, 127, 128, 254, 255]);
const id = new Uint8Array(16).fill(3);
const nonce = new Uint8Array(8).fill(9);
const encode = (bits, kind = 1, limits = null) =>
  wasm.packet_encode(payload, kind, id, nonce, bits, limits);
const parse = JSON.parse;
const packet = encode(1);
const rgb = new Uint8Array(packet.length * 8).fill(0x7f);
const pcm = new Uint8Array(packet.length * 16).fill(0x7f);

for (const bits of [-1, 0, 5, 255, 256, 257, 1.5, NaN, Infinity, -Infinity]) {
  for (const invoke of [
    () => encode(bits),
    () => wasm.capacity_rgb(rgb, bits),
    () => wasm.capacity_pcm_s16le(pcm, bits),
    () => wasm.embed_rgb(rgb, packet, bits),
    () => wasm.embed_pcm_s16le(pcm, packet, bits),
    () => wasm.extract_rgb(rgb, bits, null),
    () => wasm.extract_pcm_s16le(pcm, bits, null),
  ]) assert.throws(invoke, `accepted invalid strength ${bits}`);
}
for (const kind of [-1, 0, 6, 65535, 65536, 65537, 1.5, NaN, Infinity, -Infinity]) {
  assert.throws(() => encode(1, kind), `accepted invalid payload kind ${kind}`);
}
for (let kind = 1; kind <= 5; kind++) {
  assert.equal(parse(wasm.packet_decode(encode(1, kind), null)).payload_kind, kind);
}

function assertBody(report) {
  assert.equal(report.schema, 'steganographer.packet-report.v2');
  assert.equal(report.original_len, String(payload.length));
  assert.deepEqual(report.body, Array.from(payload));
}
for (let bits = 1; bits <= 4; bits++) {
  const encoded = encode(bits);
  assertBody(parse(wasm.packet_decode(encoded, null)));
  const units = Math.ceil(encoded.length * 8 / bits);
  for (const [name, stride] of [['rgb', 1], ['pcm_s16le', 2]]) {
    const carrier = new Uint8Array(units * stride).fill(0x7f);
    assert.ok(parse(wasm[`capacity_${name}`](carrier, bits)).max_packet_bytes >= encoded.length);
    const embedded = parse(wasm[`embed_${name}`](carrier, encoded, bits));
    assert.ok(Array.isArray(embedded.carrier));
    assert.equal(embedded.report.packet_bytes, encoded.length);
    const report = parse(wasm[`extract_${name}`](Uint8Array.from(embedded.carrier), bits, null));
    assertBody(report);
    assert.equal(report.bits_per_unit, bits);
  }
}

function crc32c(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) {
      crc = (crc >>> 1) ^ ((crc & 1) ? 0x82f63b78 : 0);
    }
  }
  return (~crc) >>> 0;
}
// Append the real protocol-v1 noncritical timestamp TLV (field 18), retaining
// the packet body/content digest and updating the public envelope extent/CRC.
function withTimestamp(encoded, timestamp) {
  const fullValue = new Uint8Array(8);
  new DataView(fullValue.buffer).setBigUint64(0, timestamp);
  let start = 0;
  while (start < 7 && fullValue[start] === 0) start++;
  const value = fullValue.subarray(start);
  const tlv = new Uint8Array(6 + value.length);
  const field = new DataView(tlv.buffer);
  field.setUint16(0, 18);
  field.setUint32(2, value.length);
  tlv.set(value, 6);
  const source = new DataView(encoded.buffer, encoded.byteOffset, encoded.byteLength);
  const oldLength = source.getUint32(8);
  const result = new Uint8Array(encoded.length + tlv.length);
  result.set(encoded.subarray(0, 32 + oldLength));
  result.set(tlv, 32 + oldLength);
  result.set(encoded.subarray(32 + oldLength), 32 + oldLength + tlv.length);
  const view = new DataView(result.buffer);
  view.setUint32(8, oldLength + tlv.length);
  view.setUint32(20, crc32c(result.subarray(32, 32 + oldLength + tlv.length)));
  return result;
}
for (const timestamp of [9007199254740993n, 18446744073709551615n]) {
  const exact = withTimestamp(encode(4), timestamp);
  const report = parse(wasm.packet_decode(exact, null));
  assertBody(report);
  assert.equal(report.created_at_unix, timestamp.toString());
  assert.equal(BigInt(report.created_at_unix), timestamp);
  for (const [name, stride] of [['rgb', 1], ['pcm_s16le', 2]]) {
    const embedded = parse(wasm[`embed_${name}`](new Uint8Array(exact.length * 2 * stride), exact, 4));
    const extracted = parse(wasm[`extract_${name}`](Uint8Array.from(embedded.carrier), 4, null));
    assertBody(extracted);
    assert.equal(extracted.created_at_unix, timestamp.toString());
  }
}
assert.equal(parse(wasm.packet_decode(packet, null)).created_at_unix, null);

const goodRgb = Uint8Array.from(parse(wasm.embed_rgb(rgb, packet, 1)).carrier);
const goodPcm = Uint8Array.from(parse(wasm.embed_pcm_s16le(pcm, packet, 1)).carrier);
for (const limits of [
  '{', '[]', '1', '{"unknown":1}', '{"max_body_len":-1}',
  '{"max_body_len":1.5}', '{"max_body_len":"1"}',
  '{"max_body_len":4294967296}', '{"max_body_len":18446744073709551616}',
]) {
  assert.throws(() => encode(1, 1, limits), `accepted encode limits ${limits}`);
  assert.throws(() => wasm.packet_decode(packet, limits), `accepted decode limits ${limits}`);
  assert.throws(() => wasm.extract_rgb(goodRgb, 1, limits), `accepted RGB limits ${limits}`);
  assert.throws(() => wasm.extract_pcm_s16le(goodPcm, 1, limits), `accepted PCM limits ${limits}`);
}
assertBody(parse(wasm.packet_decode(packet, 'null')));
assertBody(parse(wasm.packet_decode(packet, wasm.decode_limits_default())));
console.log('Actual wasm-bindgen Node boundary regressions passed');
