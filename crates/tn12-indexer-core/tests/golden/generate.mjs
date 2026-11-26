// Generates golden vectors for compute_covenant_id by invoking
// @noble/hashes/blake2b with key="CovenantID" over the canonical preimage
// (must match the TS impl in covenant-sdk/src/covenant.ts:265).
//
// Run from this directory (or anywhere) with:
//   node --experimental-vm-modules generate.mjs > golden.json
// Requires @noble/hashes to be resolvable (we hop into /root/covenant-sdk).

import { blake2b } from '/root/covenant-sdk/node_modules/@noble/hashes/blake2b.js';

const enc = new TextEncoder();
const COVENANT_ID_KEY = enc.encode('CovenantID');

function writeU16LE(n) {
  const b = new Uint8Array(2);
  new DataView(b.buffer).setUint16(0, n, true);
  return b;
}
function writeU32LE(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}
function writeU64LE(n) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
}
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function bytesToHex(b) {
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

function computeCovenantId(txid, index, authOutputs) {
  const parts = [];
  parts.push(hexToBytes(txid));
  parts.push(writeU32LE(index));
  parts.push(writeU64LE(authOutputs.length));
  for (const out of authOutputs) {
    parts.push(writeU32LE(out.index));
    parts.push(writeU64LE(out.value));
    parts.push(writeU16LE(out.scriptVersion));
    parts.push(writeU64LE(out.scriptBytes.length));
    parts.push(out.scriptBytes);
  }
  let total = 0;
  for (const p of parts) total += p.length;
  const preimage = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { preimage.set(p, off); off += p.length; }
  const hash = blake2b(preimage, { key: COVENANT_ID_KEY, dkLen: 32 });
  return bytesToHex(hash);
}

// Deterministic test vectors. Mix simple + realistic.
const vectors = [
  {
    name: 'empty_auth_outputs',
    txid: '00'.repeat(32),
    index: 0,
    auth: [],
  },
  {
    name: 'single_auth_pubkey_output',
    txid: '11'.repeat(32),
    index: 5,
    auth: [
      { index: 0, value: 1000n, scriptVersion: 0, scriptBytes: new Uint8Array([0xaa]) },
    ],
  },
  {
    name: 'two_auth_outputs',
    txid: 'cdb813b86af4cef2d4038ef53694e376a703f4cf9df25ec35748bb3d76b5e8fa',
    index: 0,
    auth: [
      {
        index: 0,
        value: 15000000000n,
        scriptVersion: 0,
        scriptBytes: hexToBytes('aa2011f8924c7f0718634c684a96facacfdc38999073f0ce70c0d429b64c89596eb987'),
      },
      {
        index: 1,
        value: 5594991436n,
        scriptVersion: 0,
        scriptBytes: hexToBytes('2026cb3ff1d2275f7d5b9d960a6f5ec437bf15dfc099dacb199e8d35e8151562fcac'),
      },
    ],
  },
  {
    name: 'big_value_long_script',
    txid: 'ff'.repeat(32),
    index: 4294967295, // u32 max
    auth: [
      {
        index: 7,
        value: 18446744073709000000n,
        scriptVersion: 2,
        scriptBytes: hexToBytes('aa20' + 'de'.repeat(32) + '87' + '01'.repeat(100)),
      },
    ],
  },
];

const out = vectors.map(v => ({
  name: v.name,
  txid: v.txid,
  index: v.index,
  authOutputs: v.auth.map(o => ({
    index: o.index,
    value: o.value.toString(),
    scriptVersion: o.scriptVersion,
    scriptBytes: bytesToHex(o.scriptBytes),
  })),
  expected: computeCovenantId(v.txid, v.index, v.auth),
}));

console.log(JSON.stringify(out, null, 2));
