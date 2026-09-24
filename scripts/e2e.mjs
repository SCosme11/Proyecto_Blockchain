// End-to-end smoke test against a running node. Uses Node's WebCrypto — the same API the
// browser uses — so it also proves browser signatures verify in the C++ backend.
//   node scripts/e2e.mjs [http://127.0.0.1:8080]
const BASE = process.argv[2] ?? 'http://127.0.0.1:8080';
const { subtle } = globalThis.crypto;

let failures = 0;
const check = (ok, what, extra = '') => {
  console.log(`[${ok ? ' OK ' : 'FAIL'}] ${what}${extra ? '  ' + extra : ''}`);
  if (!ok) failures++;
};

async function api(method, path, body) {
  const res = await fetch(BASE + path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => null);
  return { status: res.status, json };
}

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const sha256hex = async (text) => hex(await subtle.digest('SHA-256', new TextEncoder().encode(text)));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

await api('POST', '/api/demo/reset');

// 1. Agent work in three confidence bands
const submit = (name, metrics, type = 'code') =>
  api('POST', '/api/work', {
    agent_name: name,
    artifact_type: type,
    filename: `${name}.txt`,
    content_text: `output of ${name} @ ${Date.now()}`,
    metrics,
  });
const low = await submit('agent-low', { self_confidence: 0.9, tests_passed_ratio: 0.1, lines_changed: 50 });
const high = await submit('agent-high', { self_confidence: 0.95, tests_passed_ratio: 1, lines_changed: 20 });
const med = await submit('agent-med', {
  self_confidence: 0.8, tests_passed_ratio: 0.9, lines_changed: 120, has_external_side_effects: true,
});
check(low.json?.category === 'LOW', 'LOW classification', low.json?.score);
check(high.json?.category === 'HIGH', 'HIGH classification', high.json?.score);
check(med.json?.category === 'MEDIUM', 'MEDIUM classification', med.json?.score);

const queue = (await api('GET', '/api/review-queue')).json;
check(queue.length === 1 && queue[0].id === med.json.id, 'only MEDIUM item is in the review queue');

// 2. Auditor identity: P-256 key generated client-side, only the public key is sent
const keys = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
const spki = Buffer.from(await subtle.exportKey('spki', keys.publicKey)).toString('base64');
const auditor = (await api('POST', '/api/auditors', { name: 'Test Auditor', public_key_spki: spki })).json;
check(auditor?.fingerprint?.length === 64, 'auditor registered', auditor?.fingerprint?.slice(0, 16));

// 3. Sign the canonical payload in "the browser"
const item = queue[0];
const comment = 'Reviewed diff and side effects; OK to ship.';
const ts = Date.now();
const canonical = [
  'v1', item.id, item.work_hash, item.artifact_type, item.score, item.rules_hash,
  'APPROVED', await sha256hex(comment), auditor.fingerprint, ts,
].join('|');
const sig = hex(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, new TextEncoder().encode(canonical)));

// Negative: tampered canonical must be rejected
const bad = await api('POST', '/api/transactions', {
  work_item_id: item.id, auditor_id: auditor.id, decision: 'REJECTED', comment, timestamp_ms: ts, signature: sig,
});
check(bad.status === 400 && bad.json?.error === 'bad signature', 'signature over different payload rejected', bad.json?.error);

const lowTx = await api('POST', '/api/transactions', {
  work_item_id: low.json.id, auditor_id: auditor.id, decision: 'APPROVED', comment, timestamp_ms: ts, signature: sig,
});
check(lowTx.status === 400, 'LOW item cannot be signed onto the chain', lowTx.json?.error);

const tx = await api('POST', '/api/transactions', {
  work_item_id: item.id, auditor_id: auditor.id, decision: 'APPROVED', comment, timestamp_ms: ts, signature: sig, canonical,
});
check(tx.status === 201 && tx.json?.signature_valid, 'WebCrypto signature verified by C++ node', tx.json?.tx_id?.slice(0, 16));

const mempool = (await api('GET', '/api/mempool')).json;
check(mempool.length === 1, 'transaction in mempool');

// 4. Mining race: 4 miners
const start = await api('POST', '/api/mine', { miners: 4, difficulty_bits: 18 });
check(start.status === 202, 'mining round started');
let snap;
for (let i = 0; i < 300; i++) {
  await sleep(100);
  snap = (await api('GET', '/api/mine/status')).json;
  if (!snap.running) break;
}
check(snap.result?.outcome === 'sealed', 'block sealed', `winner=${snap.result?.winner} nonce=${snap.result?.nonce} ${Math.round(snap.total_hashrate / 1e3)} kH/s`);
const statuses = snap.miners.map((m) => m.status);
check(statuses.filter((s) => s === 'winner').length === 1, 'exactly one winner', statuses.join(','));

const block = (await api('GET', `/api/blocks/${snap.result.height}`)).json;
check(block.transactions?.[0]?.tx_id === tx.json.tx_id, 'tx included in block', `#${block.height} ${block.hash.slice(0, 20)}...`);

// 5. Verification + tamper detection
let v = (await api('GET', '/api/chain/verify')).json;
check(v.ok, 'chain verifies');

for (const kind of ['tx_decision', 'comment', 'artifact', 'block_nonce']) {
  await api('POST', '/api/demo/tamper', { kind });
  v = (await api('GET', '/api/chain/verify')).json;
  const bad = v.blocks.find((b) => !b.ok);
  check(!v.ok && v.first_bad_height === block.height, `tamper '${kind}' detected`, bad?.errors?.[0]);
  await api('POST', '/api/demo/restore');
  v = (await api('GET', '/api/chain/verify')).json;
  check(v.ok, `restore after '${kind}'`);
}

console.log(`\n${failures ? 'FAILED' : 'ALL PASSED'} (${failures} failures)`);
process.exit(failures ? 1 : 0);
