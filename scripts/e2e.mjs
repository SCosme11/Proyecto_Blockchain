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

// 4. Consensus (PoS): 10 nodes (the guide's minimum), stake-weighted quorum
const NODES = 10;
await api('POST', '/api/nodes', { count: NODES, stake: 100 });
const start = await api('POST', '/api/consensus/propose', { mode: 'pos', nodes: NODES, abstain: 0 });
check(start.status === 202, 'consensus round started');
let snap;
for (let i = 0; i < 300; i++) {
  await sleep(100);
  snap = (await api('GET', '/api/consensus/status')).json;
  if (!snap.running) break;
}
check(
  snap.result?.outcome === 'sealed',
  'block sealed',
  `proposer=${snap.result?.proposer} quorum=${snap.result?.quorum_stake}/${snap.result?.total_stake}`,
);
check(snap.quorum_stake >= snap.quorum_threshold, 'quorum threshold reached', `${snap.quorum_stake}/${snap.quorum_threshold}`);

const block = (await api('GET', `/api/blocks/${snap.result.height}`)).json;
check(block.transactions?.[0]?.tx_id === tx.json.tx_id, 'tx included in block', `#${block.height} ${block.hash.slice(0, 20)}...`);

// 4b. A dishonest proposer must be caught, slashed and redrawn: mark the node with the most
// stake (so it is very likely to be drawn first) as dishonest, submit a fresh MEDIUM item so
// there is something to propose, and confirm the round still seals with someone else.
const med2 = await submit('agent-med-2', {
  self_confidence: 0.8, tests_passed_ratio: 0.9, lines_changed: 80, has_external_side_effects: true,
});
const ts2 = Date.now();
const canonical2 = [
  'v1', med2.json.id, med2.json.work_hash, med2.json.artifact_type, med2.json.score, med2.json.rules_hash,
  'APPROVED', await sha256hex(comment), auditor.fingerprint, ts2,
].join('|');
const sig2 = hex(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, new TextEncoder().encode(canonical2)));
await api('POST', '/api/transactions', {
  work_item_id: med2.json.id, auditor_id: auditor.id, decision: 'APPROVED', comment, timestamp_ms: ts2, signature: sig2, canonical: canonical2,
});

const beforeNodes = (await api('GET', '/api/nodes')).json;
const richest = beforeNodes[0];
// Give it overwhelming stake so the weighted draw picks it (almost) for certain, instead of
// depending on luck across the 10 equally-staked nodes.
await api('POST', `/api/nodes/${richest.id}/stake`, { delta: 10_000_000 });
await api('POST', `/api/nodes/${richest.id}/dishonest`, { dishonest: true });

const dStart = await api('POST', '/api/consensus/propose', { mode: 'pos', nodes: NODES, abstain: 0 });
check(dStart.status === 202, 'dishonest-proposer round started');
let dSnap;
for (let i = 0; i < 300; i++) {
  await sleep(100);
  dSnap = (await api('GET', '/api/consensus/status')).json;
  if (!dSnap.running) break;
}
check(dSnap.result?.outcome === 'sealed', 'round still seals after a dishonest draw', dSnap.result?.outcome);
check((dSnap.result?.attempts ?? 1) >= 1, 'sorteo attempt count recorded', dSnap.result?.attempts);
const afterNodes = (await api('GET', '/api/nodes')).json;
check(afterNodes.find((n) => n.id === richest.id)?.slashed, 'dishonest proposer got slashed', richest.name);

// 4c. node_copy tamper: corrupts one node's own in-memory chain mirror, independent of the
// reference ledger; it must come back in sync after a resync.
const anyNode = afterNodes[0];
const nc = await api('POST', '/api/demo/tamper', { kind: 'node_copy' });
check(nc.status === 200, 'node_copy tamper applied', nc.json?.change);
let syncStatus = (await api('GET', '/api/nodes/sync')).json;
check(syncStatus.some((s) => !s.synced), 'a node mirror is now out of sync');
await api('POST', '/api/demo/restore');
syncStatus = (await api('GET', '/api/nodes/sync')).json;
check(syncStatus.every((s) => s.synced), 'all node mirrors back in sync after restore');

// 5. Verification + tamper detection
let v = (await api('GET', '/api/chain/verify')).json;
check(v.ok, 'chain verifies');

for (const kind of ['tx_decision', 'comment', 'artifact', 'validator_signature']) {
  await api('POST', '/api/demo/tamper', { kind });
  v = (await api('GET', '/api/chain/verify')).json;
  const bad = v.blocks.find((b) => !b.ok);
  check(!v.ok, `tamper '${kind}' detected`, bad?.errors?.[0]);
  await api('POST', '/api/demo/restore');
  v = (await api('GET', '/api/chain/verify')).json;
  check(v.ok, `restore after '${kind}'`);
}

console.log(`\n${failures ? 'FAILED' : 'ALL PASSED'} (${failures} failures)`);
process.exit(failures ? 1 : 0);
