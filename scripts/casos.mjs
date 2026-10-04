// Covers the "Casos que la aplicación debe contemplar" list (guia_simulador_blockchain.pdf,
// sección 5) against a running node. Complements scripts/e2e.mjs, which is the happy-path
// smoke test; this script is specifically about robustness under bad/edge-case input.
//   node scripts/casos.mjs [http://127.0.0.1:8080]
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
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON */ }
  return { status: res.status, json, raw: text };
}

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const sha256hex = async (text) => hex(await subtle.digest('SHA-256', new TextEncoder().encode(text)));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function signAndSubmit(auditor, keys, workItem, decision = 'APPROVED') {
  const comment = 'ok';
  const ts = Date.now();
  const canonical = [
    'v1', workItem.id, workItem.work_hash, workItem.artifact_type, workItem.score, workItem.rules_hash,
    decision, await sha256hex(comment), auditor.fingerprint, ts,
  ].join('|');
  const sig = hex(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, new TextEncoder().encode(canonical)));
  return api('POST', '/api/transactions', {
    work_item_id: workItem.id, auditor_id: auditor.id, decision, comment, timestamp_ms: ts, signature: sig, canonical,
  });
}

async function waitForRound() {
  let snap;
  for (let i = 0; i < 400; i++) {
    await sleep(100);
    snap = (await api('GET', '/api/consensus/status')).json;
    if (!snap.running) break;
  }
  return snap;
}

await api('POST', '/api/demo/reset');

// ---------------- Entradas inválidas ----------------
check((await api('POST', '/api/nodes', { count: 5, stake: 100 })).status === 400, 'N=5 (<10) rechazado');
check((await api('POST', '/api/nodes', { count: 25, stake: 100 })).status === 400, 'N=25 (>20) rechazado');
check((await api('POST', '/api/consensus/propose', { mode: 'pow', nodes: 10, difficulty_hex_zeros: 0 })).status === 400,
  'dificultad=0 rechazada');
check((await api('POST', '/api/consensus/propose', { mode: 'pow', nodes: 10, difficulty_hex_zeros: 99 })).status === 400,
  'dificultad=99 rechazada');
check((await api('POST', '/api/consensus/propose', { mode: 'xyz', nodes: 10 })).status === 400, "modo inválido 'xyz' rechazado");
check((await api('POST', '/api/nodes/999999/stake', { delta: 10 })).status === 404, 'nodo inexistente (stake) -> 404');
check((await api('POST', '/api/nodes/999999/dishonest', { dishonest: true })).status === 404, 'nodo inexistente (dishonest) -> 404');
const malformed = await fetch(BASE + '/api/consensus/propose', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{not json' });
check(malformed.status === 400, 'cuerpo JSON mal formado -> 400 (no 500)');

// ---------------- Mempool vacío ----------------
await api('POST', '/api/demo/reset');
const emptyPow = await api('POST', '/api/consensus/propose', { mode: 'pow', nodes: 10, difficulty_hex_zeros: 3 });
check(emptyPow.status === 409, 'minar con mempool vacío se rechaza con mensaje claro', emptyPow.json?.error);
const emptyPos = await api('POST', '/api/consensus/propose', { mode: 'pos', nodes: 10 });
check(emptyPos.status === 409, 'proponer con mempool vacío se rechaza con mensaje claro', emptyPos.json?.error);

// ---------------- PoS: ningún nodo con stake ----------------
await api('POST', '/api/demo/reset');
const zeroed = (await api('POST', '/api/nodes', { count: 10, stake: 0 })).json;
// `nodes` may already exist from an earlier section (reset resets stake to the configured
// initial value, not to 0), so zero each one explicitly.
for (const n of zeroed) await api('POST', `/api/nodes/${n.id}/stake`, { delta: -n.stake });
// need at least one pending tx so the "zero stake" check (not the "empty mempool" one) fires
const keys = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
const spki = Buffer.from(await subtle.exportKey('spki', keys.publicKey)).toString('base64');
const auditor = (await api('POST', '/api/auditors', { name: 'Casos Auditor', public_key_spki: spki })).json;
const submitMed = (n) => api('POST', '/api/work', {
  agent_name: `agent-${n}`, artifact_type: 'code', filename: `${n}.txt`,
  content_text: `output ${n} @ ${Date.now()}-${Math.random()}`,
  metrics: { self_confidence: 0.8, tests_passed_ratio: 0.9, lines_changed: 80, has_external_side_effects: true },
});
const work1 = (await submitMed('zero-stake')).json;
await signAndSubmit(auditor, keys, work1);
const zeroStake = await api('POST', '/api/consensus/propose', { mode: 'pos', nodes: 10 });
check(zeroStake.status === 409, 'ningún nodo con stake -> rechazado con mensaje claro', zeroStake.json?.error);

// ---------------- Stake inválido ----------------
await api('POST', '/api/demo/reset');
const provisioned = (await api('POST', '/api/nodes', { count: 10, stake: 50 })).json;
const neg = await api('POST', `/api/nodes/${provisioned[0].id}/stake`, { delta: -1000 });
check(neg.status === 409, 'apuesta que deja el stake negativo se rechaza', neg.json?.error);

// ---------------- Ronda ya corriendo ----------------
// Nodes were zeroed out two sections ago; give them stake back so this round can actually run.
for (const n of (await api('GET', '/api/nodes')).json) await api('POST', `/api/nodes/${n.id}/stake`, { delta: 100 });
const work2 = (await submitMed('busy')).json;
await signAndSubmit(auditor, keys, work2);
const first = await api('POST', '/api/consensus/propose', { mode: 'pos', nodes: 10 });
check(first.status === 202, 'primera ronda inicia');
const second = await api('POST', '/api/consensus/propose', { mode: 'pos', nodes: 10 });
check(second.status === 409, 'pedir proponer mientras ya hay una ronda corriendo se rechaza', second.json?.error);
await waitForRound();

// ---------------- PoW: minar >= 10 bloques seguidos y madurar una recompensa ----------------
await api('POST', '/api/demo/reset');
await api('POST', '/api/nodes', { count: 10, stake: 100 });
let lastHeight = 0;
for (let i = 0; i < 10; i++) {
  const w = (await submitMed(`pow-${i}`)).json;
  await signAndSubmit(auditor, keys, w);
  const r = await api('POST', '/api/consensus/propose', { mode: 'pow', nodes: 10, difficulty_hex_zeros: 3 });
  if (r.status !== 202) { check(false, `ronda PoW #${i} inició`, JSON.stringify(r.json)); break; }
  const snap = await waitForRound();
  if (snap?.result?.outcome !== 'sealed') { check(false, `bloque PoW #${i} sellado`, snap?.result?.error); break; }
  lastHeight = snap.result.height;
}
check(lastHeight >= 10, 'se minaron al menos 10 bloques PoW seguidos', `altura final=${lastHeight}`);
const rewards = (await api('GET', '/api/rewards')).json;
const matured = rewards.find((r) => r.height === 1 && r.confirmed);
check(!!matured, 'la recompensa del bloque #1 maduró a las 6 confirmaciones', JSON.stringify(rewards.find((r) => r.height === 1)));
const pending = rewards.find((r) => r.height === lastHeight);
check(pending && !pending.confirmed, 'la recompensa del último bloque sigue pendiente (aún no 6 confirmaciones)');

console.log(`\n${failures ? 'FAILED' : 'ALL PASSED'} (${failures} failures)`);
process.exit(failures ? 1 : 0);
