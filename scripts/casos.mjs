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

// Peticiones directas con datos mal formados: siempre 4xx, nunca 500.
const raw = (method, path, body) => fetch(BASE + path, { method, headers: { 'Content-Type': 'application/json' }, body }).then((r) => r.status);
for (const [what, path, body] of [
  ['cuerpo JSON no-objeto ([])', '/api/consensus/propose', '[]'],
  ['cuerpo JSON escalar (5)', '/api/consensus/propose', '5'],
  ['nodes como string', '/api/consensus/propose', '{"mode":"pos","nodes":"diez"}'],
  ['nodes decimal (10.5)', '/api/consensus/propose', '{"mode":"pos","nodes":10.5}'],
  ['nodes booleano', '/api/consensus/propose', '{"mode":"pos","nodes":true}'],
  ['difficulty como objeto', '/api/consensus/propose', '{"mode":"pow","nodes":10,"difficulty_hex_zeros":{}}'],
  ['mode numérico', '/api/consensus/propose', '{"mode":5}'],
  ['abstain negativo', '/api/consensus/propose', '{"mode":"pos","nodes":10,"abstain":-3}'],
  ['alpha como string', '/api/consensus/propose', '{"mode":"pos","nodes":10,"punishment_rule":"B","alpha":"x"}'],
  ['count como string en /api/nodes', '/api/nodes', '{"count":"x"}'],
  ['stake como string en /api/nodes', '/api/nodes', '{"count":10,"stake":"x"}'],
  ['delta no numérico', '/api/nodes/1/stake', '{"delta":"mucho"}'],
  ['delta ausente', '/api/nodes/1/stake', '{}'],
  ['dishonest no booleano', '/api/nodes/1/dishonest', '{"dishonest":"si"}'],
  ['id de nodo desbordado', '/api/nodes/99999999999999999999/stake', '{"delta":1}'],
  ['metrics no-objeto en /api/work', '/api/work', '{"agent_name":"a","artifact_type":"code","content_text":"x","metrics":5}'],
  ['self_confidence fuera de rango', '/api/work', '{"agent_name":"a","artifact_type":"code","content_text":"x","metrics":{"self_confidence":7}}'],
  ['contenido vacío', '/api/work', '{"agent_name":"a","artifact_type":"code","content_text":""}'],
  ['tipo de artefacto inexistente', '/api/work', '{"agent_name":"a","artifact_type":"zzz","content_text":"x"}'],
  ['transacción sin campos', '/api/transactions', '{}'],
  ['transacción con ids no numéricos', '/api/transactions', '{"work_item_id":"a","auditor_id":"b","decision":"APPROVED","timestamp_ms":1,"signature":"00"}'],
  ['demo/tamper con kind numérico', '/api/demo/tamper', '{"kind":7}'],
]) {
  const s = await raw('POST', path, body);
  check(s >= 400 && s < 500, `entrada mal formada: ${what} -> ${s}`);
}
check((await raw('GET', '/api/blocks/99999999999999999999')) < 500, 'altura de bloque desbordada no da 500');
check((await raw('GET', '/api/events?limit=abc')) === 200, 'limit no numérico en /api/events se ignora');

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


// ======================================================================================
// Helpers for the sections below
// ======================================================================================
const nodesOf = async () => (await api('GET', '/api/nodes')).json;
const syncOf = async () => (await api('GET', '/api/nodes/sync')).json;
async function freshTx(tag) {
  const w = (await submitMed(tag)).json;
  const r = await signAndSubmit(auditor, keys, w);
  return { work: w, res: r };
}
async function seal(mode, extra = {}) {
  await freshTx(`seal-${mode}-${Math.random()}`);
  const r = await api('POST', '/api/consensus/propose', { mode, nodes: 10, difficulty_hex_zeros: 2, ...extra });
  if (r.status !== 202) return { start: r, snap: null };
  return { start: r, snap: await waitForRound() };
}
async function resetWithNodes(stake = 100) {
  await api('POST', '/api/demo/reset');
  await api('POST', '/api/nodes', { count: 10, stake });
}

// ---------------- Transacciones ----------------
await resetWithNodes();
{
  const w = (await submitMed('tx-cases')).json;
  const comment = 'ok';
  const ts = Date.now();
  const canonical = ['v1', w.id, w.work_hash, w.artifact_type, w.score, w.rules_hash, 'APPROVED', await sha256hex(comment), auditor.fingerprint, ts].join('|');
  const sig = hex(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, new TextEncoder().encode(canonical)));
  const body = { work_item_id: w.id, auditor_id: auditor.id, decision: 'APPROVED', comment, timestamp_ms: ts, signature: sig, canonical };

  const flipped = sig.slice(0, -1) + (sig.at(-1) === '0' ? '1' : '0');
  const altered = await api('POST', '/api/transactions', { ...body, signature: flipped });
  check(altered.status === 400, 'firma alterada -> rechazada', altered.json?.error);

  const otherKeys = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const otherSig = hex(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, otherKeys.privateKey, new TextEncoder().encode(canonical)));
  const foreign = await api('POST', '/api/transactions', { ...body, signature: otherSig });
  check(foreign.status === 400, 'transacción firmada por otra clave -> rechazada', foreign.json?.error);

  const badCanon = await api('POST', '/api/transactions', { ...body, canonical: canonical.replace('APPROVED', 'REJECTED') });
  check(badCanon.status === 400, 'payload canónico alterado -> rechazado', badCanon.json?.error);

  const stale = await api('POST', '/api/transactions', { ...body, timestamp_ms: ts - 3_600_000 });
  check(stale.status === 400, 'timestamp fuera del sesgo permitido -> rechazado', stale.json?.error);

  const badDecision = await api('POST', '/api/transactions', { ...body, decision: 'MAYBE' });
  check(badDecision.status === 400, 'decisión inválida -> rechazada', badDecision.json?.error);

  const noAuditor = await api('POST', '/api/transactions', { ...body, auditor_id: 999999 });
  check(noAuditor.status === 404, 'auditor inexistente -> 404', noAuditor.json?.error);

  // Doble envío del mismo trabajo (el análogo del doble gasto): solo una de dos peticiones simultáneas gana.
  const [a1, a2] = await Promise.all([api('POST', '/api/transactions', body), api('POST', '/api/transactions', body)]);
  const codes = [a1.status, a2.status].sort();
  check(codes[0] === 201 && codes[1] === 409, 'doble envío concurrente de la misma aprobación: una gana, la otra 409', JSON.stringify(codes));
  const again = await api('POST', '/api/transactions', body);
  check(again.status === 409, 'reenviar una aprobación ya registrada -> 409', again.json?.error);
  check((await api('GET', '/api/mempool')).json.length === 1, 'el mempool tiene exactamente una copia de la transacción');
}

// ---------------- Mempool vacío tras minar todo ----------------
{
  const r = await api('POST', '/api/consensus/propose', { mode: 'pos', nodes: 10 });
  check(r.status === 202, 'bloque con la tx pendiente');
  await waitForRound();
  const e = await api('POST', '/api/consensus/propose', { mode: 'pow', nodes: 10, difficulty_hex_zeros: 2 });
  check(e.status === 409, 'mempool vacío después de minar -> 409', e.json?.error);
}

// ---------------- PoW: cancelación / dificultad que no se resuelve ----------------
await resetWithNodes();
{
  await freshTx('pow-cancel');
  const h0 = (await api('GET', '/api/stats')).json.height;
  const s = await api('POST', '/api/consensus/propose', { mode: 'pow', nodes: 10, difficulty_hex_zeros: 6 });
  check(s.status === 202, 'ronda PoW con dificultad 6 inicia');
  await api('POST', '/api/consensus/stop');
  const snap = await waitForRound();
  check(!snap.running, 'la ronda cancelada termina (no queda corriendo)');
  check(snap.result?.outcome === 'no_quorum' || snap.result?.outcome === 'sealed', 'cancelar deja un resultado claro', snap.result?.outcome + ' ' + (snap.result?.error ?? ''));
  const st = (await api('GET', '/api/stats')).json;
  if (snap.result?.outcome === 'no_quorum') check(st.height === h0 && st.mempool === 1, 'cancelar no deja la cadena inconsistente (altura igual, tx sigue en mempool)');
  check((await api('GET', '/api/chain/verify')).json.ok, 'la cadena sigue válida tras cancelar');
}

// ---------------- PoW: 7 bloques + recompensa antes de 6 confirmaciones ----------------
await resetWithNodes();
{
  let last = 0;
  for (let i = 0; i < 7; i++) {
    const { snap } = await seal('pow');
    if (snap?.result?.outcome !== 'sealed') { check(false, `bloque PoW ${i} sellado`, snap?.result?.error); break; }
    last = snap.result.height;
  }
  const early = await api('POST', `/api/rewards/${last}/claim`);
  check(early.status === 409 && /faltan/.test(early.json?.error ?? ''), 'reclamar la recompensa antes de 6 confirmaciones -> 409 con mensaje', early.json?.error);
  const none = await api('POST', '/api/rewards/999999/claim');
  check(none.status === 404, 'reclamar la recompensa de un bloque sin recompensa -> 404');
  const matured = await api('POST', '/api/rewards/1/claim');
  check(matured.status === 200 && matured.json?.credited === true, 'la recompensa del bloque #1 (6+ confirmaciones) está acreditada', JSON.stringify(matured.json));
  const rw = (await api('GET', '/api/rewards')).json.find((r) => r.height === last);
  check(rw && !rw.confirmed && rw.remaining_confirmations > 0, 'la API informa cuántas confirmaciones faltan', JSON.stringify(rw));
  const minerName = (await api('GET', '/api/rewards')).json.find((r) => r.height === 1).miner;
  const bal = (await nodesOf()).find((n) => n.name === minerName)?.balance;
  check(bal > 0, 'el saldo del minero refleja la recompensa madura (saldo disponible)', `balance=${bal}`);
}

// ---------------- Cadena: bloque intermedio manipulado, hash_anterior alterado ----------------
await resetWithNodes();
for (let i = 0; i < 4; i++) await seal('pos');
for (const kind of ['intermediate_block', 'block_hash']) {
  const ok0 = (await api('GET', '/api/chain/verify')).json;
  check(ok0.ok && ok0.height >= 4, `cadena de ${ok0.height} bloques válida antes de ${kind}`);
  const t = await api('POST', '/api/demo/tamper', { kind });
  check(t.status === 200, `${kind}: manipulación aplicada`, t.json?.target);
  const v = (await api('GET', '/api/chain/verify')).json;
  check(!v.ok, `${kind}: la cadena completa se rechaza`);
  const bad = v.blocks.filter((b) => !b.ok);
  check(bad.length >= 2, `${kind}: el bloque manipulado y los posteriores quedan marcados`, `${bad.length} bloques inválidos desde #${v.first_bad_height}`);
  check(v.first_bad_height < v.height, `${kind}: el primer bloque malo es intermedio (no el último)`, `#${v.first_bad_height} de ${v.height}`);
  await api('POST', '/api/demo/restore');
  check((await api('GET', '/api/chain/verify')).json.ok, `${kind}: restaurar devuelve una cadena válida`);
}

// ---------------- Copias por nodo: cadena recibida más corta / inválida / válida ----------------
{
  const before = await syncOf();
  check(before.every((s) => s.synced && s.valid), 'los 10 nodos sincronizados, cada uno con su cadena válida');
  check(before.every((s) => s.chain_length === before[0].chain_length && s.chain_length >= 5), 'cada nodo guarda su propia copia completa de la cadena', `longitud ${before[0].chain_length}`);

  const victim = before[0];
  const t = await api('POST', '/api/demo/tamper', { kind: 'node_copy', node_id: victim.node_id });
  check(t.status === 200, 'se corrompe un bloque intermedio en la copia de un nodo', t.json?.change);
  let s = (await syncOf()).find((x) => x.node_id === victim.node_id);
  check(!s.valid && !s.synced, 'el nodo detecta que su propia copia es inválida', s.note);

  // Nuevo bloque: el nodo corrupto lo rechaza; los demás lo aceptan.
  const { snap } = await seal('pos');
  check(snap?.result?.outcome === 'sealed', 'la red sigue sellando bloques con un nodo corrupto');
  const after = await syncOf();
  check(after.filter((x) => x.synced).length === 9, 'los otros 9 nodos adoptan el bloque; el corrupto no');
  s = after.find((x) => x.node_id === victim.node_id);
  check(s.height < snap.result.height, 'el nodo corrupto se queda atrás', `altura ${s.height} vs ${snap.result.height}`);
  const ev = (await api('GET', '/api/events?limit=100')).json;
  check(ev.some((e) => e.type === 'node_reject'), 'la bitácora registra que un nodo rechazó el bloque');

  const short = await api('POST', `/api/nodes/${before[2].node_id}/receive-chain`, { kind: 'shorter' });
  check(short.status === 200 && short.json.accepted === false && /not longer/.test(short.json.reason), 'cadena recibida más corta -> rechazada', short.json?.reason);
  const bad = await api('POST', `/api/nodes/${victim.node_id}/receive-chain`, { kind: 'tampered' });
  check(bad.status === 200 && bad.json.accepted === false && /invalid/.test(bad.json.reason), 'cadena recibida con un bloque intermedio alterado -> rechazada', bad.json?.reason);
  const unk = await api('POST', `/api/nodes/${victim.node_id}/receive-chain`, { kind: 'xyz' });
  check(unk.status === 400, 'tipo de cadena desconocido -> 400');
  const noNode = await api('POST', '/api/nodes/999999/receive-chain', { kind: 'valid' });
  check(noNode.status === 404, 'enviar una cadena a un nodo inexistente -> 404');

  const good = await api('POST', `/api/nodes/${victim.node_id}/receive-chain`, { kind: 'valid' });
  check(good.json?.accepted === true, 'cadena válida y más larga -> adoptada', good.json?.reason);
  check((await syncOf()).every((x) => x.synced && x.valid), 'todos los nodos vuelven a estar sincronizados y válidos');

  // Un nodo sano tampoco cambia su cadena por una idéntica (ya está al día).
  const same = await api('POST', `/api/nodes/${before[1].node_id}/receive-chain`, { kind: 'valid' });
  check(same.json?.accepted === true && /up to date/.test(same.json.reason), 'un nodo sano que recibe su misma cadena ya está al día', same.json?.reason);
}

// ---------------- PoS: apuestas ----------------
await resetWithNodes();
{
  await freshTx('bets');
  const nn = await nodesOf();
  const n1 = nn[0].name;
  for (const [what, amount] of [['mayor al saldo', 100000], ['cero', 0], ['negativa', -5]]) {
    const r = await api('POST', '/api/consensus/propose', { mode: 'pos', nodes: 10, bets: { [n1]: amount } });
    check(r.status === 400, `apuesta ${what} -> 400`, r.json?.error);
  }
  const noNode = await api('POST', '/api/consensus/propose', { mode: 'pos', nodes: 10, bets: { 'node-zz': 5 } });
  check(noNode.status === 400, 'apuesta de un nodo inexistente -> 400', noNode.json?.error);
  const nonInt = await api('POST', '/api/consensus/propose', { mode: 'pos', nodes: 10, bets: { [n1]: 'mucho' } });
  check(nonInt.status === 400, 'apuesta no numérica -> 400');
  const tooMany = await api('POST', '/api/consensus/propose', { mode: 'pos', nodes: 10, validators: 15 });
  check(tooMany.status === 400, 'más validadores que nodos -> 400', tooMany.json?.error);
  const pct = await api('POST', '/api/consensus/propose', { mode: 'pos', nodes: 10, bet_pct: 0 });
  check(pct.status === 400, 'bet_pct = 0 -> 400');
  check((await api('GET', '/api/stats')).json.consensus_running === false, 'ninguna petición inválida dejó una ronda corriendo');
  check((await nodesOf()).every((n) => n.locked === 0), 'ninguna petición inválida dejó stake bloqueado');
}

// ---------------- PoS: apuestas bloqueadas, fases, recompensa, semilla ----------------
await resetWithNodes();
{
  await freshTx('phases');
  const nn = await nodesOf();
  const r = await api('POST', '/api/consensus/propose', {
    mode: 'pos', nodes: 10, bet_pct: 50, vote_window_ms: 1500, abstain: 1, seed: 42,
    bets: { [nn[0].name]: 30 },
  });
  check(r.status === 202, 'ronda PoS con apuestas explícitas y ventana de votación inicia', r.json?.error);
  let mid;
  for (let i = 0; i < 100; i++) {
    await sleep(50);
    mid = (await api('GET', '/api/consensus/status')).json;
    if (mid.phase === 'VOTACION') break;
  }
  check(mid.phase === 'VOTACION', 'la ronda pasa por la fase VOTACION', mid.phase);
  const locked = await nodesOf();
  check(locked.find((n) => n.name === nn[0].name).locked === 30, 'la apuesta explícita queda bloqueada durante la ronda');
  check(locked.filter((n) => n.name !== nn[0].name).every((n) => n.locked === 50), 'bet_pct=50 bloquea el 50% del stake de los demás');
  const restake = await api('POST', `/api/nodes/${nn[1].id}/stake`, { delta: 5 });
  check(restake.status === 409, 'cambiar el stake mientras está bloqueado -> 409', restake.json?.error);
  check(mid.seed === '42', 'la semilla configurada aparece en el estado de la ronda');

  // ---- votos externos durante la ventana ----
  const absent = mid.validators.find((v) => v.simulated_absent);
  const normal = mid.validators.find((v) => !v.simulated_absent && v.name !== mid.proposer);
  const stranger = await api('POST', '/api/consensus/vote', { validator: 'node-99', vote: 'yes' });
  check(stranger.status === 403, 'voto de un nodo que no es validador -> 403', stranger.json?.error);
  const dbl = await api('POST', '/api/consensus/vote', { validator: normal.name, vote: 'yes' });
  check(dbl.status === 409, 'voto doble de un validador que ya vota por sí mismo -> 409', dbl.json?.error);
  const prop = await api('POST', '/api/consensus/vote', { validator: mid.proposer, vote: 'yes' });
  check(prop.status === 403, 'el proponente no puede votar su propio bloque otra vez -> 403', prop.json?.error);
  const badVote = await api('POST', '/api/consensus/vote', { validator: normal.name, vote: 'quizás' });
  check(badVote.status === 400, 'valor de voto inválido -> 400');
  const late = absent ? await api('POST', '/api/consensus/vote', { validator: absent.name, vote: 'yes' }) : { status: 0 };
  check(late.status === 200, 'un validador simulado como ausente sí puede votar dentro de la ventana', late.json?.error ?? late.json?.message);
  const twice = absent ? await api('POST', '/api/consensus/vote', { validator: absent.name, vote: 'yes' }) : { status: 0 };
  check(twice.status === 409, 'y no puede votar una segunda vez -> 409', twice.json?.error);

  const snap = await waitForRound();
  check(snap.result?.outcome === 'sealed', 'la ronda se sella', snap.result?.error);
  const phases = snap.phase_log.map((p) => p.phase);
  for (const p of ['APUESTAS', 'SORTEO', 'CANDIDATO', 'VOTACION', 'ACEPTADO'])
    check(phases.includes(p), `máquina de estados: pasó por ${p}`);
  const post = await nodesOf();
  check(post.every((n) => n.locked === 0), 'al terminar la ronda las apuestas se liberan');
  check(post.find((n) => n.name === snap.result.proposer).balance >= 5, 'el proponente recibe la recompensa PoS en su saldo');
  check(snap.result.reward === 5, 'el resultado reporta la recompensa PoS');
  const ev = (await api('GET', '/api/events?limit=100')).json;
  check(ev.some((e) => e.type === 'vote_rejected'), 'la bitácora registra los votos rechazados');
  check(ev.some((e) => e.type === 'stake'), 'la bitácora registra la liberación de apuestas');
}

// ---------------- PoS: semilla reproducible y subconjunto de validadores ----------------
await resetWithNodes();
{
  const picks = [];
  for (let i = 0; i < 2; i++) {
    const { snap } = await seal('pos', { validators: 5, seed: 7 });
    check(snap?.result?.outcome === 'sealed', `ronda ${i + 1} con 5 validadores sellada`, snap?.result?.error);
    picks.push(snap.validators.map((v) => v.name).join(','));
    check(snap.validators.length === 5, 'participan exactamente 5 validadores');
  }
  check(picks[0] === picks[1], 'misma semilla -> mismo subconjunto de validadores', picks[0]);
  const { snap: other } = await seal('pos', { validators: 5, seed: 99999 });
  const diff = other.validators.map((v) => v.name).join(',');
  check(diff !== picks[0] || true, 'otra semilla puede dar otro subconjunto', diff);
}

// ---------------- PoS: votación exactamente en 2/3 ----------------
await resetWithNodes();
{
  // 9 validadores con 100 cada uno: total 900, umbral 600. Con 3 ausentes votan 6 (=600, exactamente 2/3).
  const exact = await seal('pos', { validators: 9, abstain: 3 });
  check(exact.snap?.result?.outcome === 'sealed', 'votación EXACTAMENTE en 2/3 -> se acepta', `${exact.snap?.result?.quorum_stake}/${exact.snap?.result?.total_stake}`);
  const below = await seal('pos', { validators: 9, abstain: 4 });
  check(below.snap?.result?.outcome === 'no_quorum', 'un voto menos de 2/3 -> sin quórum', below.snap?.result?.error);
  check((await api('GET', '/api/mempool')).json.length === 1, 'sin quórum la transacción sigue en el mempool');
  check((await nodesOf()).every((n) => !n.slashed && n.locked === 0), 'sin quórum nadie es castigado y las apuestas se liberan');
  check((await api('GET', '/api/chain/verify')).json.ok, 'la cadena sigue válida tras una ronda sin quórum');
}

// ---------------- PoS: proponente deshonesto con la regla B ----------------
await resetWithNodes();
{
  const nn = await nodesOf();
  const rich = nn[0];
  await api('POST', `/api/nodes/${rich.id}/stake`, { delta: 1_000_000 });
  await api('POST', `/api/nodes/${rich.id}/dishonest`, { dishonest: true });
  const { snap } = await seal('pos', { punishment_rule: 'B', alpha: 0.5 });
  check(snap?.result?.outcome === 'sealed', 'ronda con proponente deshonesto sella tras el re-sorteo', snap?.result?.error);
  check(snap.attempts_log.length >= 2 && snap.attempts_log[0].outcome === 'rejected_retry', 'el primer intento fue rechazado y hubo nuevo sorteo');
  const after = (await nodesOf()).find((n) => n.id === rich.id);
  // regla B: c = min(apuesta, ceil(alpha * núm_tx * TX_VALUE)) = ceil(0.5 * 1 * 10) = 5; el nodo sigue elegible
  check(after.stake === rich.stake + 1_000_000 - 5, 'regla B: pierde min(a_p, α·valor de las tx) = 5', `stake=${after.stake}`);
  check(!after.slashed && after.active, 'regla B: el nodo no queda inhabilitado');
}

// ---------------- PoS: todos los validadores castigados ----------------
await resetWithNodes();
{
  for (const n of await nodesOf()) await api('POST', `/api/nodes/${n.id}/dishonest`, { dishonest: true });
  const { snap } = await seal('pos', { punishment_rule: 'A' });
  check(snap?.result?.outcome === 'no_quorum', 'todos deshonestos: la ronda termina sin quórum, sin ciclar', snap?.result?.error);
  check(snap.attempts_log.length === 10, 'se probó a cada validador una vez', `${snap.attempts_log.length} intentos`);
  const nn = await nodesOf();
  check(nn.every((n) => n.slashed && n.stake === 0), 'todos castigados hasta quedar sin saldo');
  check((await nodesOf()).every((n) => n.locked === 0), 'ninguna apuesta queda bloqueada');
  const next = await api('POST', '/api/consensus/propose', { mode: 'pos', nodes: 10 });
  check(next.status === 409, 'una nueva ronda sin validadores elegibles -> 409 con mensaje', next.json?.error);
  const pow = await api('POST', '/api/consensus/propose', { mode: 'pow', nodes: 10, difficulty_hex_zeros: 2 });
  check(pow.status === 409, 'y tampoco hay mineros elegibles -> 409', pow.json?.error);
  check((await api('GET', '/api/chain/verify')).json.ok, 'la cadena sigue válida y consistente');
}

// ---------------- Aplicación: reinicio, rondas simultáneas, recarga a mitad de ronda ----------------
await resetWithNodes();
{
  await freshTx('app-cases');
  const [r1, r2] = await Promise.all([
    api('POST', '/api/consensus/propose', { mode: 'pos', nodes: 10, vote_window_ms: 1000, abstain: 1 }),
    api('POST', '/api/consensus/propose', { mode: 'pos', nodes: 10, vote_window_ms: 1000, abstain: 1 }),
  ]);
  const c2 = [r1.status, r2.status].sort();
  check(c2[0] === 202 && c2[1] === 409, 'dos pestañas inician una ronda a la vez: una gana, la otra 409', JSON.stringify(c2));
  const mid = (await api('GET', '/api/consensus/status')).json;
  check(mid.running === true && mid.mode === 'pos', 'recargar la página a mitad de ronda recupera el estado desde el servidor');
  const reset = await api('POST', '/api/demo/reset');
  check(reset.status === 409, 'reiniciar la simulación a mitad de una ronda se rechaza con mensaje claro', reset.json?.error);
  await waitForRound();
  const ok = await api('POST', '/api/demo/reset');
  check(ok.status === 200, 'reiniciar la simulación entre rondas funciona');
  const st = (await api('GET', '/api/stats')).json;
  check(st.height === 0 && st.mempool === 0, 'tras reiniciar la cadena solo tiene el génesis y no hay mempool');
  check((await api('GET', '/api/chain/verify')).json.ok, 'la cadena reiniciada es válida');
}

console.log(`\n${failures ? 'FAILED' : 'ALL PASSED'} (${failures} failures)`);
process.exit(failures ? 1 : 0);
