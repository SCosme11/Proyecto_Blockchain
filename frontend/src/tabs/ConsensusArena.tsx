import { useEffect, useRef, useState } from 'react';
import { api, type Config, type ConsensusSnapshot, type ProposeParams } from '../api';
import { Badge, ErrorBox, Hash, fmtBig, fmtNum, usePoll } from '../components/ui';

const EVENT_BADGE: Record<string, 'ok' | 'bad' | 'neutral' | 'info'> = {
  block: 'ok',
  round_rejected: 'neutral',
  slash: 'bad',
  reward_confirmed: 'info',
};

const EVENT_BADGE_EXTRA: Record<string, 'ok' | 'bad' | 'neutral' | 'info'> = {
  node_reject: 'bad',
  vote_rejected: 'bad',
  chain_rejected: 'bad',
  chain_accepted: 'ok',
  reward: 'info',
  stake: 'info',
  tamper: 'bad',
  reward_claim_rejected: 'neutral',
};

// APUESTAS -> SORTEO -> CANDIDATO -> VOTACION -> ACEPTADO / RECHAZADO (PoS); MINANDO -> GANADOR (PoW).
const POS_PHASES = ['APUESTAS', 'SORTEO', 'CANDIDATO', 'VOTACION', 'ACEPTADO'];
const PHASE_HELP: Record<string, string> = {
  APUESTAS: 'los validadores apuestan 0 < aᵢ ≤ su saldo; la apuesta queda bloqueada',
  SORTEO: 'sorteo ponderado por apuesta (semilla = hash_anterior|altura|intento)',
  CANDIDATO: 'el proponente arma y firma el bloque candidato',
  VOTACION: 'cada validador revisa el bloque y vota con peso = su apuesta (umbral 2/3)',
  ACEPTADO: 'bloque agregado, recompensa pagada, apuestas liberadas',
  RECHAZADO: 'bloque rechazado: se castiga al proponente deshonesto y se vuelve a sortear (o la ronda termina)',
  MINANDO: 'los mineros prueban nonces disjuntos',
  GANADOR: 'un minero encontró el hash; todos se detienen',
  SIN_GANADOR: 'ningún minero resolvió (o se canceló)',
};

function PhaseStrip({ snap }: { snap: ConsensusSnapshot }) {
  const reached = new Set((snap.phase_log ?? []).map((p) => p.phase));
  const phases =
    snap.mode === 'pow'
      ? ['MINANDO', snap.phase === 'SIN_GANADOR' ? 'SIN_GANADOR' : 'GANADOR']
      : [...POS_PHASES.slice(0, 4), reached.has('RECHAZADO') && snap.phase === 'RECHAZADO' ? 'RECHAZADO' : 'ACEPTADO'];
  return (
    <div style={{ marginBottom: 10 }}>
      <div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
        {phases.map((p) => (
          <Badge key={p} kind={p === snap.phase ? (p === 'RECHAZADO' || p === 'SIN_GANADOR' ? 'bad' : 'ok') : reached.has(p) ? 'info' : 'neutral'}>
            {p === snap.phase && snap.running ? '▶ ' : ''}
            {p}
          </Badge>
        ))}
        {reached.has('RECHAZADO') && snap.phase !== 'RECHAZADO' && <Badge kind="bad">hubo RECHAZADO → re-sorteo</Badge>}
      </div>
      <div className="hint" style={{ margin: '4px 0 0' }}>{PHASE_HELP[snap.phase] ?? ''}</div>
    </div>
  );
}

const MINER_STATUS_TEXT: Record<string, string> = {
  idle: 'idle',
  mining: 'mining…',
  winner: 'WINNER — sealed the block',
  late: 'found a valid nonce too late',
  stale: 'stopped — attempt limit reached',
};

const VOTER_STATUS_TEXT: Record<string, string> = {
  idle: 'idle',
  voting: 'voting…',
  voted: 'voted ✓',
  abstained: 'sin voto (ausente)',
  against: 'votó EN CONTRA ✗',
};

export default function ConsensusArena({
  config,
  onChange,
  onGoChain,
}: {
  config: Config;
  onChange: () => void;
  onGoChain: () => void;
}) {
  const [mode, setMode] = useState<'pow' | 'pos'>('pos');
  const [n, setN] = useState(config.min_nodes);
  const [difficulty, setDifficulty] = useState(4);
  const [abstain, setAbstain] = useState(0);
  const [punishmentRule, setPunishmentRule] = useState<'A' | 'B'>('A');
  const [alpha, setAlpha] = useState(0.5);
  const [subset, setSubset] = useState(0);
  const [betPct, setBetPct] = useState(100);
  const [seed, setSeed] = useState('');
  const [voteWindow, setVoteWindow] = useState(0);
  const [notice, setNotice] = useState<{ kind: 'ok' | 'bad'; text: string } | null>(null);
  const [snap, setSnap] = useState<ConsensusSnapshot | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [nodeErr, setNodeErr] = useState<unknown>(null);
  const [rounds, , reloadRounds] = usePoll(api.rounds, 0);
  const [nodes, , reloadNodes] = usePoll(api.nodes, 0);
  const [mempool, , reloadMempool] = usePoll(api.mempool, 3000);
  const [sync, , reloadSync] = usePoll(api.nodesSync, 4000);
  const [rewards, , reloadRewards] = usePoll(api.rewards, 4000);
  const [events, , reloadEvents] = usePoll(api.events, 5000);
  const lastRound = useRef<number>(0);
  const maxAbstain = Math.max(0, n - 1);

  // Live telemetry over Server-Sent Events from the C++ node.
  useEffect(() => {
    const es = new EventSource('/api/consensus/stream');
    es.onmessage = (ev) => {
      const s: ConsensusSnapshot = JSON.parse(ev.data);
      setSnap(s);
      if (!s.running && s.result && s.round !== lastRound.current) {
        lastRound.current = s.round;
        reloadRounds();
        reloadNodes();
        reloadMempool();
        reloadSync();
        reloadRewards();
        reloadEvents();
        onChange();
      }
    };
    return () => es.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const start = async () => {
    setErr(null);
    try {
      const p: ProposeParams = { mode, nodes: n };
      if (mode === 'pow') {
        p.difficulty_hex_zeros = difficulty;
      } else {
        p.abstain = abstain;
        p.punishment_rule = punishmentRule;
        p.alpha = alpha;
        p.validators = subset;
        p.bet_pct = betPct;
        p.vote_window_ms = voteWindow;
        if (seed.trim() !== '') p.seed = Number(seed);
      }
      setSnap(await api.propose(p));
    } catch (e) {
      setErr(e);
    }
  };

  const restake = async (id: number, delta: number) => {
    setNodeErr(null);
    try {
      await api.adjustStake(id, delta);
      reloadNodes();
    } catch (e) {
      setNodeErr(e);
    }
  };

  const toggleDishonest = async (id: number, dishonest: boolean) => {
    setNodeErr(null);
    try {
      await api.setDishonest(id, dishonest);
      reloadNodes();
    } catch (e) {
      setNodeErr(e);
    }
  };

  const running = !!snap?.running;
  const quorumPct =
    mode === 'pos' && snap?.quorum_threshold ? Math.min(100, ((snap.quorum_stake ?? 0) / snap.quorum_threshold) * 100) : 0;
  const maxMinerAttempts = Math.max(1, ...(snap?.miners?.map((m) => m.attempts) ?? [1]));

  return (
    <div className="stack">
      <div className="row" style={{ marginBottom: 4 }}>
        <button className={`btn${mode === 'pow' ? ' primary' : ''}`} disabled={running} onClick={() => setMode('pow')}>
          V1 · Proof of Work
        </button>
        <button className={`btn${mode === 'pos' ? ' primary' : ''}`} disabled={running} onClick={() => setMode('pos')}>
          V2 · Proof of Stake
        </button>
      </div>

      <div className="grid2">
        <section className="card">
          <h2>{mode === 'pow' ? 'Mine a block' : 'Propose a block'}</h2>
          {mode === 'pow' ? (
            <p className="hint">
              Cada nodo es un minero y prueba nonces disjuntos (minero <i>i</i> prueba i, i+N, i+2N, …) buscando un hash con{' '}
              <b>{difficulty}</b> ceros hexadecimales iniciales. Si dos mineros encuentran un nonce válido en la misma ronda, gana
              el <b>nonce más pequeño</b> (nunca hay empate real: los nonces de cada minero nunca coinciden).
            </p>
          ) : (
            <p className="hint">
              Un sorteo ponderado por stake elige un <b>proponente</b> (determinístico, sin cómputo). El bloque se sella si
              validadores con ≥ 2/3 del stake votan a favor. Un proponente deshonesto es rechazado, castigado y se repite el
              sorteo con el resto.
            </p>
          )}
          <label className="field">
            <div className="row between">
              Nodos <span className="v">{n}</span>
            </div>
            <input
              type="range"
              min={config.min_nodes}
              max={config.max_nodes}
              value={n}
              disabled={running}
              onChange={(e) => {
                const v = +e.target.value;
                setN(v);
                setAbstain((a) => Math.min(a, Math.max(0, v - 1)));
              }}
            />
            <span style={{ fontSize: 12 }}>debe cumplir {config.min_nodes} ≤ N ≤ {config.max_nodes}</span>
          </label>
          {mode === 'pow' ? (
            <label className="field">
              <div className="row between">
                Dificultad (ceros hex) <span className="v">{difficulty}</span>
              </div>
              <input
                type="range"
                min={config.min_difficulty_hex_zeros}
                max={config.max_difficulty_hex_zeros}
                value={difficulty}
                disabled={running}
                onChange={(e) => setDifficulty(+e.target.value)}
              />
              <span style={{ fontSize: 12 }}>≈ {fmtBig(16 ** difficulty)} hashes esperados en total</span>
            </label>
          ) : (
            <label className="field">
              <div className="row between">
                Validadores que no responden (demo) <span className="v">{abstain}</span>
              </div>
              <input
                type="range"
                min={0}
                max={maxAbstain}
                value={abstain}
                disabled={running}
                onChange={(e) => setAbstain(+e.target.value)}
              />
              <span style={{ fontSize: 12 }}>útil para demostrar el límite exacto de 2/3 del quórum</span>
            </label>
          )}
          {mode === 'pos' && (
            <div className="stack" style={{ gap: 8 }}>
              <label className="field">
                <div className="row between">
                  Validadores (subconjunto aleatorio) <span className="v">{subset === 0 ? 'todos con stake' : subset}</span>
                </div>
                <input type="range" min={0} max={n} value={subset} disabled={running} onChange={(e) => setSubset(+e.target.value)} />
              </label>
              <label className="field">
                <div className="row between">
                  Apuesta (% del stake de cada validador) <span className="v">{betPct}%</span>
                </div>
                <input type="range" min={1} max={100} value={betPct} disabled={running} onChange={(e) => setBetPct(+e.target.value)} />
                <span style={{ fontSize: 12 }}>la apuesta se bloquea durante la ronda y se libera al terminar</span>
              </label>
              <label className="field">
                <div className="row between">
                  Ventana de votación externa <span className="v">{voteWindow} ms</span>
                </div>
                <input type="range" min={0} max={10000} step={500} value={voteWindow} disabled={running} onChange={(e) => setVoteWindow(+e.target.value)} />
                <span style={{ fontSize: 12 }}>mantiene abierta la votación para votar a mano por los validadores ausentes</span>
              </label>
              <label className="field">
                <div className="row between">Semilla (opcional, reproducible)</div>
                <input
                  type="number"
                  placeholder="aleatoria"
                  value={seed}
                  disabled={running}
                  onChange={(e) => setSeed(e.target.value)}
                />
              </label>
            </div>
          )}
          {mode === 'pos' && (
            <label className="field">
              <div className="row between">
                Regla de castigo
                <span className="row" style={{ gap: 4, margin: 0 }}>
                  <button
                    className={`btn small${punishmentRule === 'A' ? ' primary' : ''}`}
                    disabled={running}
                    onClick={() => setPunishmentRule('A')}
                  >
                    A · pierde todo
                  </button>
                  <button
                    className={`btn small${punishmentRule === 'B' ? ' primary' : ''}`}
                    disabled={running}
                    onClick={() => setPunishmentRule('B')}
                  >
                    B · pierde %
                  </button>
                </span>
              </div>
              {punishmentRule === 'A' ? (
                <span style={{ fontSize: 12 }}>
                  c = a<sub>p</sub>: el proponente deshonesto pierde toda su apuesta y queda inhabilitado para siempre.
                </span>
              ) : (
                <>
                  <input
                    type="range"
                    min={0.1}
                    max={1}
                    step={0.1}
                    value={alpha}
                    disabled={running}
                    onChange={(e) => setAlpha(+e.target.value)}
                  />
                  <span style={{ fontSize: 12 }}>
                    c = min(aₚ, α·valor de las tx), con valor = núm_tx × {config.tx_value} y α={alpha.toFixed(1)}: pierde solo una parte de su apuesta y sigue elegible.
                  </span>
                </>
              )}
            </label>
          )}
          <div className="row">
            {!running ? (
              <button className="btn primary" onClick={start}>
                {mode === 'pow' ? `⛏ Minar con ${n} nodos` : `Proponer con ${n} nodos`}
              </button>
            ) : (
              <button className="btn danger" onClick={() => api.stopConsensus()}>
                Detener ronda
              </button>
            )}
            <span className="hint" style={{ margin: 0 }}>
              {mempool?.length ?? 0} tx en mempool (máx {config.max_tx_per_block}/bloque)
              {!mempool?.length && ' — se necesita al menos 1 para minar/proponer'}
            </span>
          </div>
          <ErrorBox error={err} />
        </section>

        <section className="card">
          <h2>Ronda {snap?.round || '—'}</h2>
          {snap && snap.round > 0 ? (
            <>
              <div className="stats" style={{ marginBottom: 12 }}>
                <div className="stat">
                  <span className="l">estado</span>
                  <span className="v">
                    {running ? (
                      <>
                        <span className="pulse" /> {mode === 'pow' ? 'minando' : 'votando'}
                      </>
                    ) : (
                      snap.result?.outcome ?? '—'
                    )}
                  </span>
                </div>
                <div className="stat">
                  <span className="l">elapsed</span>
                  <span className="v">{(snap.elapsed_ms / 1000).toFixed(2)}s</span>
                </div>
                {mode === 'pos' && (
                  <>
                    <div className="stat">
                      <span className="l">proponente</span>
                      <span className="v mono">{snap.proposer || '—'}</span>
                    </div>
                    <div className="stat">
                      <span className="l">intento</span>
                      <span className="v">{snap.attempt ?? 0}</span>
                    </div>
                  </>
                )}
              </div>
              {snap.phase && <PhaseStrip snap={snap} />}
              {mode === 'pos' && (
                <div className="bar" style={{ marginBottom: 12 }}>
                  <i style={{ width: `${quorumPct}%` }} />
                </div>
              )}
              <dl className="kv">
                <dt>altura candidata</dt>
                <dd>#{snap.height}</dd>
                <dt>hash_anterior</dt>
                <dd>
                  <Hash value={snap.prev_hash} len={20} zeros />
                </dd>
                <dt>transacciones</dt>
                <dd>{snap.tx_ids.length}</dd>
                {mode === 'pos' && (
                  <>
                    <dt>semilla</dt>
                    <dd className="mono">{snap.seed}</dd>
                    <dt>quórum</dt>
                    <dd>{fmtBig(snap.quorum_stake ?? 0)} / {fmtBig(snap.quorum_threshold ?? 0)} (de {fmtBig(snap.total_stake ?? 0)} total)</dd>
                  </>
                )}
              </dl>
              {snap.result?.outcome === 'sealed' && (
                <div className="alert ok">
                  Bloque #{snap.result.height} sellado por <b>{snap.result.proposer}</b>
                  {mode === 'pow'
                    ? <> con nonce {fmtNum(snap.result.nonce ?? 0)}</>
                    : <> con {fmtBig(snap.result.quorum_stake ?? 0)}/{fmtBig(snap.result.total_stake ?? 0)} stake</>}
                  {' → '}
                  <Hash value={snap.result.hash} len={20} zeros />{' '}
                  <button className="btn small" onClick={onGoChain}>Ver cadena →</button>
                </div>
              )}
              {snap.result?.outcome === 'no_quorum' && <div className="alert warn">{snap.result.error}</div>}
              {(snap.result?.outcome === 'rejected' || snap.result?.outcome === 'error') && (
                <div className="alert err">Bloque rechazado: {snap.result.error}</div>
              )}
            </>
          ) : (
            <div className="empty">No hay ronda en esta sesión todavía.</div>
          )}
        </section>
      </div>

      {mode === 'pow' && snap && !!snap.miners?.length && (
        <section className="card">
          <h2>Mineros</h2>
          <p className="hint">Cada minero prueba su propia clase de residuo módulo N — nunca prueban el mismo nonce.</p>
          <div className="miners">
            {snap.miners.map((m) => (
              <div key={m.name} className={`miner ${m.status}`}>
                <div className="row between">
                  <span className="name">{m.name}</span>
                  {m.status === 'mining' ? <span className="pulse" /> : m.status === 'winner' ? <Badge kind="ok">winner</Badge> : null}
                </div>
                <div className="big">{fmtBig(m.attempts)}</div>
                <div style={{ fontSize: 12, color: 'var(--muted)' }}>{MINER_STATUS_TEXT[m.status]}</div>
                <div className="bar" style={{ marginTop: 6 }}>
                  <i style={{ width: `${(m.attempts / maxMinerAttempts) * 100}%` }} />
                </div>
                <div style={{ fontSize: 12, marginTop: 6 }}>
                  nonce {fmtNum(m.nonce)} {m.last_hash && <>→ <Hash value={m.last_hash} len={10} zeros /></>}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {mode === 'pos' && snap && !!snap.validators?.length && (
        <section className="card">
          <h2>Validadores (esta ronda)</h2>
          <p className="hint">
            Cada validador apuesta, vota tras un retraso simulado (semilla configurable) y su voto pesa lo que apostó. Si el proponente
            es deshonesto, los honestos votan EN CONTRA. Con la ventana de votación abierta puedes votar por los ausentes; votar dos
            veces o por alguien que no es validador se rechaza.
          </p>
          <div className="miners">
            {snap.validators.map((v) => (
              <div key={v.name} className={`miner ${v.status === 'voted' ? 'winner' : v.status === 'abstained' || v.status === 'against' ? 'late' : v.status === 'voting' ? 'mining' : ''}`}>
                <div className="row between">
                  <span className="name">{v.name}</span>
                  {v.status === 'voting' ? <span className="pulse" /> : v.status === 'voted' ? <Badge kind="ok">voted</Badge> : null}
                  {v.dishonest && <Badge kind="bad">deshonesto</Badge>}
                </div>
                <div className="big">{fmtBig(v.bet)} apuesta</div>
                <div style={{ fontSize: 12, color: 'var(--muted)' }}>de {fmtBig(v.stake)} de saldo · {VOTER_STATUS_TEXT[v.status]}</div>
                {running && snap.phase === 'VOTACION' && v.simulated_absent && v.status !== 'voted' && v.status !== 'against' && (
                  <div className="row" style={{ gap: 4, marginTop: 6 }}>
                    <button className="btn small" onClick={() => api.vote(v.name, 'yes').catch(setErr)}>votar sí</button>
                    <button className="btn small danger" onClick={() => api.vote(v.name, 'no').catch(setErr)}>votar no</button>
                  </div>
                )}
                {v.signature && (
                  <div style={{ fontSize: 12, marginTop: 6 }}>
                    firmó → <Hash value={v.signature} len={10} />
                  </div>
                )}
              </div>
            ))}
          </div>
          {!!snap.attempts_log?.length && (
            <div style={{ marginTop: 10 }}>
              <div className="hint">Historial de sorteos de esta ronda:</div>
              {snap.attempts_log.map((a) => (
                <div key={a.attempt} style={{ fontSize: 12, marginTop: 4 }}>
                  intento {a.attempt}: <span className="mono">{a.proposer}</span>{' '}
                  {a.dishonest && <Badge kind="bad">deshonesto</Badge>}{' '}
                  <Badge kind={a.outcome === 'sealed' ? 'ok' : a.outcome === 'rejected_retry' ? 'bad' : 'neutral'}>{a.outcome}</Badge>
                  {' '}({fmtBig(a.quorum_stake)}/{fmtBig(a.total_stake)})
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      <div className="grid2">
        <section className="card">
          <h2>Nodos &amp; stake</h2>
          <ErrorBox error={nodeErr} />
          {!nodes?.length ? (
            <div className="empty">Los nodos se registran automáticamente al iniciar la primera ronda.</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>nodo</th>
                    <th>stake</th>
                    <th>bloqueado</th>
                    <th>saldo (recompensas)</th>
                    <th>bloques</th>
                    <th>estado</th>
                    <th>deshonesto</th>
                  </tr>
                </thead>
                <tbody>
                  {[...nodes].sort((a, b) => b.stake - a.stake).map((v) => (
                    <tr key={v.id}>
                      <td className="mono">{v.name}</td>
                      <td>
                        <div className="row" style={{ gap: 4 }}>
                          <button className="btn small" disabled={v.slashed || running} onClick={() => restake(v.id, -10)}>−</button>
                          <span>{v.stake}</span>
                          <button className="btn small" disabled={v.slashed || running} onClick={() => restake(v.id, 10)}>+</button>
                        </div>
                      </td>
                      <td>{v.locked > 0 ? <Badge kind="info">🔒 {v.locked}</Badge> : '—'}</td>
                      <td>{v.balance}</td>
                      <td>{v.blocks_proposed}</td>
                      <td>{v.slashed ? <Badge kind="bad">slashed</Badge> : v.active ? <Badge kind="ok">active</Badge> : <Badge kind="neutral">inactive</Badge>}</td>
                      <td>
                        <button
                          className={`btn small${v.dishonest ? ' danger' : ''}`}
                          disabled={v.slashed || running}
                          onClick={() => toggleDishonest(v.id, !v.dishonest)}
                        >
                          {v.dishonest ? 'sí' : 'no'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
        <section className="card">
          <h2>Historial de rondas</h2>
          {!rounds?.length ? (
            <div className="empty">Aún no hay rondas.</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>#</th>
                    <th>modo</th>
                    <th>outcome</th>
                    <th>proponente</th>
                    <th>quórum</th>
                    <th>time</th>
                  </tr>
                </thead>
                <tbody>
                  {rounds.map((r) => (
                    <tr key={r.id}>
                      <td>{r.id}</td>
                      <td>{r.mode}</td>
                      <td>
                        <Badge kind={r.outcome === 'sealed' ? 'ok' : r.outcome === 'no_quorum' ? 'neutral' : 'bad'}>{r.outcome}</Badge>
                      </td>
                      <td className="mono">{r.proposer ?? '—'}{r.block_height !== null && ` → #${r.block_height}`}</td>
                      <td>{r.mode === 'pos' ? `${fmtBig(r.quorum_stake)}/${fmtBig(r.total_stake)}` : '—'}</td>
                      <td>{(r.duration_ms / 1000).toFixed(2)}s</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>

      <div className="grid2">
        <section className="card">
          <h2>Nodos (copias de la cadena)</h2>
          <p className="hint">
            Cada nodo guarda su propia cadena completa y valida cada bloque que recibe. Una cadena recibida solo se adopta si
            TODOS sus bloques son válidos y es más larga que la propia. Prueba enviar una cadena corta o alterada.
          </p>
          {notice && <div className={`alert ${notice.kind === 'ok' ? 'ok' : 'err'}`}>{notice.text}</div>}
          {!sync?.length ? (
            <div className="empty">Sin nodos todavía.</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>nodo</th>
                    <th>altura</th>
                    <th>bloques</th>
                    <th>hash</th>
                    <th>copia</th>
                    <th>sincronizado</th>
                    <th>enviarle una cadena</th>
                  </tr>
                </thead>
                <tbody>
                  {sync.map((s) => (
                    <tr key={s.node_id}>
                      <td className="mono">{s.name}</td>
                      <td>{s.height}</td>
                      <td>{s.chain_length}</td>
                      <td><Hash value={s.hash} len={10} /></td>
                      <td>{s.valid ? <Badge kind="ok">válida</Badge> : <Badge kind="bad">inválida</Badge>}</td>
                      <td>{s.synced ? <Badge kind="ok">✓</Badge> : <Badge kind="bad">{s.note ?? 'desincronizado'}</Badge>}</td>
                      <td>
                        <div className="row" style={{ gap: 4 }}>
                          {(['valid', 'shorter', 'tampered'] as const).map((k) => (
                            <button
                              key={k}
                              className={`btn small${k === 'valid' ? '' : ' danger'}`}
                              onClick={() =>
                                api
                                  .receiveChain(s.node_id, k)
                                  .then((r) => {
                                    setNotice({ kind: r.accepted ? 'ok' : 'bad', text: `${s.name} ${r.accepted ? 'adoptó' : 'rechazó'} la cadena (${k}): ${r.reason}` });
                                    reloadSync();
                                    reloadEvents();
                                  })
                                  .catch((e) => setNotice({ kind: 'bad', text: String(e?.message ?? e) }))
                              }
                            >
                              {k === 'valid' ? 'válida' : k === 'shorter' ? 'más corta' : 'alterada'}
                            </button>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
        <section className="card">
          <h2>Recompensas PoW (6 confirmaciones)</h2>
          <p className="hint">
            La recompensa ({config.block_reward}) del bloque de altura h queda pendiente hasta que la cadena alcanza h+{config.reward_confirmations}; solo
            entonces se acredita al saldo del minero. Pedirla antes se rechaza.
          </p>
          {!rewards?.length ? (
            <div className="empty">Aún no hay recompensas de PoW.</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>bloque</th>
                    <th>minero</th>
                    <th>estado</th>
                  </tr>
                </thead>
                <tbody>
                  {rewards.map((w) => (
                    <tr key={w.height}>
                      <td>#{w.height}</td>
                      <td className="mono">{w.miner}</td>
                      <td>
                        <div className="row" style={{ gap: 6 }}>
                          {w.confirmed ? (
                            <Badge kind="ok">acreditada +{w.amount}</Badge>
                          ) : (
                            <Badge kind="neutral">pendiente · faltan {w.remaining_confirmations}</Badge>
                          )}
                          <button
                            className="btn small"
                            onClick={() =>
                              api
                                .claimReward(w.height)
                                .then((r) => setNotice({ kind: 'ok', text: `Recompensa del bloque #${r.height}: +${r.amount} ya acreditada a ${r.miner}` }))
                                .catch((e) => setNotice({ kind: 'bad', text: String(e?.message ?? e) }))
                                .finally(() => reloadEvents())
                            }
                          >
                            reclamar
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>

      <section className="card">
        <h2>Bitácora de eventos</h2>
        <p className="hint">Bloques sellados, rondas rechazadas, castigos, recompensas, apuestas liberadas, votos rechazados y nodos que rechazan bloques o cadenas, del más reciente al más antiguo.</p>
        {!events?.length ? (
          <div className="empty">Aún no hay eventos.</div>
        ) : (
          <div className="stack" style={{ gap: 4, maxHeight: 260, overflowY: 'auto' }}>
            {events.map((e, i) => (
              <div key={i} className="row between" style={{ fontSize: 13 }}>
                <span>
                  <Badge kind={EVENT_BADGE[e.type] ?? EVENT_BADGE_EXTRA[e.type] ?? 'neutral'}>{e.type}</Badge> {e.message}
                </span>
                <span style={{ color: 'var(--muted)', fontSize: 11 }}>{new Date(e.created_at).toLocaleString()}</span>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
