import { useEffect, useRef, useState } from 'react';
import { api, type Config, type MiningSnapshot } from '../api';
import { Badge, ErrorBox, Hash, fmtBig, fmtNum, fmtRate, usePoll } from '../components/ui';

const STATUS_TEXT: Record<string, string> = {
  idle: 'idle',
  mining: 'hashing…',
  winner: 'WINNER — sealed the block',
  late: 'found a solution too late (orphan)',
  stale: 'stopped — candidate is stale',
};

export default function MiningArena({
  config,
  onChange,
  onGoChain,
}: {
  config: Config;
  onChange: () => void;
  onGoChain: () => void;
}) {
  const [n, setN] = useState(4);
  const [bits, setBits] = useState(config.default_difficulty);
  const [snap, setSnap] = useState<MiningSnapshot | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [rounds, , reloadRounds] = usePoll(api.rounds, 0);
  const [miners, , reloadMiners] = usePoll(api.miners, 0);
  const [mempool, , reloadMempool] = usePoll(api.mempool, 3000);
  const lastRound = useRef<number>(0);
  const lastRate = useRef<number>(0);

  // Live telemetry over Server-Sent Events from the C++ node.
  useEffect(() => {
    const es = new EventSource('/api/mine/stream');
    es.onmessage = (ev) => {
      const s: MiningSnapshot = JSON.parse(ev.data);
      setSnap(s);
      if (s.running && s.total_hashrate > 0) lastRate.current = s.total_hashrate;
      if (!s.running && s.result && s.round !== lastRound.current) {
        lastRound.current = s.round;
        reloadRounds();
        reloadMiners();
        reloadMempool();
        onChange();
      }
    };
    return () => es.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const start = async () => {
    setErr(null);
    try {
      setSnap(await api.mine(n, bits));
    } catch (e) {
      setErr(e);
    }
  };

  const running = !!snap?.running;
  const expected = 2 ** bits;
  const eta = lastRate.current ? expected / lastRate.current : null;
  const maxHashes = Math.max(1, ...(snap?.miners.map((m) => m.hashes) ?? [1]));

  return (
    <div className="stack">
      <div className="grid2">
        <section className="card">
          <h2>Start a mining round</h2>
          <p className="hint">
            Permissioned proof-of-work: each registered miner (a company node with its own key) races to find a nonce whose double
            SHA-256 header hash has ≥ <b>{bits}</b> leading zero bits. The winner signs the block; the node validates it and
            appends it.
          </p>
          <label className="field">
            <div className="row between">
              Competing miners <span className="v">{n}</span>
            </div>
            <input type="range" min={1} max={config.max_miners} value={n} disabled={running} onChange={(e) => setN(+e.target.value)} />
          </label>
          <label className="field">
            <div className="row between">
              Difficulty (leading zero bits) <span className="v">{bits}</span>
            </div>
            <input type="range" min={8} max={30} value={bits} disabled={running} onChange={(e) => setBits(+e.target.value)} />
            <span style={{ fontSize: 12 }}>
              ≈ {fmtBig(expected)} hashes expected
              {eta !== null && <> · ≈ {eta < 1 ? `${Math.round(eta * 1000)} ms` : `${eta.toFixed(1)} s`} at last observed rate</>}
            </span>
          </label>
          <div className="row">
            {!running ? (
              <button className="btn primary" onClick={start}>
                ⛏ Start round with {n} miner{n > 1 ? 's' : ''}
              </button>
            ) : (
              <button className="btn danger" onClick={() => api.stopMining()}>
                Stop round
              </button>
            )}
            <span className="hint" style={{ margin: 0 }}>
              {mempool?.length ?? 0} tx in mempool (max {config.max_tx_per_block}/block){!mempool?.length && ' — an empty block will be mined'}
            </span>
          </div>
          <ErrorBox error={err} />
        </section>

        <section className="card">
          <h2>Round {snap?.round || '—'}</h2>
          {snap && snap.round > 0 ? (
            <>
              <div className="stats" style={{ marginBottom: 12 }}>
                <div className="stat">
                  <span className="l">status</span>
                  <span className="v">{running ? <><span className="pulse" /> mining</> : snap.result?.outcome ?? '—'}</span>
                </div>
                <div className="stat">
                  <span className="l">elapsed</span>
                  <span className="v">{(snap.elapsed_ms / 1000).toFixed(2)}s</span>
                </div>
                <div className="stat">
                  <span className="l">total hashes</span>
                  <span className="v">{fmtBig(snap.total_hashes)}</span>
                </div>
                <div className="stat">
                  <span className="l">network rate</span>
                  <span className="v">{fmtRate(snap.total_hashrate)}</span>
                </div>
              </div>
              <dl className="kv">
                <dt>candidate height</dt>
                <dd>#{snap.height}</dd>
                <dt>prev_hash</dt>
                <dd>
                  <Hash value={snap.prev_hash} len={20} zeros />
                </dd>
                <dt>transactions</dt>
                <dd>{snap.tx_ids.length}</dd>
                <dt>target</dt>
                <dd className="mono">hash &lt; 2^{256 - snap.difficulty_bits}</dd>
              </dl>
              {snap.result?.outcome === 'sealed' && (
                <div className="alert ok">
                  Block #{snap.result.height} sealed by <b>{snap.result.winner}</b> with nonce {fmtNum(snap.result.nonce ?? 0)} →{' '}
                  <Hash value={snap.result.hash} len={20} zeros />{' '}
                  <button className="btn small" onClick={onGoChain}>View chain →</button>
                </div>
              )}
              {snap.result?.outcome === 'stopped' && <div className="alert warn">Round stopped before any miner found a valid block.</div>}
              {(snap.result?.outcome === 'rejected' || snap.result?.outcome === 'error') && (
                <div className="alert err">Block rejected: {snap.result.error}</div>
              )}
            </>
          ) : (
            <div className="empty">No round yet in this session.</div>
          )}
        </section>
      </div>

      {snap && snap.miners.length > 0 && (
        <section className="card">
          <h2>Miners</h2>
          <p className="hint">Each miner hashes a different candidate (its name and timestamp are in the header), so they search disjoint spaces.</p>
          <div className="miners">
            {snap.miners.map((m) => (
              <div key={m.name} className={`miner ${m.status}`}>
                <div className="row between">
                  <span className="name">{m.name}</span>
                  {m.status === 'mining' ? <span className="pulse" /> : m.status === 'winner' ? <Badge kind="ok">winner</Badge> : null}
                </div>
                <div className="big">{fmtBig(m.hashes)}</div>
                <div style={{ fontSize: 12, color: 'var(--muted)' }}>
                  {fmtRate(m.hashrate)} · {STATUS_TEXT[m.status]}
                </div>
                <div className="bar" style={{ marginTop: 6 }}>
                  <i style={{ width: `${(m.hashes / maxHashes) * 100}%` }} />
                </div>
                {m.hash && (
                  <div style={{ fontSize: 12, marginTop: 6 }}>
                    nonce {fmtNum(m.nonce ?? 0)} → <Hash value={m.hash} len={10} zeros />
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      <div className="grid2">
        <section className="card">
          <h2>Miner leaderboard</h2>
          {!miners?.length ? (
            <div className="empty">Miners are registered automatically on the first round.</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>miner</th>
                  <th>key fingerprint</th>
                  <th>blocks sealed</th>
                </tr>
              </thead>
              <tbody>
                {[...miners].sort((a, b) => b.blocks_mined - a.blocks_mined).map((m) => (
                  <tr key={m.id}>
                    <td className="mono">{m.name}</td>
                    <td>
                      <Hash value={m.fingerprint} len={10} />
                    </td>
                    <td>{m.blocks_mined}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
        <section className="card">
          <h2>Round history</h2>
          {!rounds?.length ? (
            <div className="empty">No rounds yet.</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>#</th>
                    <th>outcome</th>
                    <th>miners</th>
                    <th>bits</th>
                    <th>winner</th>
                    <th>hashes</th>
                    <th>time</th>
                  </tr>
                </thead>
                <tbody>
                  {rounds.map((r) => (
                    <tr key={r.id}>
                      <td>{r.id}</td>
                      <td>
                        <Badge kind={r.outcome === 'sealed' ? 'ok' : r.outcome === 'stopped' ? 'neutral' : 'bad'}>{r.outcome}</Badge>
                      </td>
                      <td>{r.participants.length}</td>
                      <td>{r.difficulty_bits}</td>
                      <td className="mono">{r.winner ?? '—'}{r.block_height !== null && ` → #${r.block_height}`}</td>
                      <td>{fmtBig(r.hashes_total)}</td>
                      <td>{(r.duration_ms / 1000).toFixed(2)}s</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
