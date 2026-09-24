import { Fragment, useState } from 'react';
import { api, type Block, type ChainVerification } from '../api';
import { Badge, Canonical, ErrorBox, Hash, fmtNum, fmtTime, usePoll } from '../components/ui';

const TAMPERS = [
  { kind: 'tx_decision', label: 'Flip a signed decision' },
  { kind: 'comment', label: "Edit a reviewer's comment" },
  { kind: 'artifact', label: 'Modify an approved artifact' },
  { kind: 'block_nonce', label: "Change a block's nonce" },
] as const;

export default function ChainExplorer() {
  const [blocks, err, reload] = usePoll(api.blocks, 4000);
  const [open, setOpen] = useState<Record<number, Block>>({});
  const [verification, setVerification] = useState<ChainVerification | null>(null);
  const [msg, setMsg] = useState<{ kind: 'ok' | 'warn' | 'err'; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const status = new Map(verification?.blocks.map((b) => [b.height, b]) ?? []);

  const toggle = async (h: number) => {
    if (open[h]) {
      const { [h]: _, ...rest } = open;
      setOpen(rest);
    } else {
      const b = await api.block(h);
      setOpen({ ...open, [h]: b });
    }
  };

  const verify = async () => {
    setBusy(true);
    try {
      const v = await api.verify();
      setVerification(v);
      setMsg(
        v.ok
          ? { kind: 'ok', text: `✓ All ${v.height + 1} blocks verified: hashes, links, proof-of-work, miner signatures, merkle roots, auditor signatures and off-chain artifacts.` }
          : { kind: 'err', text: `✗ Chain integrity broken at block #${v.first_bad_height}. Every later block is invalid too.` },
      );
    } finally {
      setBusy(false);
    }
  };

  const tamper = async (kind: (typeof TAMPERS)[number]['kind']) => {
    try {
      const r = await api.tamper(kind);
      setMsg({ kind: 'warn', text: `Tampered: ${r.change} (${r.target}), directly in Postgres. Now click “Verify chain”.` });
      setVerification(null);
      setOpen({});
      reload();
    } catch (e) {
      setMsg({ kind: 'err', text: e instanceof Error ? e.message : String(e) });
    }
  };

  const restore = async () => {
    const r = await api.restore();
    setMsg({ kind: 'ok', text: `Reverted ${r.restored} tamper edit(s).` });
    setVerification(null);
    setOpen({});
    reload();
  };

  return (
    <div className="grid-side">
      <div className="stack">
        <section className="card">
          <h2>Integrity</h2>
          <p className="hint">Re-verifies the whole chain from genesis in C++.</p>
          <button className="btn primary" onClick={verify} disabled={busy}>
            {busy ? 'Verifying…' : 'Verify chain'}
          </button>
          {msg && <div className={`alert ${msg.kind}`}>{msg.text}</div>}
        </section>
        <section className="card">
          <h2>Tamper demo</h2>
          <p className="hint">
            Pretend you are an insider with database access and try to rewrite history. The latest confirmed transaction or block
            is edited in Postgres.
          </p>
          <div className="stack" style={{ gap: 6 }}>
            {TAMPERS.map((t) => (
              <button key={t.kind} className="btn danger" onClick={() => tamper(t.kind)}>
                {t.label}
              </button>
            ))}
            <button className="btn" onClick={restore}>
              Undo all tampering
            </button>
          </div>
        </section>
      </div>

      <section className="card">
        <h2>Blocks</h2>
        <ErrorBox error={err} />
        <div className="chain">
          {blocks?.map((b, i) => {
            const v = status.get(b.height);
            const broken = v && !v.ok;
            const detail = open[b.height];
            return (
              <Fragment key={b.height}>
                {i > 0 && <div className={`link${broken ? ' broken' : ''}`} />}
                <div className={`block${broken ? ' broken' : ''}${b.height === 0 ? ' genesis' : ''}`} onClick={() => toggle(b.height)}>
                  <div className="head">
                    <span className="height">#{b.height}</span>
                    <Hash value={b.hash} len={20} zeros />
                    <span className="badge neutral">{b.tx_count} tx</span>
                    {b.height > 0 && <span className="badge info">{b.miner}</span>}
                    {v && (v.ok ? <Badge kind="ok">valid</Badge> : <Badge kind="bad">invalid</Badge>)}
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 4 }}>
                    prev <Hash value={b.prev_hash} len={10} /> · merkle <Hash value={b.merkle_root} len={10} /> · nonce{' '}
                    {fmtNum(b.nonce)} · {b.difficulty_bits} bits · {fmtTime(b.timestamp_ms)}
                  </div>
                  {broken && (
                    <ul style={{ margin: '6px 0 0', paddingLeft: 18, color: 'var(--low)', fontSize: 13 }}>
                      {v!.errors.map((e, k) => (
                        <li key={k}>{e}</li>
                      ))}
                    </ul>
                  )}
                  {detail && (
                    <div onClick={(e) => e.stopPropagation()} style={{ cursor: 'default' }}>
                      <h3 style={{ fontSize: 12, color: 'var(--muted)' }}>Header pre-image (double SHA-256 → block hash)</h3>
                      <pre className="pre">{detail.header_preimage}</pre>
                      {detail.miner_signature && (
                        <div style={{ fontSize: 12, marginTop: 6 }}>
                          miner signature: <span className="mono" style={{ overflowWrap: 'anywhere' }}>{detail.miner_signature}</span>
                        </div>
                      )}
                      {detail.transactions?.map((t) => (
                        <div key={t.tx_id} className="tx">
                          <div className="row">
                            <b>tx</b> <Hash value={t.tx_id} len={16} />
                            <Badge kind={t.decision === 'APPROVED' ? 'ok' : 'bad'}>{t.decision}</Badge>
                            {t.signature_valid ? <Badge kind="ok">sig ✓</Badge> : <Badge kind="bad">sig ✗</Badge>}
                            {!t.tx_id_valid && <Badge kind="bad">tx_id ✗</Badge>}
                          </div>
                          <div style={{ fontSize: 13, margin: '4px 0' }}>
                            <b>{t.auditor.name}</b> took responsibility for <b>{t.work.filename}</b> by {t.work.agent_name} (score{' '}
                            {t.work.score}) on {fmtTime(t.timestamp_ms)}
                            {t.comment && <> — “{t.comment}”</>}
                          </div>
                          <Canonical value={t.canonical} />
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </Fragment>
            );
          })}
        </div>
      </section>
    </div>
  );
}
