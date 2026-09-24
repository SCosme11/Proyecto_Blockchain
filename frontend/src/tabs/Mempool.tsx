import { Fragment, useState } from 'react';
import { api } from '../api';
import { Badge, Canonical, ErrorBox, Hash, fmtTime, usePoll } from '../components/ui';

export default function Mempool({ onGoMining }: { onGoMining: () => void }) {
  const [txs, err] = usePoll(api.mempool, 2000);
  const [open, setOpen] = useState<string | null>(null);

  return (
    <section className="card">
      <div className="row between">
        <div>
          <h2>Mempool — signed, not yet sealed</h2>
          <p className="hint">
            Each transaction was re-verified by the C++ node (ECDSA P-256 over the canonical payload). It becomes immutable once a
            miner seals it into a block.
          </p>
        </div>
        <button className="btn primary" onClick={onGoMining} disabled={!txs?.length}>
          Mine these →
        </button>
      </div>
      <ErrorBox error={err} />
      {!txs?.length ? (
        <div className="empty">Mempool is empty. Sign a MEDIUM work item in step 2.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>tx_id</th>
                <th>artifact</th>
                <th>decision</th>
                <th>signed by</th>
                <th>signed at</th>
                <th>signature</th>
              </tr>
            </thead>
            <tbody>
              {txs.map((t) => (
                <Fragment key={t.tx_id}>
                  <tr className={`clickable${open === t.tx_id ? ' selected' : ''}`} onClick={() => setOpen(open === t.tx_id ? null : t.tx_id)}>
                    <td>
                      <Hash value={t.tx_id} len={12} />
                    </td>
                    <td>
                      {t.work.filename} <span className="badge neutral">{t.work.agent_name}</span>
                    </td>
                    <td>
                      <Badge kind={t.decision === 'APPROVED' ? 'ok' : 'bad'}>{t.decision}</Badge>
                    </td>
                    <td>
                      {t.auditor.name} <Hash value={t.auditor.fingerprint} len={8} />
                    </td>
                    <td>{fmtTime(t.timestamp_ms)}</td>
                    <td>{t.signature_valid ? <Badge kind="ok">valid ✓</Badge> : <Badge kind="bad">invalid</Badge>}</td>
                  </tr>
                  {open === t.tx_id && (
                    <tr>
                      <td colSpan={6}>
                        <div className="hint">Signed payload:</div>
                        <Canonical value={t.canonical} />
                        <div className="hint" style={{ marginTop: 8 }}>
                          Signature (raw r‖s): <span className="mono">{t.signature}</span>
                        </div>
                        {t.comment && <div className="hint">Comment: “{t.comment}”</div>}
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
