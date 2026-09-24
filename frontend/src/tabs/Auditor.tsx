import { useEffect, useMemo, useState } from 'react';
import { api, ApiError, type Decision, type Tx, type WorkItem } from '../api';
import { b64ToBytes, buildCanonical, generateKeyPair, keyStore, sha256Hex, signCanonical, type Identity } from '../crypto';
import { Badge, CANONICAL_FIELDS, Canonical, CategoryBadge, ErrorBox, Hash, usePoll } from '../components/ui';

type Integrity = { status: 'idle' } | { status: 'ok' | 'mismatch'; computed: string; preview: string | null };

export default function Auditor({ onChange, onGoMempool }: { onChange: () => void; onGoMempool: () => void }) {
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [active, setActive] = useState<string | null>(null);
  const [newName, setNewName] = useState('');
  const [idErr, setIdErr] = useState<unknown>(null);

  const [queue, , reloadQueue] = usePoll(api.reviewQueue, 3000);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [integrity, setIntegrity] = useState<Integrity>({ status: 'idle' });
  const [decision, setDecision] = useState<Decision>('APPROVED');
  const [comment, setComment] = useState('');
  const [commentHash, setCommentHash] = useState('');
  const [signing, setSigning] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const [signed, setSigned] = useState<Tx | null>(null);

  const me = identities.find((i) => i.fingerprint === active) ?? null;
  const item = useMemo(() => queue?.find((q) => q.id === selectedId) ?? null, [queue, selectedId]);

  useEffect(() => {
    keyStore.list().then((ids) => {
      setIdentities(ids);
      if (ids.length) setActive(ids[0].fingerprint);
    }, setIdErr);
  }, []);

  useEffect(() => {
    sha256Hex(comment).then(setCommentHash);
  }, [comment]);

  useEffect(() => {
    setIntegrity({ status: 'idle' });
    setErr(null);
  }, [selectedId]);

  const createIdentity = async () => {
    setIdErr(null);
    try {
      const { privateKey, spkiB64 } = await generateKeyPair();
      const reg = await api.registerAuditor(newName.trim(), spkiB64);
      const id: Identity = {
        auditorId: reg.id,
        name: reg.name,
        fingerprint: reg.fingerprint,
        publicKeySpki: spkiB64,
        privateKey,
        createdAt: Date.now(),
      };
      await keyStore.save(id);
      setIdentities((xs) => [...xs, id]);
      setActive(id.fingerprint);
      setNewName('');
      onChange();
    } catch (e) {
      setIdErr(e);
    }
  };

  const verifyArtifact = async (w: WorkItem) => {
    const c = await api.workContent(w.id);
    const bytes = b64ToBytes(c.content_b64);
    const computed = await sha256Hex(bytes);
    let preview: string | null = null;
    try {
      preview = new TextDecoder('utf-8', { fatal: true }).decode(bytes.slice(0, 4000));
    } catch {
      preview = null; // binary artifact
    }
    setIntegrity({ status: computed === w.work_hash ? 'ok' : 'mismatch', computed, preview });
  };

  const previewCanonical = (w: WorkItem, ts: number | string) =>
    buildCanonical({
      workItemId: w.id,
      workHash: w.work_hash,
      artifactType: w.artifact_type,
      score: w.score,
      rulesHash: w.rules_hash,
      decision,
      commentHash,
      auditorFingerprint: me?.fingerprint ?? '<your fingerprint>',
      timestampMs: ts as number,
    });

  const sign = async () => {
    if (!item || !me) return;
    setSigning(true);
    setErr(null);
    try {
      const ts = Date.now();
      const canonical = previewCanonical(item, ts);
      const signature = await signCanonical(me.privateKey, canonical);
      const body = { work_item_id: item.id, auditor_id: me.auditorId, decision, comment, timestamp_ms: ts, signature, canonical };
      let tx;
      try {
        tx = await api.submitTx(body);
      } catch (e) {
        // Fresh database but a key already in this browser: re-register the same public key and retry.
        // The fingerprint (what was signed) is unchanged, so the signature stays valid.
        if (!(e instanceof ApiError && e.message === 'auditor not registered')) throw e;
        const reg = await api.registerAuditor(me.name, me.publicKeySpki);
        const updated = { ...me, auditorId: reg.id };
        await keyStore.save(updated);
        setIdentities((xs) => xs.map((x) => (x.fingerprint === me.fingerprint ? updated : x)));
        tx = await api.submitTx({ ...body, auditor_id: reg.id });
      }
      setSigned(tx);
      setSelectedId(null);
      setComment('');
      reloadQueue();
      onChange();
    } catch (e) {
      setErr(e);
    } finally {
      setSigning(false);
    }
  };

  return (
    <div className="grid-side">
      <div className="stack">
        <section className="card">
          <h2>Reviewer identity</h2>
          <p className="hint">
            A P-256 key pair is generated <b>in this browser</b>. The private key is non-extractable and stored in IndexedDB — the
            server only ever receives the public key.
          </p>
          {identities.map((i) => (
            <div
              key={i.fingerprint}
              className={`list-item${active === i.fingerprint ? ' selected' : ''}`}
              onClick={() => setActive(i.fingerprint)}
            >
              <div className="row between">
                <b>{i.name}</b>
                <span className="badge neutral">#{i.auditorId}</span>
              </div>
              <div style={{ fontSize: 12, color: 'var(--muted)' }}>
                fpr <Hash value={i.fingerprint} len={16} />
              </div>
            </div>
          ))}
          <div className="row" style={{ marginTop: 8 }}>
            <input type="text" placeholder="Your name, e.g. Ana López" value={newName} onChange={(e) => setNewName(e.target.value)} style={{ flex: 1 }} />
            <button className="btn" disabled={!newName.trim()} onClick={createIdentity}>
              Create key
            </button>
          </div>
          <ErrorBox error={idErr} />
        </section>

        <section className="card">
          <h2>Review queue</h2>
          <p className="hint">MEDIUM-confidence work waiting for a responsible human.</p>
          {!queue?.length && <div className="empty">Queue is empty. Submit MEDIUM work in step 1.</div>}
          {queue?.map((w) => (
            <div key={w.id} className={`list-item${selectedId === w.id ? ' selected' : ''}`} onClick={() => setSelectedId(w.id)}>
              <div className="row between">
                <b>{w.filename}</b>
                <CategoryBadge c={w.category} />
              </div>
              <div style={{ fontSize: 12, color: 'var(--muted)' }}>
                #{w.id} · {w.agent_name} · {w.artifact_type} · score {w.score}
              </div>
            </div>
          ))}
        </section>
      </div>

      <div className="stack">
        {signed && (
          <div className="alert ok">
            Signed transaction <Hash value={signed.tx_id} len={16} /> accepted — signature verified by the C++ node and added to the
            mempool. <button className="btn small" onClick={onGoMempool}>View mempool →</button>
          </div>
        )}
        {!item ? (
          <section className="card">
            <div className="empty">Select a work item from the queue to review it.</div>
          </section>
        ) : (
          <section className="card">
            <div className="row between">
              <h2>
                Review #{item.id}: {item.filename}
              </h2>
              <CategoryBadge c={item.category} />
            </div>
            <dl className="kv">
              <dt>agent</dt>
              <dd>{item.agent_name}</dd>
              <dt>artifact type</dt>
              <dd>{item.artifact_type}</dd>
              <dt>score</dt>
              <dd className="mono">{item.score}</dd>
              <dt>why MEDIUM</dt>
              <dd>{item.reasons.join('; ')}</dd>
              <dt>signals</dt>
              <dd className="mono">
                self={item.metrics.self_confidence} tests={item.metrics.tests_passed_ratio} lines={item.metrics.lines_changed}
                {item.metrics.has_external_side_effects && ' side-effects'}
              </dd>
              <dt>work_hash</dt>
              <dd>
                <Hash value={item.work_hash} len={24} />
              </dd>
              <dt>rules</dt>
              <dd>
                {item.rules_version} · <Hash value={item.rules_hash} len={12} />
              </dd>
            </dl>

            <h3>1 · Inspect the artifact</h3>
            <p className="hint">Download the output and re-hash it locally, so you know you're signing exactly what the agent produced.</p>
            <button className="btn" onClick={() => verifyArtifact(item).catch(setErr)}>
              Download & verify SHA-256 in browser
            </button>
            {integrity.status !== 'idle' && (
              <>
                <div className={`alert ${integrity.status === 'ok' ? 'ok' : 'err'}`}>
                  {integrity.status === 'ok' ? '✓ Local hash matches work_hash' : '✗ Hash mismatch — do not sign'}:{' '}
                  <span className="mono">{integrity.computed.slice(0, 24)}…</span>
                </div>
                {integrity.preview !== null ? <pre className="pre">{integrity.preview}</pre> : <div className="hint">(binary artifact — no preview)</div>}
              </>
            )}

            <h3>2 · Decide</h3>
            <div className="row" style={{ marginBottom: 10 }}>
              <div className="seg">
                {(['APPROVED', 'REJECTED'] as Decision[]).map((d) => (
                  <button key={d} className={decision === d ? 'on' : ''} onClick={() => setDecision(d)}>
                    {d}
                  </button>
                ))}
              </div>
            </div>
            <textarea rows={3} placeholder="Review notes (hashed into the signed payload)" value={comment} onChange={(e) => setComment(e.target.value)} />

            <h3>3 · Sign</h3>
            <p className="hint">This is the exact string your private key will sign (the timestamp is set at the moment you click):</p>
            <Canonical value={previewCanonical(item, '<now>')} />
            <div className="hint" style={{ fontSize: 12 }}>
              fields: {CANONICAL_FIELDS.join(' | ')}
            </div>
            <div className="row" style={{ marginTop: 10 }}>
              <button className="btn primary" disabled={!me || integrity.status !== 'ok' || signing} onClick={sign}>
                {signing ? 'Signing…' : `Sign as ${me?.name ?? '…'} & submit`}
              </button>
              {!me && <Badge kind="bad">create a reviewer identity first</Badge>}
              {me && integrity.status !== 'ok' && <Badge kind="neutral">verify the artifact first</Badge>}
            </div>
            <ErrorBox error={err} />
          </section>
        )}
      </div>
    </div>
  );
}
