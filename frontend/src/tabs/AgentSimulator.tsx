import { useState } from 'react';
import { api, type Config, type Metrics, type WorkItem } from '../api';
import { bytesToB64 } from '../crypto';
import { CategoryBadge, ErrorBox, Hash, usePoll } from '../components/ui';

interface Preset {
  label: string;
  agent: string;
  type: string;
  filename: string;
  content: string;
  metrics: Metrics;
}

const PRESETS: Preset[] = [
  {
    label: 'Small refactor, all tests pass',
    agent: 'code-agent',
    type: 'code',
    filename: 'utils/format_date.ts',
    content: `export function formatDate(d: Date): string {\n  return d.toISOString().slice(0, 10);\n}\n`,
    metrics: { self_confidence: 0.95, tests_passed_ratio: 1, lines_changed: 18, has_external_side_effects: false },
  },
  {
    label: 'Excel forecast emailed to CFO',
    agent: 'finance-agent',
    type: 'excel_model',
    filename: 'q4_revenue_forecast.xlsx',
    content: `Region,Q4 Forecast,Growth\nNorth,1250000,0.08\nSouth,980000,0.05\nWest,1410000,0.11\n=SUM(B2:B4)\n`,
    metrics: { self_confidence: 0.85, tests_passed_ratio: 0.9, lines_changed: 140, has_external_side_effects: true },
  },
  {
    label: 'Large DB migration',
    agent: 'code-agent',
    type: 'code',
    filename: 'migrations/0042_split_customers.sql',
    content: `ALTER TABLE customers ADD COLUMN segment TEXT;\nUPDATE customers SET segment = 'smb' WHERE employees < 50;\n-- ...\n`,
    metrics: { self_confidence: 0.8, tests_passed_ratio: 0.85, lines_changed: 260, has_external_side_effects: false },
  },
  {
    label: 'ETL pipeline, tests failing',
    agent: 'data-agent',
    type: 'data_pipeline',
    filename: 'etl/nightly_sales.py',
    content: `def run():\n    rows = extract()\n    load(transform(rows))  # TODO handle nulls\n`,
    metrics: { self_confidence: 0.9, tests_passed_ratio: 0.2, lines_changed: 75, has_external_side_effects: false },
  },
];

const STATUS_LABEL: Record<string, string> = {
  rework_required: 'sent back to agent',
  auto_accepted: 'auto-accepted',
  pending_review: 'awaiting human',
  signed: 'signed · in mempool',
  on_chain: 'on chain',
};

export default function AgentSimulator({
  config,
  onChange,
  onGoReview,
}: {
  config: Config;
  onChange: () => void;
  onGoReview: () => void;
}) {
  const types = Object.keys(config.rules.artifact_type_risk);
  const [agent, setAgent] = useState('code-agent');
  const [type, setType] = useState(types[0] ?? 'code');
  const [filename, setFilename] = useState('output.txt');
  const [content, setContent] = useState('');
  const [file, setFile] = useState<{ name: string; b64: string; size: number } | null>(null);
  const [m, setM] = useState<Metrics>({
    self_confidence: 0.8,
    tests_passed_ratio: 0.8,
    lines_changed: 120,
    has_external_side_effects: false,
  });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const [result, setResult] = useState<WorkItem | null>(null);
  const [items, , reloadItems] = usePoll(() => api.work(), 3000);

  const applyPreset = (p: Preset) => {
    setAgent(p.agent);
    setType(p.type);
    setFilename(p.filename);
    setContent(p.content);
    setFile(null);
    setM(p.metrics);
  };

  const onFile = async (f: File | undefined) => {
    if (!f) return;
    const bytes = new Uint8Array(await f.arrayBuffer());
    setFile({ name: f.name, b64: bytesToB64(bytes), size: bytes.length });
    setFilename(f.name);
  };

  const submit = async () => {
    setBusy(true);
    setErr(null);
    try {
      const r = await api.submitWork({
        agent_name: agent,
        artifact_type: type,
        filename,
        ...(file ? { content_b64: file.b64 } : { content_text: content || `(empty output from ${agent})` }),
        metrics: m,
      });
      setResult(r);
      reloadItems();
      onChange();
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  };

  const slider = (key: 'self_confidence' | 'tests_passed_ratio', label: string) => (
    <label className="field">
      <div className="row between">
        {label} <span className="v">{m[key].toFixed(2)}</span>
      </div>
      <input type="range" min={0} max={1} step={0.01} value={m[key]} onChange={(e) => setM({ ...m, [key]: +e.target.value })} />
    </label>
  );

  const { low, high } = config.rules.thresholds;

  return (
    <div className="stack">
      <div className="grid2">
        <section className="card">
          <h2>Simulate an AI agent's output</h2>
          <p className="hint">
            The agent submits its work plus self-reported and objective signals. The C++ rules engine scores it; only{' '}
            <b>MEDIUM</b> work needs a human signature and can reach the chain.
          </p>
          <div className="row" style={{ marginBottom: 12 }}>
            {PRESETS.map((p) => (
              <button key={p.label} className="btn small" onClick={() => applyPreset(p)}>
                {p.label}
              </button>
            ))}
          </div>
          <div className="grid2" style={{ gap: 12 }}>
            <label className="field">
              Agent
              <input type="text" value={agent} onChange={(e) => setAgent(e.target.value)} />
            </label>
            <label className="field">
              Artifact type
              <select value={type} onChange={(e) => setType(e.target.value)}>
                {types.map((t) => (
                  <option key={t} value={t}>
                    {t} (risk {config.rules.artifact_type_risk[t]})
                  </option>
                ))}
              </select>
            </label>
          </div>
          <label className="field">
            File name
            <input type="text" value={filename} onChange={(e) => setFilename(e.target.value)} />
          </label>
          <label className="field">
            <div className="row between">
              Output content
              <span>
                or upload: <input type="file" onChange={(e) => onFile(e.target.files?.[0])} />
              </span>
            </div>
            {file ? (
              <div className="alert info">
                Using uploaded file <b>{file.name}</b> ({file.size.toLocaleString()} bytes){' '}
                <button className="btn small" onClick={() => setFile(null)}>
                  use text instead
                </button>
              </div>
            ) : (
              <textarea rows={6} value={content} onChange={(e) => setContent(e.target.value)} placeholder="Paste the agent's output…" />
            )}
          </label>
        </section>

        <section className="card">
          <h2>Signals for the confidence rules</h2>
          <p className="hint">
            Rule set <code>{config.rules_version}</code> · LOW &lt; {low} ≤ MEDIUM &lt; {high} ≤ HIGH, plus policy overrides.
          </p>
          {slider('self_confidence', "Agent's self-reported confidence")}
          {slider('tests_passed_ratio', 'Tests / validations passed')}
          <label className="field">
            <div className="row between">
              Lines / cells changed <span className="v">{m.lines_changed}</span>
            </div>
            <input type="range" min={0} max={1500} step={5} value={m.lines_changed} onChange={(e) => setM({ ...m, lines_changed: +e.target.value })} />
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={m.has_external_side_effects}
              onChange={(e) => setM({ ...m, has_external_side_effects: e.target.checked })}
            />
            Has external side effects (sends email, writes to prod, moves money…)
          </label>
          <button className="btn primary" onClick={submit} disabled={busy || !agent}>
            {busy ? 'Classifying…' : 'Submit work to auditor'}
          </button>
          <ErrorBox error={err} />

          {result && (
            <div style={{ marginTop: 16 }}>
              <h3>Classification</h3>
              <div className="row" style={{ marginBottom: 6 }}>
                <CategoryBadge c={result.category} />
                <span>
                  score <b className="mono">{result.score}</b>
                </span>
                <span className="badge neutral">{STATUS_LABEL[result.status] ?? result.status}</span>
              </div>
              <div className="scale">
                <div className="z-low" style={{ width: `${low * 100}%` }} />
                <div className="z-med" style={{ width: `${(high - low) * 100}%` }} />
                <div className="z-high" style={{ flex: 1 }} />
                <div className="marker" style={{ left: `calc(${+result.score * 100}% - 1px)` }} />
              </div>
              <ul style={{ margin: '8px 0', paddingLeft: 18, fontSize: 13 }}>
                {result.reasons.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
              {result.breakdown && (
                <table>
                  <thead>
                    <tr>
                      <th>signal</th>
                      <th>value</th>
                      <th>weight</th>
                      <th>contribution</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(result.breakdown).map(([k, v]) => (
                      <tr key={k}>
                        <td>{k}</td>
                        <td className="mono">{v.signal.toFixed(3)}</td>
                        <td className="mono">{v.weight.toFixed(2)}</td>
                        <td className="mono">{(v.signal * v.weight).toFixed(4)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              <dl className="kv" style={{ marginTop: 10 }}>
                <dt>work_hash</dt>
                <dd>
                  <Hash value={result.work_hash} len={20} />
                </dd>
                <dt>rules_hash</dt>
                <dd>
                  <Hash value={result.rules_hash} len={20} />
                </dd>
              </dl>
              {result.category === 'MEDIUM' && (
                <div className="alert warn">
                  Needs a human. <button className="btn small" onClick={onGoReview}>Go to review →</button>
                </div>
              )}
            </div>
          )}
        </section>
      </div>

      <section className="card">
        <h2>All agent work</h2>
        <p className="hint">Every classification is stored off-chain with the rule-set hash that produced it. Only signed MEDIUM work becomes a transaction.</p>
        {!items?.length ? (
          <div className="empty">No work submitted yet — try a preset above.</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>agent</th>
                  <th>artifact</th>
                  <th>score</th>
                  <th>category</th>
                  <th>status</th>
                  <th>work hash</th>
                  <th>signed by</th>
                </tr>
              </thead>
              <tbody>
                {items.map((w) => (
                  <tr key={w.id}>
                    <td>{w.id}</td>
                    <td>{w.agent_name}</td>
                    <td>
                      {w.filename} <span className="badge neutral">{w.artifact_type}</span>
                    </td>
                    <td className="mono">{w.score}</td>
                    <td>
                      <CategoryBadge c={w.category} />
                    </td>
                    <td>
                      {STATUS_LABEL[w.status] ?? w.status}
                      {w.block_height !== null && <> · block #{w.block_height}</>}
                    </td>
                    <td>
                      <Hash value={w.work_hash} len={10} />
                    </td>
                    <td>{w.auditor_name ? `${w.auditor_name} (${w.decision})` : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
