import { useEffect, useRef, useState } from 'react';
import type { Category } from '../api';

/** Truncated hash; full value in the tooltip, click to copy. Leading zero hex digits highlighted. */
export function Hash({ value, len = 12, zeros = false }: { value: string | null | undefined; len?: number; zeros?: boolean }) {
  const [copied, setCopied] = useState(false);
  if (!value) return <span className="mono">—</span>;
  const short = value.length > len * 2 ? `${value.slice(0, len)}…${value.slice(-6)}` : value;
  const copy = () => {
    navigator.clipboard?.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 900);
    });
  };
  let body: React.ReactNode = short;
  if (zeros) {
    const m = short.match(/^0*/)?.[0] ?? '';
    body = (
      <>
        <b>{m}</b>
        {short.slice(m.length)}
      </>
    );
  }
  return (
    <span className={`hash${zeros ? ' zeros' : ''}`} title={copied ? 'copied' : value} onClick={copy}>
      {copied ? 'copied ✓' : body}
    </span>
  );
}

export const CategoryBadge = ({ c }: { c: Category }) => <span className={`badge ${c}`}>{c}</span>;

export function Badge({ kind, children }: { kind: 'ok' | 'bad' | 'neutral' | 'info'; children: React.ReactNode }) {
  return <span className={`badge ${kind}`}>{children}</span>;
}

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  return <div className="alert err">{error instanceof Error ? error.message : String(error)}</div>;
}

/** Colour-codes each '|'-delimited field of a canonical payload. */
export function Canonical({ value }: { value: string }) {
  const parts = value.split('|');
  return (
    <pre className="pre canonical">
      {parts.map((p, i) => (
        <span key={i}>
          {i > 0 && <span className="sep">|</span>}
          {p}
        </span>
      ))}
    </pre>
  );
}

export const CANONICAL_FIELDS = [
  'version', 'work_item_id', 'work_hash', 'artifact_type', 'score', 'rules_hash',
  'decision', 'comment_hash', 'auditor_fingerprint', 'timestamp_ms',
];

/** Polls fn every `ms` while mounted; returns [data, error, reload]. */
export function usePoll<T>(fn: () => Promise<T>, ms: number, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const load = useRef(async () => {
    try {
      setData(await fnRef.current());
      setError(null);
    } catch (e) {
      setError(e);
    }
  }).current;
  useEffect(() => {
    load();
    if (!ms) return;
    const t = setInterval(load, ms);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ms, ...deps]);
  return [data, error, load] as const;
}

export const fmtNum = (n: number) => n.toLocaleString('en-US');
export function fmtRate(hps: number) {
  if (hps >= 1e6) return `${(hps / 1e6).toFixed(2)} MH/s`;
  if (hps >= 1e3) return `${(hps / 1e3).toFixed(1)} kH/s`;
  return `${hps.toFixed(0)} H/s`;
}
export function fmtBig(n: number) {
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)}G`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(2)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}k`;
  return String(Math.round(n));
}
export const fmtTime = (ms: number) => new Date(ms).toLocaleString();
