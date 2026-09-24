// Browser-side cryptography for human reviewers.
// Private keys are generated with extractable=false and kept in IndexedDB: they can sign, but no
// script (and not the server) can ever read the key material. This is what makes the signature
// attributable to the person holding this browser profile.

const subtle = globalThis.crypto.subtle;

export const toHex = (buf: ArrayBuffer | Uint8Array) =>
  [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

export async function sha256Hex(data: string | Uint8Array): Promise<string> {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return toHex(await subtle.digest('SHA-256', bytes as BufferSource));
}

export function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

export interface Identity {
  auditorId: number;
  name: string;
  fingerprint: string;
  publicKeySpki: string;
  privateKey: CryptoKey;
  createdAt: number;
}

export async function generateKeyPair(): Promise<{ privateKey: CryptoKey; spkiB64: string }> {
  const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const spki = new Uint8Array(await subtle.exportKey('spki', kp.publicKey));
  return { privateKey: kp.privateKey, spkiB64: bytesToB64(spki) };
}

/** ECDSA P-256 / SHA-256 over the UTF-8 canonical string. Returns raw r||s as hex (128 chars). */
export async function signCanonical(key: CryptoKey, canonical: string): Promise<string> {
  const sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, new TextEncoder().encode(canonical));
  return toHex(sig);
}

/** Must match chain::canonical() in backend/src/chain.cpp field-for-field. */
export function buildCanonical(f: {
  workItemId: number;
  workHash: string;
  artifactType: string;
  score: string;
  rulesHash: string;
  decision: string;
  commentHash: string;
  auditorFingerprint: string;
  timestampMs: number;
}): string {
  return [
    'v1',
    f.workItemId,
    f.workHash,
    f.artifactType,
    f.score,
    f.rulesHash,
    f.decision,
    f.commentHash,
    f.auditorFingerprint,
    f.timestampMs,
  ].join('|');
}

// ---------- IndexedDB key store ----------
const DB_NAME = 'ai-ledger-keys';
const STORE = 'identities';

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE, { keyPath: 'fingerprint' });
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function tx<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const req = fn(db.transaction(STORE, mode).objectStore(STORE));
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export const keyStore = {
  list: () => tx<Identity[]>('readonly', (s) => s.getAll() as IDBRequest<Identity[]>),
  save: (id: Identity) => tx('readwrite', (s) => s.put(id)),
  remove: (fingerprint: string) => tx('readwrite', (s) => s.delete(fingerprint)),
};
