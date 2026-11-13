import { randomBytes } from 'node:crypto';
import type { KeyPair } from './crypto';
import { sha256, signJson, verifyJson } from './crypto';
import type { DomainPolicy } from './directory';
import { verifiedDomainSigner } from './operators';

/** Requests older or newer than this are refused; within it, a `ReplayCache` refuses repeats. */
export const AUTH_SKEW_MS = 5 * 60_000;

const payload = (method: string, path: string, ts: string, nonce: string, body: string | Uint8Array) => ({
  method: method.toUpperCase(),
  path,
  ts,
  nonce,
  body: sha256(body),
});

const newNonce = () => randomBytes(16).toString('base64url');

/**
 * Signed requests the server has already accepted, kept for as long as their timestamp could pass the
 * freshness check. A captured request replayed inside that window is refused. Check only requests whose
 * signature verified, so nobody can fill it with junk.
 */
export class ReplayCache {
  private readonly seen = new Map<string, number>();

  constructor(
    private readonly windowMs = 2 * AUTH_SKEW_MS,
    saved: Iterable<[string, number]> = [],
  ) {
    for (const [key, expires] of saved) this.seen.set(key, expires);
  }

  /** What to save so the cache survives a restart: keys still inside the window. */
  entries(now = Date.now()): [string, number][] {
    return [...this.seen].filter(([, expires]) => expires > now);
  }

  /** True the first time `key` is seen within the window; false for a repeat. */
  firstUse(key: string, now = Date.now()): boolean {
    if (this.seen.size > 10_000) for (const [seenKey, expires] of this.seen) if (expires <= now) this.seen.delete(seenKey);
    const expires = this.seen.get(key);
    if (expires !== undefined && expires > now) return false;
    this.seen.set(key, now + this.windowMs);
    return true;
  }
}

/** Headers a client sends to its own home server. The server checks the key is active in the principal's log. */
export function clientAuthHeaders(
  principal: string,
  clientId: string,
  key: KeyPair,
  method: string,
  path: string,
  body: string | Uint8Array,
  now = new Date(),
): Record<string, string> {
  const ts = now.toISOString();
  const nonce = newNonce();
  return {
    'signet-principal': principal,
    'signet-client': clientId,
    'signet-ts': ts,
    'signet-nonce': nonce,
    'signet-sig': signJson(key, { kind: 'client', ...payload(method, path, ts, nonce, body) }),
  };
}

/** Headers one server sends another on delivery, signed with the sending domain's key. */
export function domainAuthHeaders(
  domain: string,
  key: KeyPair,
  method: string,
  path: string,
  body: string | Uint8Array,
  now = new Date(),
): Record<string, string> {
  const ts = now.toISOString();
  const nonce = newNonce();
  return {
    'signet-domain': domain,
    'signet-ts': ts,
    'signet-nonce': nonce,
    'signet-sig': signJson(key, { kind: 'domain', domain, ...payload(method, path, ts, nonce, body) }),
  };
}

const fresh = (ts: string, now: Date) => Math.abs(now.getTime() - Date.parse(ts)) <= AUTH_SKEW_MS;

export function verifyClientAuth(
  sigKey: string,
  sig: string,
  ts: string,
  nonce: string,
  method: string,
  path: string,
  body: string | Uint8Array,
  now = new Date(),
): boolean {
  return fresh(ts, now) && nonce.length > 0 && verifyJson(sigKey, { kind: 'client', ...payload(method, path, ts, nonce, body) }, sig);
}

export function verifyDomainAuth(
  domain: string,
  domainKey: string,
  sig: string,
  ts: string,
  nonce: string,
  method: string,
  path: string,
  body: string | Uint8Array,
  now = new Date(),
): boolean {
  return fresh(ts, now) && nonce.length > 0 && verifyJson(domainKey, { kind: 'domain', domain, ...payload(method, path, ts, nonce, body) }, sig);
}

/**
 * Headers a home sends another server, signed with the home key rather than the domain key, which the
 * home doesn't hold (Section 6.9.3). The key names itself in a header and in the signed object.
 */
export function homeAuthHeaders(
  domain: string,
  homeKey: KeyPair,
  method: string,
  path: string,
  body: string | Uint8Array,
  now = new Date(),
): Record<string, string> {
  const ts = now.toISOString();
  const nonce = newNonce();
  return {
    'signet-domain': domain,
    'signet-home': homeKey.publicKey,
    'signet-ts': ts,
    'signet-nonce': nonce,
    'signet-sig': signJson(homeKey, { kind: 'domain', domain, home: homeKey.publicKey, ...payload(method, path, ts, nonce, body) }),
  };
}

/**
 * Check a call from another domain's server: signed by the domain key, or by the key of a home in the
 * domain's verified operators statement when `signet-home` says so.
 */
export function verifyDomainCall(
  policy: Pick<DomainPolicy, 'domain' | 'domainKey' | 'operators'>,
  headers: { sig: string; ts: string; nonce: string; home?: string },
  method: string,
  path: string,
  body: string | Uint8Array,
  now = new Date(),
): boolean {
  const signer = verifiedDomainSigner(policy, headers.home);
  if (signer === undefined || !fresh(headers.ts, now) || headers.nonce.length === 0) return false;
  const signed = headers.home === undefined ? { kind: 'domain', domain: policy.domain } : { kind: 'domain', domain: policy.domain, home: headers.home };
  return verifyJson(signer, { ...signed, ...payload(method, path, headers.ts, headers.nonce, body) }, headers.sig);
}
