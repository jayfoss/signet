import type { KeyPair } from './crypto';
import { open, randomId, seal, sha256, signJson, verifyJson } from './crypto';
import type { ClientKeys } from './identity';
import type { SealedCopy } from './request';

/** Header that Signet servers add to plain email, so a Signet-capable recipient can upgrade the conversation. */
export const SIGNET_HEADER = 'Signet';

/**
 * `Signet-Audience: humans` asks that no agent read this email (password resets, security codes). A
 * Signet server receiving it seals it only to the recipient's devices; agents never get a copy.
 */
export const AUDIENCE_HEADER = 'Signet-Audience';

/** Whether a raw RFC 5322 message's header block marks it humans-only. */
export function isHumansOnly(raw: Uint8Array | string): boolean {
  const text = typeof raw === 'string' ? raw : Buffer.from(raw).toString('latin1');
  const end = text.search(/\r?\n\r?\n/);
  const headers = (end === -1 ? text : text.slice(0, end)).replace(/\r?\n[ \t]+/g, ' ');
  return /^signet-audience:\s*humans\s*$/im.test(headers);
}

export interface SignetHeader {
  version: string;
  server: string;
  fingerprint: string;
  /** A Signet address other than the From address, e.g. for someone sending from consumer Gmail. */
  address?: string;
  /** Attestation by the sender's home server, signed with its domain key; see `attestationPayload`. */
  ts?: string;
  nonce?: string;
  sig?: string;
}

/** The fields of a plain email the sender's home server vouches for. */
export interface AttestedFields {
  from: string;
  to: string[];
  subject: string;
}

/**
 * What the domain key signs: the visible From, To and Subject, plus a timestamp, a nonce, the identity
 * key fingerprint and any alternate address. Without this, anyone could paste someone's public
 * fingerprint into a forged email; with it, only that address's own domain can produce a valid header.
 */
export function attestationPayload(fields: AttestedFields, header: { fingerprint: string; address?: string; ts: string; nonce: string }) {
  return {
    type: 'signet-legacy-attestation',
    from: fields.from.toLowerCase(),
    to: [...fields.to].map((address) => address.toLowerCase()).sort(),
    subject: fields.subject,
    fp: header.fingerprint,
    addr: header.address ?? null,
    ts: header.ts,
    nonce: header.nonce,
  };
}

/** Build the header on the sender's home server: hint fields plus a domain-key attestation. */
export function attestedSignetHeader(
  domainKey: KeyPair,
  server: string,
  identityKey: string,
  fields: AttestedFields,
  address?: string,
  now = new Date(),
): string {
  const fingerprint = sha256(identityKey);
  const ts = now.toISOString();
  const nonce = randomId('n');
  const sig = signJson(domainKey, attestationPayload(fields, { fingerprint, address, ts, nonce }));
  return `v=signet0; server=${server}; fp=${fingerprint}${address ? `; addr=${address}` : ''}; ts=${ts}; nonce=${nonce}; sig=${sig}`;
}

/**
 * True when the header's attestation is signed by `domainKey` for exactly this From, To and Subject and
 * is recent. The fingerprint must still be checked against the sender's verified directory entry.
 */
export function verifyAttestation(header: SignetHeader, fields: AttestedFields, domainKey: string, now = new Date(), maxAgeMs = 7 * 86_400_000): boolean {
  if (!header.ts || !header.nonce || !header.sig) return false;
  const age = now.getTime() - Date.parse(header.ts);
  if (!(age >= -300_000 && age <= maxAgeMs)) return false;
  const payload = attestationPayload(fields, { fingerprint: header.fingerprint, address: header.address, ts: header.ts, nonce: header.nonce });
  return verifyJson(domainKey, payload, header.sig);
}

/**
 * The header is only a hint unless its attestation verifies: Google and other providers don't include
 * it in their DKIM signature, so any hop can add or strip it. Recipients resolve the address through DNS
 * and the transparency log, compare the fingerprint, and never trust `server`.
 */
export const formatSignetHeader = (server: string, identityKey: string, address?: string): string =>
  `v=signet0; server=${server}; fp=${sha256(identityKey)}${address ? `; addr=${address}` : ''}`;

export function parseSignetHeader(value: string | undefined): SignetHeader | null {
  if (!value) return null;
  const fields = new Map(
    value
      .replace(/\s+/g, '')
      .split(';')
      .map((part) => part.trim().split('='))
      .filter((pair) => pair.length >= 2)
      .map(([key, ...rest]) => [key.trim(), rest.join('=').trim()]),
  );
  const version = fields.get('v');
  const server = fields.get('server');
  const fingerprint = fields.get('fp');
  if (version !== 'signet0' || !server || !fingerprint) return null;
  const optional = (['addr', 'ts', 'nonce', 'sig'] as const).flatMap((key) => {
    const value = fields.get(key);
    return value ? [[key === 'addr' ? 'address' : key, value] as const] : [];
  });
  return { version, server, fingerprint, ...Object.fromEntries(optional) };
}

/** SPF, DKIM and DMARC results the receiving server saw before it encrypted the message. */
export interface LegacyAuth {
  spf: string;
  dkim: string;
  dmarc: string;
}

/**
 * Plain email that arrived over SMTP, encrypted to the recipient's reading clients on arrival.
 * It was readable in transit, so clients show it at a lower trust tier than Signet mail.
 */
export interface SealedLegacyMail {
  envelopeFrom: string;
  auth: LegacyAuth;
  copies: SealedCopy[];
}

const legacyInfo = (to: string) => `signet0 legacy ${to}`;

export async function sealLegacyMail(
  to: string,
  raw: Uint8Array,
  readers: { clientId: string; agreeKey: string }[],
  envelopeFrom: string,
  auth: LegacyAuth,
): Promise<SealedLegacyMail> {
  return {
    envelopeFrom,
    auth,
    copies: await Promise.all(
      readers.map(async (reader) => ({ clientId: reader.clientId, sealed: await seal(reader.agreeKey, raw, legacyInfo(to)) })),
    ),
  };
}

export const hasLegacyCopy = (me: ClientKeys, mail: SealedLegacyMail): boolean => mail.copies.some((copy) => copy.clientId === me.cert.clientId);

export async function openLegacyMail(me: ClientKeys, mail: SealedLegacyMail): Promise<Buffer> {
  const copy = mail.copies.find((candidate) => candidate.clientId === me.cert.clientId);
  if (!copy) throw new Error('no copy of this mail for this client');
  return open(me.agreement, copy.sealed, legacyInfo(me.cert.principal));
}
