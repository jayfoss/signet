/**
 * Enrolling a new client without its private keys ever leaving it.
 *
 * The new client generates its own keys and makes an enrollment request: its public keys, the kind,
 * label, scopes and limits it asks for, and a nonce, signed with its new signing key to prove it holds
 * the private half. The holder of the identity key shows the request and a short fingerprint, decides
 * the scopes and limits itself, and appends the certificate to the log.
 *
 * The request reaches the identity holder one of two ways:
 *
 * - A QR code or deep link (`enrollmentLink`), carried over a channel that is itself authentic: the
 *   new device's screen, or a link from the service the owner is connecting.
 * - A pairing code through the home server (`pairAsOwner` / `pairAsNewClient`). Both sides run SPAKE2
 *   over the code's secret part and seal the request and the reply under the key it gives. The server
 *   only relays and never learns the secret, so it can't swap keys, and a guesser gets one try per code.
 */
import { hkdfSync, randomBytes } from 'node:crypto';
import type { Ciphertext, KeyPair } from './crypto';
import { decrypt, encrypt, generateAgreementKey, generateSigningKey, randomId, sha256Bytes, signJson, verifyJson } from './crypto';
import { canonicalJson, fromB64u, utf8 } from './encoding';
import type { ClientCert, ClientKeys, ClientKind } from './identity';
import { native } from './native';

export interface EnrollmentRequestBody {
  v: 0;
  type: 'enroll';
  principal: string;
  /** Chosen by the new client, so it knows its id before it is approved. */
  clientId: string;
  kind: ClientKind;
  label: string;
  sigKey: string;
  agreeKey: string;
  /** What the client asks for. The identity holder decides what it gets. */
  scopes: string[];
  limits?: Record<string, number>;
  nonce: string;
  ts: string;
}

export interface EnrollmentRequest {
  body: EnrollmentRequestBody;
  sig: string;
}

/** A new client's request and the private keys behind it, which stay on that client. */
export interface PendingClient {
  request: EnrollmentRequest;
  signing: KeyPair;
  agreement: KeyPair;
}

export class EnrollmentError extends Error {}

const REQUEST_TTL_MS = 15 * 60_000;
const LINK_PREFIX = 'signet:enroll?r=';
// Crockford base32: no I, L, O or U, so codes survive being read aloud or retyped.
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function requestEnrollment(
  principal: string,
  options: { kind: ClientKind; label: string; scopes: string[]; limits?: Record<string, number> },
  now = new Date(),
): PendingClient {
  const signing = generateSigningKey();
  const agreement = generateAgreementKey();
  const body: EnrollmentRequestBody = {
    v: 0,
    type: 'enroll',
    principal: principal.toLowerCase(),
    clientId: randomId('c'),
    kind: options.kind,
    label: options.label,
    sigKey: signing.publicKey,
    agreeKey: agreement.publicKey,
    scopes: options.scopes,
    limits: options.limits,
    nonce: randomBytes(16).toString('base64url'),
    ts: now.toISOString(),
  };
  return { request: { body, sig: signJson(signing, body) }, signing, agreement };
}

/** Signed by the key it names, for this principal, and recent. */
export function verifyEnrollmentRequest(request: EnrollmentRequest, principal: string, now = new Date()): EnrollmentRequestBody {
  const { body } = request;
  if (body?.v !== 0 || body.type !== 'enroll') throw new EnrollmentError('not an enrollment request');
  if (body.principal !== principal.toLowerCase()) throw new EnrollmentError(`this request is for ${body.principal}, not ${principal}`);
  if (Math.abs(now.getTime() - Date.parse(body.ts)) > REQUEST_TTL_MS) throw new EnrollmentError('enrollment request has expired');
  if (!verifyJson(body.sigKey, body, request.sig)) throw new EnrollmentError('enrollment request is not signed by the key it names');
  return body;
}

/** What both screens show, so a person can see the request arrived unchanged: 16 characters in 4 groups. */
export function enrollmentFingerprint(request: EnrollmentRequest): string {
  const digest = sha256Bytes(utf8(canonicalJson(request.body)));
  const chars = Array.from({ length: 16 }, (_, i) => ALPHABET.at(digest[i] % 32));
  return [0, 4, 8, 12].map((at) => chars.slice(at, at + 4).join('')).join('-');
}

export const enrollmentLink = (request: EnrollmentRequest): string => `${LINK_PREFIX}${utf8(canonicalJson(request)).toString('base64url')}`;

export function parseEnrollmentLink(link: string): EnrollmentRequest {
  if (!link.startsWith(LINK_PREFIX)) throw new EnrollmentError('not a Signet enrollment link');
  try {
    return JSON.parse(fromB64u(link.slice(LINK_PREFIX.length)).toString('utf8')) as EnrollmentRequest;
  } catch {
    throw new EnrollmentError('enrollment link is damaged');
  }
}

/** The approved certificate, checked against the request it answers: same id, same keys. */
export function completeEnrollment(pending: PendingClient, cert: ClientCert): ClientKeys {
  const { body } = pending.request;
  if (cert.clientId !== body.clientId || cert.sigKey !== body.sigKey || cert.agreeKey !== body.agreeKey || cert.principal !== body.principal) {
    throw new EnrollmentError('the certificate does not match this enrollment request');
  }
  return { cert, signing: pending.signing, agreement: pending.agreement };
}

// Pairing codes: "4821-H7KQ-9XRM". The four digits name a relay slot on the home server; the eight
// letters are the SPAKE2 password, which the server never sees.

export function newPairingSecret(): string {
  return Array.from(randomBytes(8), (byte) => ALPHABET.at(byte % 32)).join('');
}

export const pairingCode = (slot: string, secret: string): string => `${slot}-${secret.slice(0, 4)}-${secret.slice(4)}`;

export function parsePairingCode(code: string): { slot: string; secret: string } {
  const match = /^(\d{4})-([0-9A-HJKMNP-TV-Z]{4})-([0-9A-HJKMNP-TV-Z]{4})$/.exec(code.trim().toUpperCase());
  if (!match) throw new EnrollmentError('a pairing code looks like 4821-H7KQ-9XRM');
  return { slot: match[1], secret: match[2] + match[3] };
}

/** One side's view of a pairing slot: send to the other side, and wait for its next message. */
export interface PairingChannel {
  send(body: string): Promise<void>;
  receive(): Promise<string>;
}

type Sealed = Ciphertext;
type Reply = { cert: ClientCert } | { refused: string };

const pakeIds = (principal: string, slot: string): [string, string] => [
  `signet pair v0 ${principal.toLowerCase()} ${slot} owner`,
  `signet pair v0 ${principal.toLowerCase()} ${slot} new client`,
];
const sessionKey = (shared: string, purpose: 'request' | 'reply'): Buffer =>
  Buffer.from(hkdfSync('sha256', fromB64u(shared), Buffer.alloc(0), `signet pair v0 ${purpose}`, 32));
const sealFor = (key: Buffer, value: unknown): string => JSON.stringify(encrypt(key, utf8(canonicalJson(value)), utf8('signet pair v0')));
const openWith = <T>(key: Buffer, body: string): T => JSON.parse(decrypt(key, JSON.parse(body) as Sealed, utf8('signet pair v0')).toString('utf8')) as T;

/**
 * The identity holder's side. `decide` is shown the request and its fingerprint; it returns the
 * certificate it appended and published, or null to refuse. A wrong code fails here, before `decide`.
 */
export async function pairAsOwner(
  channel: PairingChannel,
  principal: string,
  code: string,
  decide: (request: EnrollmentRequest, fingerprint: string) => Promise<ClientCert | null>,
): Promise<ClientCert | null> {
  const { slot, secret } = parsePairingCode(code);
  const pake = new (native().Pake)('a', secret, ...pakeIds(principal, slot));
  await channel.send(pake.message);
  const shared = pake.finish(await channel.receive());
  let request: EnrollmentRequest;
  try {
    request = openWith<EnrollmentRequest>(sessionKey(shared, 'request'), await channel.receive());
  } catch {
    // Tell the other side straight away rather than leave it waiting; it can't read this either.
    await channel.send('abort').catch(() => undefined);
    throw new EnrollmentError('pairing failed: the other side used a different code');
  }
  verifyEnrollmentRequest(request, principal);
  const cert = await decide(request, enrollmentFingerprint(request));
  const reply: Reply = cert ? { cert } : { refused: 'the account owner declined' };
  await channel.send(sealFor(sessionKey(shared, 'reply'), reply));
  return cert;
}

/** The new client's side: returns its keys and certificate once the identity holder approves. */
export async function pairAsNewClient(
  channel: PairingChannel,
  principal: string,
  code: string,
  options: { kind: ClientKind; label: string; scopes: string[]; limits?: Record<string, number> },
  onRequest?: (fingerprint: string) => void,
): Promise<ClientKeys> {
  const { slot, secret } = parsePairingCode(code);
  const pake = new (native().Pake)('b', secret, ...pakeIds(principal, slot));
  await channel.send(pake.message);
  const shared = pake.finish(await channel.receive());
  const pending = requestEnrollment(principal, options);
  await channel.send(sealFor(sessionKey(shared, 'request'), pending.request));
  onRequest?.(enrollmentFingerprint(pending.request));
  let reply: Reply;
  try {
    reply = openWith<Reply>(sessionKey(shared, 'reply'), await channel.receive());
  } catch {
    throw new EnrollmentError('pairing failed: the other side used a different code');
  }
  if ('refused' in reply) throw new EnrollmentError(reply.refused);
  return completeEnrollment(pending, reply.cert);
}

/**
 * A pairing slot on the home server, which only relays: `/v0/pairing/{slot}/{side}`. The owner's side
 * signs its requests as one of its devices; the new client's side has no account yet and signs nothing.
 */
export class HttpPairingChannel implements PairingChannel {
  private received = 0;

  constructor(
    private readonly server: string,
    private readonly slot: string,
    private readonly side: 'a' | 'b',
    private readonly auth: (method: string, path: string, body: string) => Record<string, string> = () => ({}),
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly timeoutMs = 10 * 60_000,
    private readonly pollMs = 250,
  ) {}

  async send(body: string): Promise<void> {
    const path = `/v0/pairing/${this.slot}/${this.side}`;
    const payload = JSON.stringify({ body });
    const response = await this.fetchImpl(`${this.server}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...this.auth('POST', path, payload) },
      body: payload,
    });
    if (!response.ok) throw new EnrollmentError(`pairing relay refused: ${response.status} ${await response.text()}`);
  }

  async receive(): Promise<string> {
    const other = this.side === 'a' ? 'b' : 'a';
    const deadline = Date.now() + this.timeoutMs;
    while (Date.now() < deadline) {
      const response = await this.fetchImpl(`${this.server}/v0/pairing/${this.slot}/${other}?after=${this.received}`);
      if (!response.ok) throw new EnrollmentError(`pairing relay refused: ${response.status} ${await response.text()}`);
      const { messages } = (await response.json()) as { messages: string[] };
      if (messages.length > 0) {
        this.received += 1;
        return messages[0];
      }
      await new Promise((resolve) => setTimeout(resolve, this.pollMs));
    }
    throw new EnrollmentError('pairing timed out');
  }
}
