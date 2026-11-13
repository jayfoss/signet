import type { Directory, SignedCard, SignedView } from './cards';
import { verifyCard, verifyView } from './cards';
import type { KeyPair } from './crypto';
import { sha256, signJson, verifyJson } from './crypto';
import { canonicalJson } from './encoding';
import type { LogEntry } from './identity';
import { LogError, replayLog } from './identity';
import type { Operators } from './operators';
import { verifiedDomainSigner } from './operators';
import type { TrustedLog } from './transparency';
import type { VrfProof } from './vrf';
import { verifyIndex } from './vrf';

/** Served at https://<domain>/.well-known/signet.json and announced by `_signet.<domain>` TXT. */
export interface DomainPolicy {
  v: 'signet0';
  domain: string;
  server: string;
  /** Every home of a domain that runs several, in order of preference; `server` is the first (Section 6.8). */
  homes?: string[];
  /** The domain owner's signed list of independent homes (Section 6.9). When present, `homes` and `server` come from it. */
  operators?: Operators;
  mode: 'enforce' | 'testing';
  maxAge: number;
  domainKey: string;
  /** VRF public key: proves each address's index in the transparency log (RFC 9381). */
  vrfKey: string;
  /** The transparency log this domain writes every directory change to. Clients only accept logs they trust. */
  log: TrustedLog;
  /** Oblivious HTTP gateway (RFC 9458) for sealed and anonymous deliveries: its URL and key configuration. */
  ohttp?: { gateway: string; keys: string };
  /** The Privacy Pass issuer whose tokens this domain accepts on anonymous requests. */
  privacyPass?: { issuer: string };
  /**
   * The domain's intake, for addresses whose owners chose to be unlisted. Requests to them are sealed to
   * this key; the home server opens them and passes them on, or drops them if there is no such address.
   */
  intake?: { keyId: string; agreeKey: string };
}

/** The domain's statement that an address belongs to an identity key. The domain can rebind; it can't add clients. */
export interface DomainBinding {
  principal: string;
  identityKey: string;
  ts: string;
  sig: string;
}

/** What a lookup returns: the public card always, the contact view to admitted contacts, the private log only to the owner. */
export interface EnrolledEntry {
  status: 'enrolled';
  principal: string;
  binding: DomainBinding;
  card: SignedCard;
  view?: SignedView;
  log?: LogEntry[];
  vrf: VrfProof;
}

export interface NotEnrolledEntry {
  status: 'not-enrolled';
  principal: string;
  ts: string;
  /** The home key that signed this answer in place of the domain key (Section 6.9.3). */
  home?: string;
  sig: string;
  vrf: VrfProof;
}

/**
 * The answer a domain with an intake gives strangers for an unlisted address and for one that doesn't
 * exist alike. It carries no VRF proof, so the transparency log can't tell the two apart either.
 */
export interface UnlistedEntry {
  status: 'unlisted';
  principal: string;
  ts: string;
  home?: string;
  sig: string;
}

export type DirectoryEntry = EnrolledEntry | NotEnrolledEntry | UnlistedEntry;

/** The address may or may not exist: reach it with a request through the domain's intake. */
export class UnlistedAddressError extends Error {
  constructor(readonly principal: string) {
    super(`${principal} is unlisted (or doesn't exist): requests go through its domain's intake`);
  }
}

/**
 * The domain says an address is unlisted, but this client already knows it is on Signet: it pinned its
 * key, or got authenticated Signet mail from it. The domain may be hiding it to read a first request
 * through its intake, so the client won't send one that way. A contact card from the person fixes it.
 */
export class HiddenAddressError extends Error {
  constructor(
    readonly principal: string,
    readonly reason: string,
  ) {
    super(`${principal}'s domain says it is unlisted, but ${reason}. Not sending through the domain's intake, which could read it; ask them for a contact card`);
  }
}

/**
 * A self-proving contact card: the person's own directory entry (domain binding, signed card, VRF
 * proof), handed out as a link or QR code. Checked against the transparency log like any lookup, it lets
 * the holder reach the person's own keys whatever the domain tells strangers.
 */
export type ContactCard = Pick<EnrolledEntry, 'status' | 'principal' | 'binding' | 'card' | 'vrf'>;

const CARD_PREFIX = 'signet:card?e=';

export const contactCardLink = (card: ContactCard): string => `${CARD_PREFIX}${Buffer.from(canonicalJson(card)).toString('base64url')}`;

export function parseContactCard(link: string): ContactCard {
  if (!link.startsWith(CARD_PREFIX)) throw new LogError('not a Signet contact card');
  try {
    const card = JSON.parse(Buffer.from(link.slice(CARD_PREFIX.length), 'base64url').toString('utf8')) as ContactCard;
    if (card.status !== 'enrolled') throw new Error();
    return card;
  } catch {
    throw new LogError('contact card is damaged');
  }
}

/** Sign with the domain key, or with a home key (`asHome`), which names itself in the answer. */
export function signUnlisted(signer: KeyPair, principal: string, now = new Date(), asHome = false): UnlistedEntry {
  const unsigned = { status: 'unlisted' as const, principal, ts: now.toISOString(), ...(asHome ? { home: signer.publicKey } : {}) };
  return { ...unsigned, sig: signJson(signer, unsigned) };
}

export function verifyUnlisted(entry: UnlistedEntry, policy: DomainPolicy): void {
  const { sig, ...unsigned } = entry;
  const signer = verifiedDomainSigner(policy, entry.home);
  if (splitAddress(entry.principal).domain !== policy.domain || !policy.intake || signer === undefined || !verifyJson(signer, unsigned, sig)) {
    throw new LogError(`unsigned unlisted answer for ${entry.principal}`);
  }
}

/** Thrown when an address we have talked to before now presents a different identity key, or none. */
export class IdentityChangedError extends Error {
  constructor(
    readonly principal: string,
    readonly pinned: string,
    readonly presented: string | null,
  ) {
    super(`identity for ${principal} changed; refusing until the change is confirmed`);
  }
}

export function splitAddress(address: string): { local: string; domain: string } {
  const at = address.lastIndexOf('@');
  if (at < 1 || at === address.length - 1) throw new Error(`not an address: ${address}`);
  return { local: address.slice(0, at).toLowerCase(), domain: address.slice(at + 1).toLowerCase() };
}

/** How home servers name a requester to each other, and how owners name contacts they release their view to. */
export const requesterHash = (address: string): string => sha256(`${splitAddress(address).domain}|${normalizeAddress(address)}`);

export const normalizeAddress = (address: string): string => {
  const { local, domain } = splitAddress(address);
  return `${local}@${domain}`;
};

export function bindIdentity(domainKey: KeyPair, principal: string, identityKey: string, now = new Date()): DomainBinding {
  const unsigned = { principal, identityKey, ts: now.toISOString() };
  return { ...unsigned, sig: signJson(domainKey, { type: 'binding', ...unsigned }) };
}

export function signNotEnrolled(signer: KeyPair, principal: string, vrf: VrfProof, now = new Date(), asHome = false): NotEnrolledEntry {
  const unsigned = { status: 'not-enrolled' as const, principal, ts: now.toISOString(), ...(asHome ? { home: signer.publicKey } : {}) };
  return { ...unsigned, sig: signJson(signer, unsigned), vrf };
}

/** Check a not-enrolled answer's signature and VRF proof; returns the address's log index. */
export function verifyNotEnrolled(entry: NotEnrolledEntry, policy: DomainPolicy): string {
  const { sig, vrf, ...unsigned } = entry;
  const signer = verifiedDomainSigner(policy, entry.home);
  if (splitAddress(entry.principal).domain !== policy.domain || signer === undefined || !verifyJson(signer, unsigned, sig)) {
    throw new LogError(`unsigned not-enrolled answer for ${entry.principal}`);
  }
  return verifyIndex(policy.vrfKey, entry.principal, vrf);
}

/**
 * Check the domain binding, the card and view signatures, the VRF proof and (for the owner) the
 * private log. Transparency, freshness and pinning are the caller's job.
 */
export function verifyDirectoryEntry(entry: EnrolledEntry, policy: DomainPolicy): Omit<Directory, 'viewHash'> {
  if (splitAddress(entry.principal).domain !== policy.domain) throw new LogError('entry is for another domain');
  const { sig, ...binding } = entry.binding;
  if (binding.principal !== entry.principal || !verifyJson(policy.domainKey, { type: 'binding', ...binding }, sig)) {
    throw new LogError('binding is not signed by the domain key');
  }
  const card = verifyCard(entry.card, entry.principal, binding.identityKey);
  const view = entry.view ? verifyView(entry.view, entry.principal, binding.identityKey) : undefined;
  const index = verifyIndex(policy.vrfKey, entry.principal, entry.vrf);
  const log = entry.log ? replayLog(entry.log) : undefined;
  if (log && (log.identityKey !== binding.identityKey || log.principal !== entry.principal || log.head !== card.logHead)) {
    throw new LogError('log does not match the domain binding and card');
  }
  return { principal: entry.principal, identityKey: binding.identityKey, card, view, index, log };
}
