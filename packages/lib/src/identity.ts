import type { Grant, SignedCard, SignedView } from './cards';
import { cardFromLog, signCard, signGrant, signView, viewFromLog } from './cards';
import type { KeyPair } from './crypto';
import { generateAgreementKey, generateSigningKey, randomId, sha256, signJson, verifyJson } from './crypto';
import { canonicalJson } from './encoding';
import type { EnrollmentRequest } from './enrollment';
import { verifyEnrollmentRequest } from './enrollment';

export type ClientKind = 'device' | 'agent' | 'tool' | 'org-escrow';

/** A client the identity key has approved: its public keys, what it may do, and for how long. */
export interface ClientCert {
  v: 0;
  principal: string;
  clientId: string;
  kind: ClientKind;
  label: string;
  sigKey: string;
  agreeKey: string;
  scopes: string[];
  limits?: Record<string, number>;
  notBefore: string;
  expires: string;
}

/**
 * The one client strangers can reach: requests can be sealed to it, and it may answer `intents` for
 * anyone. With `exclusive`, requests are sealed to it alone, so first contact always goes through it.
 */
export interface Intake {
  clientId: string;
  intents: string[];
  exclusive: boolean;
}

/**
 * A change of identity key, stated so that anyone holding the old key can follow it. `rotate` and
 * `set-recovery` are signed by the current identity key; `recover` is signed by the recovery key the
 * identity key named earlier, for when the identity key is lost. Cards carry the chain, so contacts who
 * pinned an earlier key accept the new one without trusting the domain.
 */
export type KeyLink =
  | { type: 'rotate'; principal: string; from: string; to: string; ts: string }
  | { type: 'set-recovery'; principal: string; from: string; recoveryKey: string; ts: string }
  | { type: 'recover'; principal: string; from: string; to: string; recoveryKey: string; ts: string };

export interface SignedKeyLink {
  link: KeyLink;
  sig: string;
}

/** Each identity key in order, and how it ended: rotated by the owner, or replaced through recovery. */
export interface KeyHistory {
  keys: { key: string; ended?: 'rotated' | 'recovered' }[];
  recoveryKey: string | null;
}

export type LogBody =
  | { type: 'genesis'; principal: string; identityKey: string }
  | { type: 'key-change'; change: SignedKeyLink }
  | { type: 'add-client'; cert: ClientCert }
  | { type: 'revoke-client'; clientId: string }
  | { type: 'set-intake'; intake: Intake | null }
  | { type: 'set-audience-policy'; agentsReadHumansOnly: string[] }
  | { type: 'revoke-grant'; grantId: string }
  /** Unlisted: strangers get the same answer as for an address that doesn't exist, and reach it through the domain's intake. */
  | { type: 'set-listing'; unlisted: boolean };

export interface LogEntry {
  seq: number;
  prev: string | null;
  ts: string;
  body: LogBody;
  sig: string;
}

/** What a principal's log says right now, after replaying every entry. */
export interface LogState {
  principal: string;
  identityKey: string;
  head: string;
  clients: Map<string, ClientCert>;
  revoked: Set<string>;
  intake: Intake | null;
  revokedGrants: Set<string>;
  /** Agents the owner lets read mail a sender marked humans-only. The recipient decides, not the sender. */
  agentsReadHumansOnly: Set<string>;
  /** Every key change since genesis; published on the card. */
  keyChain: SignedKeyLink[];
  recoveryKey: string | null;
  unlisted: boolean;
}

/** What the owner publishes to its home server: the private log, and the two signed views derived from it. */
export interface Publication {
  entries: LogEntry[];
  card: SignedCard;
  view: SignedView;
}

/** A client's private keys, held only on that client. */
export interface ClientKeys {
  cert: ClientCert;
  signing: KeyPair;
  agreement: KeyPair;
}

export class LogError extends Error {}

export const entryHash = (entry: LogEntry): string => sha256(canonicalJson(entry));

const DAY_MS = 86_400_000;
const DEFAULT_TTL_DAYS: Record<ClientKind, number> = { device: 365, agent: 90, tool: 90, 'org-escrow': 365 };

/** A principal's identity key and the hash-linked log it signs. It signs log entries and nothing else. */
export class Identity {
  readonly entries: LogEntry[] = [];

  private constructor(
    readonly principal: string,
    private key: KeyPair,
  ) {}

  static create(principal: string, now = new Date()): Identity {
    const identity = new Identity(principal, generateSigningKey());
    identity.append({ type: 'genesis', principal, identityKey: identity.identityKey }, now);
    return identity;
  }

  /** Restore an identity saved with `export()`. The log is replayed, so a tampered file is refused. */
  static restore(saved: { principal: string; key: KeyPair; entries: LogEntry[] }): Identity {
    const identity = new Identity(saved.principal, saved.key);
    const log = replayLog(saved.entries);
    if (log.identityKey !== saved.key.publicKey || log.principal !== saved.principal) {
      throw new LogError('saved log does not belong to this identity key');
    }
    identity.entries.push(...saved.entries);
    return identity;
  }

  /** Everything needed to restore this identity, private key included. Keep it on the owner's device. */
  export(): { principal: string; key: KeyPair; entries: LogEntry[] } {
    return { principal: this.principal, key: this.key, entries: [...this.entries] };
  }

  get identityKey(): string {
    return this.key.publicKey;
  }

  append(body: LogBody, now = new Date()): LogEntry {
    return this.appendSignedBy(this.key, body, now);
  }

  private appendSignedBy(key: KeyPair, body: LogBody, now: Date): LogEntry {
    const last = this.entries.at(-1);
    const unsigned = { seq: this.entries.length, prev: last ? entryHash(last) : null, ts: now.toISOString(), body };
    const entry = { ...unsigned, sig: signJson(key, unsigned) };
    this.entries.push(entry);
    return entry;
  }

  /**
   * Replace the identity key, signed by the old one. Clients, grants and threads carry on: contacts follow
   * the chain on the card from the key they pinned. Do this on a schedule, or when a device that held the
   * key is lost but the key itself is still in hand.
   */
  rotateKey(now = new Date()): LogEntry {
    const next = generateSigningKey();
    const link: KeyLink = { type: 'rotate', principal: this.principal, from: this.identityKey, to: next.publicKey, ts: now.toISOString() };
    const entry = this.append({ type: 'key-change', change: { link, sig: signJson(this.key, link) } }, now);
    this.key = next;
    return entry;
  }

  /**
   * Name a recovery key, to keep offline (printed, in a safe, with a trusted colleague). It can replace the
   * identity key once if that is lost; returns the private half, which Signet does not keep.
   */
  setRecovery(now = new Date()): KeyPair {
    const recovery = generateSigningKey();
    const link: KeyLink = { type: 'set-recovery', principal: this.principal, from: this.identityKey, recoveryKey: recovery.publicKey, ts: now.toISOString() };
    this.append({ type: 'key-change', change: { link, sig: signJson(this.key, link) } }, now);
    return recovery;
  }

  /**
   * The identity key is gone: start a new one from the last published log, signed by the recovery key.
   * The recovery key is used up, and pre-recovery grants stop counting, since whoever has the old key may
   * be someone else. Contacts are told the key was recovered rather than rotated.
   */
  static recover(saved: { principal: string; entries: LogEntry[] }, recovery: KeyPair, now = new Date()): Identity {
    const log = replayLog(saved.entries);
    if (log.principal !== saved.principal) throw new LogError('log belongs to another address');
    if (log.recoveryKey !== recovery.publicKey) throw new LogError('that is not the recovery key this log names');
    const identity = new Identity(saved.principal, generateSigningKey());
    identity.entries.push(...saved.entries);
    const link: KeyLink = {
      type: 'recover',
      principal: saved.principal,
      from: log.identityKey,
      to: identity.identityKey,
      recoveryKey: recovery.publicKey,
      ts: now.toISOString(),
    };
    identity.appendSignedBy(recovery, { type: 'key-change', change: { link, sig: signJson(recovery, link) } }, now);
    return identity;
  }

  /**
   * Approve a new client, generating its keys here. For tests and demos only: a real client generates
   * its own keys and sends an enrollment request (`approveClient`).
   */
  enrollClient(options: {
    kind: ClientKind;
    label: string;
    scopes: string[];
    limits?: Record<string, number>;
    ttlDays?: number;
    now?: Date;
  }): ClientKeys {
    const now = options.now ?? new Date();
    const signing = generateSigningKey();
    const agreement = generateAgreementKey();
    const ttlDays = options.ttlDays ?? DEFAULT_TTL_DAYS[options.kind];
    const cert: ClientCert = {
      v: 0,
      principal: this.principal,
      clientId: randomId('c'),
      kind: options.kind,
      label: options.label,
      sigKey: signing.publicKey,
      agreeKey: agreement.publicKey,
      scopes: options.scopes,
      limits: options.limits,
      notBefore: now.toISOString(),
      expires: new Date(now.getTime() + ttlDays * DAY_MS).toISOString(),
    };
    this.append({ type: 'add-client', cert }, now);
    return { cert, signing, agreement };
  }

  /**
   * Certify a client from its own enrollment request: its keys, with the scopes and limits the owner
   * chooses (by default what it asked for). Its private keys never come here.
   */
  approveClient(
    request: EnrollmentRequest,
    options: { scopes?: string[]; limits?: Record<string, number>; label?: string; ttlDays?: number; now?: Date } = {},
  ): ClientCert {
    const now = options.now ?? new Date();
    const body = verifyEnrollmentRequest(request, this.principal, now);
    const cert: ClientCert = {
      v: 0,
      principal: this.principal,
      clientId: body.clientId,
      kind: body.kind,
      label: options.label ?? body.label,
      sigKey: body.sigKey,
      agreeKey: body.agreeKey,
      scopes: options.scopes ?? body.scopes,
      limits: options.limits ?? body.limits,
      notBefore: now.toISOString(),
      expires: new Date(now.getTime() + (options.ttlDays ?? DEFAULT_TTL_DAYS[body.kind]) * DAY_MS).toISOString(),
    };
    this.append({ type: 'add-client', cert }, now);
    return cert;
  }

  revoke(clientId: string, now = new Date()): LogEntry {
    return this.append({ type: 'revoke-client', clientId }, now);
  }

  /** Make this agent the public intake, or clear it with null. */
  setIntake(intake: Intake | null, now = new Date()): LogEntry {
    return this.append({ type: 'set-intake', intake }, now);
  }

  /**
   * Give an agent authority to act with one counterparty. Only that counterparty ever sees the grant:
   * the agent presents it when it relies on it.
   */
  grant(
    options: { agent: string; counterparty: string; intents: string[]; limits?: Record<string, number>; ttlDays?: number },
    now = new Date(),
  ): Grant {
    return signGrant(
      this.key,
      {
        v: 0,
        type: 'grant',
        id: randomId('g'),
        principal: this.principal,
        agent: options.agent,
        counterparty: options.counterparty.toLowerCase(),
        intents: options.intents,
        limits: options.limits,
        expires: new Date(now.getTime() + (options.ttlDays ?? 30) * DAY_MS).toISOString(),
      },
    );
  }

  /**
   * Senders can ask that agents not read a message (password resets, security codes). By default that
   * request is honoured: such mail is sealed only to the owner's devices. Listing agents here opts them in,
   * so a sender can't keep the owner's own assistant out against the owner's wishes.
   */
  setAudiencePolicy(agentsReadHumansOnly: string[], now = new Date()): LogEntry {
    return this.append({ type: 'set-audience-policy', agentsReadHumansOnly }, now);
  }

  /**
   * Opt out of the public directory (or back in). Strangers then can't tell this address from one that
   * doesn't exist: they send first-contact requests through the domain's intake, which can read them.
   * Contacts this account has released its view to still see it as usual. Needs a domain with an intake.
   */
  setUnlisted(unlisted: boolean, now = new Date()): LogEntry {
    return this.append({ type: 'set-listing', unlisted }, now);
  }

  revokeGrant(grantId: string, now = new Date()): LogEntry {
    return this.append({ type: 'revoke-grant', grantId }, now);
  }

  /** The private log plus the public card and contact view, both re-signed for the current head. */
  publication(now = new Date()): Publication {
    const log = replayLog(this.entries);
    return {
      entries: [...this.entries],
      card: signCard(this.key, cardFromLog(log, now)),
      view: signView(this.key, viewFromLog(log, now)),
    };
  }
}

function applyEntry(state: LogState, body: LogBody, seq: number): void {
  switch (body.type) {
    case 'genesis':
      if (seq !== 0) throw new LogError('genesis must be the first entry');
      return;
    case 'key-change':
      applyKeyLink(state, body.change, `entry ${seq}`);
      state.keyChain.push(body.change);
      return;
    case 'add-client':
      if (body.cert.principal !== state.principal) throw new LogError(`entry ${seq} certifies another principal`);
      if (state.clients.has(body.cert.clientId)) throw new LogError(`entry ${seq} reuses client ${body.cert.clientId}`);
      if (body.cert.kind === 'org-escrow' && !hasScope(body.cert, 'read:*')) throw new LogError(`entry ${seq} adds an escrow client that can't read everything`);
      state.clients.set(body.cert.clientId, body.cert);
      return;
    case 'revoke-client':
      if (!state.clients.has(body.clientId)) throw new LogError(`entry ${seq} revokes an unknown client`);
      state.revoked.add(body.clientId);
      if (state.intake?.clientId === body.clientId) state.intake = null;
      return;
    case 'set-intake': {
      if (body.intake) {
        const cert = state.clients.get(body.intake.clientId);
        if (!cert || cert.kind !== 'agent' || state.revoked.has(cert.clientId)) {
          throw new LogError(`entry ${seq} makes a client that is not an active agent the intake`);
        }
      }
      state.intake = body.intake;
      return;
    }
    case 'revoke-grant':
      state.revokedGrants.add(body.grantId);
      return;
    case 'set-listing':
      state.unlisted = body.unlisted;
      return;
    case 'set-audience-policy':
      for (const clientId of body.agentsReadHumansOnly) {
        if (!state.clients.has(clientId)) throw new LogError(`entry ${seq} opts in an unknown client`);
      }
      state.agentsReadHumansOnly = new Set(body.agentsReadHumansOnly);
      return;
  }
}

/** Verify every link and signature in a log and return the state it describes. Throws on any break. */
export function replayLog(entries: LogEntry[]): LogState {
  const genesis = entries[0];
  if (genesis?.body.type !== 'genesis') throw new LogError('log must start with a genesis entry');
  const { principal, identityKey } = genesis.body;
  const state: LogState = {
    principal,
    identityKey,
    head: '',
    clients: new Map(),
    revoked: new Set(),
    intake: null,
    revokedGrants: new Set(),
    agentsReadHumansOnly: new Set(),
    keyChain: [],
    recoveryKey: null,
    unlisted: false,
  };
  let prev: string | null = null;
  entries.forEach((entry, seq) => {
    const { sig, ...unsigned } = entry;
    if (entry.seq !== seq || entry.prev !== prev) throw new LogError(`entry ${seq} is out of order`);
    // A recovery entry is the one entry the identity key can't sign: it has been lost.
    const recovering = entry.body.type === 'key-change' && entry.body.change.link.type === 'recover';
    const signer = recovering ? state.recoveryKey : state.identityKey;
    if (!signer || !verifyJson(signer, unsigned, sig)) {
      throw new LogError(`entry ${seq} is not signed by the ${recovering ? 'recovery' : 'identity'} key`);
    }
    applyEntry(state, entry.body, seq);
    prev = entryHash(entry);
  });
  state.head = prev ?? '';
  return state;
}

function applyKeyLink(state: { principal: string; identityKey: string; recoveryKey: string | null }, change: SignedKeyLink, where: string): void {
  const { link, sig } = change;
  if (link.principal !== state.principal || link.from !== state.identityKey) throw new LogError(`${where} changes a key that isn't current`);
  switch (link.type) {
    case 'rotate':
      if (!verifyJson(state.identityKey, link, sig)) throw new LogError(`${where} rotation is not signed by the old key`);
      state.identityKey = link.to;
      return;
    case 'set-recovery':
      if (!verifyJson(state.identityKey, link, sig)) throw new LogError(`${where} recovery key is not set by the identity key`);
      state.recoveryKey = link.recoveryKey;
      return;
    case 'recover':
      if (!state.recoveryKey || link.recoveryKey !== state.recoveryKey || !verifyJson(state.recoveryKey, link, sig)) {
        throw new LogError(`${where} recovery is not signed by the recovery key`);
      }
      state.identityKey = link.to;
      state.recoveryKey = null;
      return;
  }
}

/** Follow a card's key chain from its first key and check it ends at `identityKey`. */
export function keyHistory(principal: string, chain: SignedKeyLink[], identityKey: string): KeyHistory {
  const state = { principal, identityKey: chain[0]?.link.from ?? identityKey, recoveryKey: null as string | null };
  const keys: KeyHistory['keys'] = [{ key: state.identityKey }];
  chain.forEach((change, i) => {
    applyKeyLink(state, change, `key change ${i}`);
    if (change.link.type !== 'set-recovery') {
      keys[keys.length - 1].ended = change.link.type === 'rotate' ? 'rotated' : 'recovered';
      keys.push({ key: state.identityKey });
    }
  });
  if (state.identityKey !== identityKey) throw new LogError(`key chain for ${principal} does not end at its identity key`);
  return { keys, recoveryKey: state.recoveryKey };
}

/**
 * How `pinned` became `current`, if the chain shows it did: 'rotated' when every step was the owner's
 * own rotation, 'recovered' when any step went through the recovery key. Null when `pinned` isn't in it.
 */
export function keyChangeSince(history: KeyHistory, pinned: string): 'rotated' | 'recovered' | null {
  const at = history.keys.findIndex((entry) => entry.key === pinned);
  if (at < 0) return null;
  return history.keys.slice(at, -1).some((entry) => entry.ended === 'recovered') ? 'recovered' : 'rotated';
}

/** Keys whose grants still count: the current one, and those rotated out since the last recovery. */
export function grantKeys(history: KeyHistory): string[] {
  const lastRecovery = history.keys.map((entry) => entry.ended).lastIndexOf('recovered');
  return history.keys.slice(lastRecovery + 1).map((entry) => entry.key);
}

const RECOVERY_PROOF_MS = 5 * 60_000;
const recoveryChallenge = (principal: string, ts: string) => ({ type: 'signet recovery', principal, ts });

/** What the holder of a recovery key shows its home server to get the log back when every device is gone. */
export function recoveryProof(principal: string, recovery: KeyPair, now = new Date()): { ts: string; sig: string } {
  const ts = now.toISOString();
  return { ts, sig: signJson(recovery, recoveryChallenge(principal, ts)) };
}

export function verifyRecoveryProof(state: LogState, proof: { ts: string; sig: string }, now = new Date()): boolean {
  const age = Math.abs(now.getTime() - Date.parse(proof.ts));
  return state.recoveryKey !== null && age < RECOVERY_PROOF_MS && verifyJson(state.recoveryKey, recoveryChallenge(state.principal, proof.ts), proof.sig);
}

export function activeClient(state: LogState, clientId: string, now = new Date()): ClientCert | undefined {
  const cert = state.clients.get(clientId);
  if (!cert || state.revoked.has(clientId)) return undefined;
  const t = now.getTime();
  return Date.parse(cert.notBefore) <= t && t < Date.parse(cert.expires) ? cert : undefined;
}

export const activeClients = (state: LogState, now = new Date()): ClientCert[] =>
  [...state.clients.keys()]
    .map((clientId) => activeClient(state, clientId, now))
    .filter((cert): cert is ClientCert => cert !== undefined);

/** `read:*` covers `read:thread:t_1`; `intent:schedule.*` covers `intent:schedule.propose`. */
export const hasScope = (cert: ClientCert, wanted: string): boolean =>
  cert.scopes.some((scope) => scope === wanted || (scope.endsWith('*') && wanted.startsWith(scope.slice(0, -1))));
