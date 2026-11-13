import { simpleParser } from 'mailparser';
import type { AdmissionDecision, AdmissionPolicy } from './admission';
import { decideAdmission, isTrusted, knownDomains, lookalikeOf } from './admission';
import type { AttachmentRef, FileInput } from './attachments';
import { openAttachment, sealAttachment } from './attachments';
import { clientAuthHeaders } from './auth';
import type { Directory, Grant, SignedView, ViewMember } from './cards';
import { cardHash, cardKeyHistory, verifyView, viewHash, viewMember } from './cards';
import type { Ciphertext, Sealed } from './crypto';
import { decrypt, encrypt, open, padPlaintext, randomId, randomSecret, seal, sha256, unpadPlaintext } from './crypto';
import type { ContactCard, DirectoryEntry, DomainPolicy, EnrolledEntry } from './directory';
import {
  HiddenAddressError,
  IdentityChangedError,
  contactCardLink,
  parseContactCard,
  normalizeAddress,
  requesterHash,
  splitAddress,
  verifyDirectoryEntry,
  verifyNotEnrolled,
  verifyUnlisted,
  UnlistedAddressError,
} from './directory';
import { decodeResponse, encodeRequest } from './bhttp';
import { MAX_HTML_BYTES, htmlToText, sanitizeHtml, textDiverges } from './html';
import { signRequesterProof } from './requester';
import type { ApprovalCard, ApprovalChoice, AudienceMember, DisclosureContext, OrgClaim } from './disclosure';
import { DisclosureError, audienceHash, verifyOrgClaim } from './disclosure';
import { b64u, canonicalJson, fromB64u, utf8 } from './encoding';
import { OHTTP_REQUEST_TYPE, decapsulateResponse, encapsulateRequest } from './ohttp';
import type { KeyPair } from './crypto';
import type { ClientCert, ClientKeys, ClientKind, LogEntry } from './identity';
import { activeClients, keyChangeSince, recoveryProof, replayLog } from './identity';
import type { PairingChannel, PendingClient } from './enrollment';
import { EnrollmentError, HttpPairingChannel, completeEnrollment, newPairingSecret, pairAsNewClient, pairingCode, parsePairingCode } from './enrollment';
import type { Intent } from './intents';
import type { GmailMailbox } from './gmail';
import type { AttestedFields, LegacyAuth, SealedLegacyMail } from './legacy';
import { AUDIENCE_HEADER, SIGNET_HEADER, hasLegacyCopy, hashBody, isHumansOnly, openLegacyMail, parseSignetHeader, verifyAttestation } from './legacy';
import type { MessageFields, SignedMessage } from './message';
import { composeMessage, verifyMessage } from './message';
import type { Addition, ClaimedKeyPackage, CommitPreview, Joiner, Member, StateUndo } from './mls';
import { MlsSession, commitHash } from './mls';
import type { AgentCard } from './live';
import { LIVE_LABEL, LiveSession, agentCardHash, newSessionId, tokensMatch } from './live';
import type { IssuerKey } from './privacypass';
import { blindTokenRequest, finalizeToken } from './privacypass';
import type { Introduction, SealedRequest, SignedRequest } from './request';
import { createIntroduction, createRequest, myCopy, openRequest } from './request';
import { homeGateway } from './operators';
import type { Receipt } from './receipts';
import { verifyReceipt } from './receipts';
import type { Resolver } from './resolver';
import { NotSignetDomainError } from './resolver';
import { DELIVERY_LABEL, TOKEN_EPOCHS_KEPT, deliveryTokenHash, randomToken } from './sealed';
import type { InclusionProof, LatestLeaf, LogLeaf, TreeHead, TrustedLog } from './transparency';
import { TransparencyError, checkLeafDomain, countCosignatures, verifyConsistency, verifyLeaf, verifyTreeHead } from './transparency';
import { domainKeyIndex } from './policy';

export type MailKind = 'request' | 'welcome' | 'commit' | 'message' | 'legacy' | 'bounce' | 'receipt';

/** A mailbox entry. `from` is empty for sealed deliveries: the server never learned who sent them. */
export interface MailItem {
  seq: number;
  id: string;
  kind: MailKind;
  from: string;
  sealed?: boolean;
  payload: unknown;
  receivedAt: string;
}

export interface LegacyMail {
  from: string;
  subject: string;
  text: string;
  /** The html part reduced by the rules of Section 8.4.1, with no images: the only form of it that may be shown. */
  html?: string;
  date: string | null;
  auth: LegacyAuth;
  /** `inbox` only when DMARC passed and the sender would be admitted anyway; everything else is a request. */
  tier: 'inbox' | 'request';
  /** Present when the mail carried a Signet header. */
  signet: SignetCheck | null;
  /** Set when the sender's domain reads like one you know but isn't it. */
  lookalike?: string;
  /** The sender asked that agents not read this (`Signet-Audience: humans`). */
  humansOnly: boolean;
  attachments: { filename: string; contentType: string; size: number }[];
}

/**
 * What a Signet header on plain email proves. `onSignet`: that address is enrolled with the key the header
 * names. `authenticated`: additionally, that address's own domain signed this exact From, To and Subject
 * recently, so the email itself isn't a forgery. Only `authenticated` says anything about this message.
 */
export interface SignetCheck {
  address: string;
  onSignet: boolean;
  authenticated: boolean;
}

/** A plain email found in Gmail that carries a Signet header. */
export interface GmailSignetOffer {
  gmailId: string;
  from: string;
  subject: string;
  signet: SignetCheck;
  humansOnly: boolean;
}

/** A client as others see it: device or agent, and a label only if it shared one in a thread. */
export interface ClientSummary {
  clientId: string;
  kind: 'device' | 'agent' | 'escrow';
  label?: string;
}

/** A person in a thread, with the clients (devices and agents) that read it for them. */
export interface Participant {
  principal: string;
  clients: ClientSummary[];
}

export type SignetEvent =
  | { kind: 'request'; request: SignedRequest; admission: AdmissionDecision }
  | {
      kind: 'joined' | 'rekeyed' | 'fork-resolved';
      thread: string;
      epoch: number;
      members: Member[];
      participants: Participant[];
      humansOnly: boolean;
      /** For a humans-only thread opened beside an ordinary one. */
      linkedTo?: string;
    }
  | { kind: 'removed'; thread: string }
  | {
      kind: 'message';
      thread: string;
      message: SignedMessage;
      sender: ClientSummary;
      /** The message's html reduced by the rules of Section 8.4.1: the only form of it that may be shown. */
      safeHtml?: string;
      /** The text and the html say different things, so a person and an agent reading them would not agree (Section 8.4.1). */
      divergent?: boolean;
    }
  | { kind: 'legacy'; mail: LegacyMail }
  | { kind: 'bounce'; id: string; to: string[]; reason: string }
  /** An agent handed a thread to its owner: their devices should show it as needing them. */
  | { kind: 'handoff'; thread: string; by: string; reason: string }
  /**
   * A contact's identity key changed along the chain on their card. `rotated`: their own old key signed
   * it. `recovered`: their recovery key did, because the old key was lost; worth a word with them.
   */
  | { kind: 'key-changed'; principal: string; how: 'rotated' | 'recovered'; from: string; to: string }
  /** A domain told this client's server one thing about an address and anonymous lookups another. */
  | { kind: 'directory-alert'; principal: string; alert: string }
  /** A home of this client's domain still lacks an item that others delivered, after the grace period: it may be withholding mail (Section 6.9.6). */
  | { kind: 'home-missing'; home: string; itemId: string }
  /** No recipient home has proved it received this send, after resending through other homes (Section 6.9.5). */
  | { kind: 'delivery-unconfirmed'; id: string; to: string[] }
  | { kind: 'error'; item: MailItem; error: string };

export interface ThreadMeta {
  humansOnly: boolean;
  linkedTo?: string;
}

export interface UnconfirmedSend {
  id: string;
  /** The addresses still without a receipt. */
  to: string[];
  body: { id: string; to: string[]; kind: MailKind; payload: unknown; token?: string; anonymousToken?: string };
  /** When it was sent or last sent again, how many times it has been sent again, and the home it went through. */
  at: number;
  tries: number;
  via: string;
}

/** Everything a client carries between runs apart from its signing keys. `mls` holds its MLS key store. */
export interface ClientSnapshot {
  cursor: number;
  /** A mailbox cursor for each home of a domain with several (their `seq` values differ), by home URL. */
  cursors: Record<string, number>;
  /**
   * Mail already processed, by id and when, so an item that comes from more than one home, or comes late, is
   * handled once (Section 6.9.6). Entries are kept for thirty days, longer than any sender retries.
   */
  seen: Record<string, number>;
  /** The epoch each home last gave for its mailbox. A different one means the home started over, so its cursor is void. */
  epochs: Record<string, string>;
  /** Registrations a home missed because it was down, repeated at the next sync (Section 6.9.6). */
  pending: { home: string; path: string; body: unknown }[];
  /** Sends no recipient home has yet proved it received, kept to send again (Section 6.9.5). */
  unconfirmed: UnconfirmedSend[];
  /** Items seen at some homes but not yet all: which homes had each, and when it first showed up. */
  homeWatch: Record<string, { homes: string[]; at: number; alerted?: boolean }>;
  pins: Record<string, string>;
  admission: AdmissionPolicy;
  mls: string;
  threads: string[];
  /** Delivery-token hashes this client registered, per thread, oldest first. */
  tokens: Record<string, string[]>;
  /** Ids of this client's own deliveries, so their echoes are skipped. */
  sentIds: string[];
  treeHeads: Record<string, TreeHead>;
  /** The domain key already checked against the domain's log, by domain (Section 6.5). */
  domainKeys: Record<string, string>;
  /** The contacts key each home's document is under (Section 7.9), by home URL. */
  contactKeys: Record<string, { epoch: number; key: string }>;
  /** The newest contacts epoch and version each home has answered with, so an older answer is refused. */
  contactSeen: Record<string, { epoch: number; version: number }>;
  /** Changes to the contacts that a home has not taken yet, by home URL. */
  contactOps: Record<string, ContactOp[]>;
  /** The latest commit applied in each thread, with the undo for it, kept briefly in case a competing one arrives (Section 8.8). */
  lastCommit: Record<string, { hash: string; undo: StateUndo; at: number; own: boolean; joined?: boolean }>;
  /** Messages that could not be read yet, kept until the winning commit may arrive (Section 8.8). */
  held: { item: MailItem; at: number }[];
  /** Threads where this client's own commit lost, to be recomputed against the winner. */
  rekeyAgain: string[];
  knownOwnClients: string[];
  /** Grants this agent holds from its owner. */
  grants: Grant[];
  /** Contact views people presented to this client (in requests), checked against the log on every use. */
  views: Record<string, SignedView>;
  /** Labels other clients chose to share in threads. */
  labels: Record<string, string>;
  /** Which threads are humans-only, and which ordinary thread each sits beside. */
  threadMeta: Record<string, ThreadMeta>;
  /** Ordinary thread → its humans-only sibling, once one exists. */
  siblings: Record<string, string>;
  /** Live A2A sessions this client offered (host) or was offered (guest). */
  liveSessions: Record<string, LiveSessionRecord>;
  /** Threads an agent handed to a human; agents won't send in them until a human device has. */
  needsHuman: Record<string, { by: string; reason: string; ts: string }>;
  /** Contacts' key changes noticed during lookups, reported on the next sync. */
  keyChanges: KeyChangedEvent[];
  /** Domains caught answering inconsistently, reported on the next sync. */
  directoryAlerts: Extract<SignetEvent, { kind: 'directory-alert' }>[];
  /** Address → identity-key fingerprint, from plain email whose Signet header its domain authenticated. */
  knownOnSignet: Record<string, string>;
  /** Contact cards people handed this client, used when their domain says they are unlisted. */
  contactCards: Record<string, ContactCard>;
  /** This account's own thread for approval cards, once created. */
  selfThread?: string;
}

export type KeyChangedEvent = Extract<SignetEvent, { kind: 'key-changed' }>;

export interface LiveSessionRecord {
  thread: string;
  role: 'host' | 'guest';
  url: string;
  cardHash?: string;
  expires: string;
}

export interface SignetClientOptions {
  trustedLogs: TrustedLog[];
  /**
   * Witnesses whose cosignatures a tree head needs, and how many of them (Section 5.5.1). Set by the client,
   * never by a domain's policy. Without them a log is trusted on its own signature alone.
   */
  witnesses?: { keys: string[]; threshold: number };
  /** Reject tree heads older than this many milliseconds (Section 5.5.2). Defaults to 24 hours. */
  maxHeadAgeMs?: number;
  snapshot?: Partial<ClientSnapshot>;
  fetchImpl?: typeof fetch;
  /** How many unused key packages to keep on the home server, besides the last-resort one. */
  keyPackageTarget?: number;
  /** Share this client's label ("Phone", "Clerk") with the threads it writes in. Off by default. */
  shareLabel?: boolean;
  /**
   * An Oblivious HTTP relay for anonymous directory lookups: cross-checking an "unlisted" answer, and the
   * owner's check of what strangers see. Without one those lookups go direct, from this client's address.
   */
  ohttpRelay?: string;
  /**
   * How long an item may be missing from one home, when others have it, before the client reports that home
   * (`home-missing`). Defaults to ten minutes, longer than a sender's first retry.
   */
  homeGraceMs?: number;
  /** How long a send may go without a receipt before it is sent again through another home. Defaults to five minutes. */
  receiptGraceMs?: number;
  /** How many times to send again before reporting `delivery-unconfirmed`. Defaults to 3. */
  receiptRetries?: number;
}

export interface MonitorReport {
  alerts: string[];
  newClients: ClientSummary[];
}

/**
 * `for` lists hashes of the joining clients' ids, so servers don't see who is being added. A humans-only
 * thread says so, and names the ordinary thread it sits beside, if any, so clients can show them linked.
 */
interface WelcomePayload {
  thread: string;
  welcome: string;
  for: string[];
  humansOnly?: boolean;
  linkedTo?: string;
  /** For a welcome that comes with a commit: the hex SHA-256 of that commit and the epoch it makes (Section 8.8). */
  commit?: string;
  epoch?: number;
}

interface MlsPayload {
  thread: string;
  mls: string;
}


const emptySnapshot = (): ClientSnapshot => ({
  cursor: 0,
  cursors: {},
  seen: {},
  epochs: {},
  pending: [],
  unconfirmed: [],
  homeWatch: {},
  pins: {},
  admission: { contacts: [], trustedDomains: [] },
  mls: '',
  threads: [],
  tokens: {},
  sentIds: [],
  treeHeads: {},
  domainKeys: {},
  contactKeys: {},
  contactSeen: {},
  contactOps: {},
  lastCommit: {},
  held: [],
  rekeyAgain: [],
  knownOwnClients: [],
  grants: [],
  views: {},
  labels: {},
  threadMeta: {},
  siblings: {},
  liveSessions: {},
  needsHuman: {},
  keyChanges: [],
  directoryAlerts: [],
  knownOnSignet: {},
  contactCards: {},
});

const SENT_IDS_KEPT = 1000;
/** How long, and at most how many, processed ids are remembered. */
const SEEN_MAX_AGE_MS = 30 * 86_400_000;
const SEEN_MAX = 200_000;
const PENDING_KEPT = 200;
const UNCONFIRMED_KEPT = 200;
const WATCH_KEPT = 500;
const WATCH_MAX_AGE_MS = 24 * 3_600_000;

const joinerTag = (clientId: string): string => sha256(`signet joiner ${clientId}`);
const welcomeFor = (thread: string, welcome: string, joiners: Joiner[], meta: ThreadMeta = { humansOnly: false }, commit?: { hash: string; epoch: number }): WelcomePayload => ({
  thread,
  welcome,
  for: joiners.map((joiner) => joinerTag(joiner.clientId)),
  ...(commit ? { commit: commit.hash, epoch: commit.epoch } : {}),
  ...(meta.humansOnly ? { humansOnly: true } : {}),
  ...(meta.linkedTo ? { linkedTo: meta.linkedTo } : {}),
});

/** Who may be in a thread: readers, and in a humans-only thread only devices and agents their owner opted in. */
const eligible = (member: ViewMember, humansOnly: boolean): boolean => member.reads && (!humansOnly || member.humansOnly);

/** One change to the shared contacts (Section 7.9). */
interface ContactOp {
  op: 'add' | 'remove';
  kind: 'contact' | 'domain';
  value: string;
}

function applyContactOps(lists: AdmissionPolicy, ops: ContactOp[]): AdmissionPolicy {
  const contacts = new Set(lists.contacts);
  const domains = new Set(lists.trustedDomains);
  for (const { op, kind, value } of ops) {
    const set = kind === 'contact' ? contacts : domains;
    if (op === 'add') set.add(value);
    else set.delete(value);
  }
  return { contacts: [...contacts], trustedDomains: [...domains] };
}

/** How long a client keeps the means to take back its latest commit, and messages it cannot read yet (Section 8.8). */
const FORK_WINDOW_MS = 5 * 60_000;

/** A thread message that cannot be decrypted yet, perhaps because the commit it follows has not arrived. */
class NotReadableYet extends Error {}

const describe = (error: unknown) => (error instanceof Error ? error.message : String(error));
const unique = (values: string[]) => [...new Set(values)];

/** Current clients that join this person's threads (only humans-only ones, if asked). Needs their contact view. */
function readers(directory: Directory, humansOnly = false, now = new Date()): ViewMember[] {
  if (!directory.view) throw new Error(`${directory.principal} hasn't shared their contact view with you`);
  return directory.view.members.filter((member) => eligible(member, humansOnly) && Date.parse(member.expires) > now.getTime());
}

/**
 * One approved client. It talks only to its own home server, which proxies lookups, key-package claims
 * and log queries, so other domains rate-limit by requester and never see this client's address.
 */
export class SignetClient {
  private readonly state: ClientSnapshot;
  private readonly mls: MlsSession;
  private readonly directories = new Map<string, Promise<Directory | null>>();
  private readonly fetchImpl: typeof fetch;
  private readonly ohttpRelay: string | undefined;
  private released = 0;
  /** Set while this client's own server refuses it: lookups then go straight to the public directory and log. */
  private direct = false;

  constructor(
    readonly keys: ClientKeys,
    private readonly resolver: Resolver,
    private readonly options: SignetClientOptions,
  ) {
    this.state = { ...emptySnapshot(), ...structuredClone(options.snapshot ?? {}) };
    // A snapshot from before ids carried times held them as a list.
    if (Array.isArray(this.state.seen)) this.state.seen = Object.fromEntries((this.state.seen as string[]).map((id) => [`id:${id}`, Date.now()]));
    this.mls = new MlsSession(keys, this.state.mls);
    this.fetchImpl = resolver.failoverFetch?.(options.fetchImpl ?? fetch) ?? options.fetchImpl ?? fetch;
    this.ohttpRelay = options.ohttpRelay;
  }

  get address(): string {
    return this.keys.cert.principal;
  }

  get admission(): AdmissionPolicy {
    return this.state.admission;
  }

  get threadIds(): string[] {
    return [...this.state.threads];
  }

  members(thread: string): Member[] {
    return this.mls.members(this.thread(thread));
  }

  /** The people in a thread, each with the clients that read it for them. */
  async participants(thread: string): Promise<Participant[]> {
    this.directories.clear();
    return this.toParticipants(this.members(thread));
  }

  epoch(thread: string): number {
    return this.mls.epoch(this.thread(thread));
  }

  snapshot(): ClientSnapshot {
    return structuredClone({ ...this.state, mls: this.mls.state });
  }

  /**
   * Contacts and trusted domains are shared by every client of the account, so each admits the same people and
   * warns about the same lookalikes. The home server holds them encrypted under a key only the account's clients
   * have (Section 7.9). A change is kept until every home has taken it.
   */
  async addContact(address: string): Promise<void> {
    await this.changeContacts([{ op: 'add', kind: 'contact', value: normalizeAddress(address) }]);
  }

  async trustDomain(domain: string): Promise<void> {
    await this.changeContacts([{ op: 'add', kind: 'domain', value: domain.toLowerCase() }]);
  }

  async removeContact(address: string): Promise<void> {
    await this.changeContacts([{ op: 'remove', kind: 'contact', value: normalizeAddress(address) }]);
  }

  async untrustDomain(domain: string): Promise<void> {
    await this.changeContacts([{ op: 'remove', kind: 'domain', value: domain.toLowerCase() }]);
  }

  /** Delete an attachment this client uploaded, at every home that holds it (Section 8.9). Copies already fetched stay fetched. */
  async deleteAttachment(ref: AttachmentRef): Promise<void> {
    const failed: unknown[] = [];
    for (const url of [ref.url, ...(ref.mirrors ?? [])]) {
      const { origin, pathname } = new URL(url);
      try {
        await this.request(origin, 'DELETE', pathname);
      } catch (error) {
        failed.push(error);
      }
    }
    if (failed.length > 0) throw failed[0];
  }

  /**
   * Whether a request to this address will be readable by the recipient's organisation escrow client. A sender
   * MUST tell the person before sending (Section 4.3); the card says so on the escrow client's key.
   */
  async escrowRecipient(address: string, humansOnly = false): Promise<boolean> {
    const { card } = await this.recipientFor(normalizeAddress(address));
    return (humansOnly ? card.humanKeys : card.requestKeys).some((key) => key.escrow === true);
  }

  /** Mark a client this device approved itself, so `monitor` doesn't ask whether it was you. */
  acknowledgeClient(clientId: string): void {
    if (!this.state.knownOwnClients.includes(clientId)) this.state.knownOwnClients.push(clientId);
  }

  /** Apply a change here, and at every home as soon as each takes it. */
  private async changeContacts(ops: ContactOp[]): Promise<void> {
    this.state.admission = applyContactOps(this.state.admission, ops);
    const homes = await this.homeBases();
    for (const home of homes) (this.state.contactOps[home] ??= []).push(...ops);
    let failure: unknown;
    let taken = 0;
    for (const home of homes) {
      try {
        await this.syncContactsAt(home);
        taken += 1;
      } catch (error) {
        failure = error;
      }
    }
    if (taken === 0 && failure) throw failure;
  }

  /** The clients that hold a copy of the contacts key: every active client of this account. */
  private async activeOwnClients(): Promise<ClientCert[]> {
    const own = (await this.call('GET', `/v0/lookup?address=${encodeURIComponent(this.address)}`)) as EnrolledEntry;
    if (!own.log) throw new Error('home server did not return this account’s log');
    return activeClients(replayLog(own.log));
  }

  private contactsAad = (epoch: number): Uint8Array => utf8(`signet0 contacts|${this.address}|${epoch}`);
  private contactsInfo = (epoch: number): string => `signet0 contacts key|${this.address}|${epoch}`;

  private sealContacts(lists: AdmissionPolicy, key: Buffer, epoch: number): Ciphertext {
    return encrypt(key, padPlaintext(utf8(JSON.stringify({ v: 0, contacts: lists.contacts, trustedDomains: lists.trustedDomains }))), this.contactsAad(epoch));
  }

  private openContacts(data: Ciphertext, key: Buffer, epoch: number): AdmissionPolicy {
    const body = JSON.parse(unpadPlaintext(decrypt(key, data, this.contactsAad(epoch))).toString('utf8')) as { contacts?: string[]; trustedDomains?: string[] };
    return { contacts: unique(body.contacts ?? []), trustedDomains: unique(body.trustedDomains ?? []) };
  }

  private async wrapsFor(clients: ClientCert[], key: Buffer, epoch: number): Promise<Record<string, Sealed>> {
    return Object.fromEntries(await Promise.all(clients.map(async (cert) => [cert.clientId, await seal(cert.agreeKey, key, this.contactsInfo(epoch))] as const)));
  }

  /**
   * Bring one home's contacts document in step (Section 7.9): open the key, apply the changes this home has not
   * taken, give new clients their wraps, and rotate the key if a revoked client still has one. Returns the lists
   * the home holds, with changes it has not yet taken applied, or null if this client has no key there yet.
   */
  private async syncContactsAt(home: string): Promise<AdmissionPolicy | null> {
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const answer = (await this.request(home, 'GET', '/v0/contacts')) as { epoch: number; version: number; data: Ciphertext | null; wrap: Sealed | null; wrapped: string[] };
      const seen = this.state.contactSeen[home];
      if (seen && (answer.epoch < seen.epoch || (answer.epoch === seen.epoch && answer.version < seen.version))) {
        throw new Error(`${home} answered with older contacts than it did before`);
      }
      this.state.contactSeen[home] = { epoch: answer.epoch, version: answer.version };
      const pending = this.state.contactOps[home] ?? [];
      let held: { epoch: number; key: string } | undefined = this.state.contactKeys[home];
      if (answer.epoch > 0 && held?.epoch !== answer.epoch) {
        held = undefined;
        delete this.state.contactKeys[home];
        if (answer.wrap) {
          const key = await open(this.keys.agreement, answer.wrap, this.contactsInfo(answer.epoch));
          held = { epoch: answer.epoch, key: b64u(key) };
          this.state.contactKeys[home] = held;
        }
      }
      // No key yet: another client has to give this one a wrap.
      if (answer.epoch > 0 && !held) return null;
      const active = await this.activeOwnClients();
      const activeIds = new Set(active.map((cert) => cert.clientId));
      let key = held ? fromB64u(held.key) : randomSecret();
      let epoch = answer.epoch;
      const stored = answer.data && held ? this.openContacts(answer.data, key, answer.epoch) : answer.epoch === 0 ? this.state.admission : { contacts: [], trustedDomains: [] };
      const lists = applyContactOps(stored, pending);
      const missing = active.filter((cert) => !answer.wrapped.includes(cert.clientId));
      const revoked = answer.wrapped.some((id) => !activeIds.has(id));
      let body: { expectedVersion: number; epoch: number; data?: Ciphertext; wraps: Record<string, Sealed> } | undefined;
      if (answer.epoch === 0 || revoked) {
        // A first key, or a new one because a client that is no longer active still holds the old.
        epoch = answer.epoch + 1;
        key = randomSecret();
        body = { expectedVersion: answer.version, epoch, data: this.sealContacts(lists, key, epoch), wraps: await this.wrapsFor(active, key, epoch) };
      } else if (pending.length > 0 || missing.length > 0) {
        body = {
          expectedVersion: answer.version,
          epoch,
          ...(pending.length > 0 ? { data: this.sealContacts(lists, key, epoch) } : {}),
          wraps: await this.wrapsFor(missing, key, epoch),
        };
      }
      if (body) {
        try {
          const { version } = (await this.request(home, 'PUT', '/v0/contacts', body)) as { version: number };
          this.state.contactSeen[home] = { epoch, version };
          this.state.contactKeys[home] = { epoch, key: b64u(key) };
          delete this.state.contactOps[home];
        } catch (error) {
          if (error instanceof Error && error.message.includes(' 409 ')) continue;
          throw error;
        }
      }
      return lists;
    }
    throw new Error(`${home} kept changing the contacts; try again`);
  }

  /** At each sync: bring every home's contacts in step, then take the lists from the first that answers (Section 7.9). */
  private async pullContacts(): Promise<void> {
    let lists: AdmissionPolicy | null = null;
    let failure: unknown;
    for (const home of await this.homeBases()) {
      try {
        const got = await this.syncContactsAt(home);
        if (!lists && got) lists = got;
      } catch (error) {
        failure = error;
      }
    }
    if (lists) this.state.admission = lists;
    else if (failure && (await this.homeBases()).length === 1) throw failure;
  }

  /** Hold a grant from this client's owner. The agent presents it only to the counterparty it names. */
  addGrant(grant: Grant): void {
    if (grant.agent !== this.keys.cert.clientId || grant.principal !== this.address) throw new Error('this grant is for another client');
    this.state.grants = [...this.state.grants.filter((held) => held.id !== grant.id), grant];
  }

  /** Publish key packages so others can add this client to threads. Call once after enrolling; sync keeps them topped up. */
  async ready(): Promise<void> {
    this.directories.clear();
    if (this.state.knownOwnClients.length === 0) {
      const own = await this.require(this.address);
      this.state.knownOwnClients = (own.view?.members ?? []).map((member) => member.clientId);
    }
    await this.topUpKeyPackages();
  }

  /**
   * Fetch and verify an address's directory entry and its transparency-log record. Strangers get the
   * public card; contacts who have been released the view get it too. Pins the identity key on first
   * sight. Returns null when the address is provably not enrolled.
   */
  async lookup(address: string): Promise<Directory | null> {
    this.directories.clear();
    return this.cachedLookup(address);
  }

  /** Vouch for `introduced` to `to`, using this client's key and its current contact view. */
  async introduce(introduced: string, to: string, context: string): Promise<Introduction> {
    return createIntroduction(this.keys, await this.ownView(), normalizeAddress(introduced), normalizeAddress(to), context);
  }

  /**
   * Send a first-contact request, sealed to the recipient's public request keys (just its intake agent,
   * if it chose that). When the recipient's domain accepts Privacy Pass tokens, it goes anonymously: a
   * token instead of a sender on the envelope. Pass `anonymous: false` to send it signed in the clear.
   */
  async sendRequest(
    to: string,
    fields: { subject: string; intent?: Intent; note?: string; introduction?: Introduction },
    options: { anonymous?: boolean; humansOnly?: boolean } = {},
  ): Promise<SealedRequest> {
    this.directories.clear();
    const recipient = await this.recipientFor(to);
    const policy = await this.resolver.policy(splitAddress(recipient.principal).domain);
    const anonymous = options.anonymous ?? policy.privacyPass !== undefined;
    const replyToken = randomToken();
    await this.registerTokens([deliveryTokenHash(replyToken, this.address)], []);
    await this.releaseView([recipient.principal]);
    const request = await createRequest(
      this.keys,
      await this.ownView(),
      recipient,
      { ...fields, replyToken, grants: this.state.grants, humansOnly: options.humansOnly },
      new Date(),
      anonymous,
    );
    if (anonymous) await this.submit([request.to], 'request', request, undefined, await this.privacyPassToken(policy));
    else await this.submit([request.to], 'request', request);
    await this.addContact(request.to);
    return request;
  }

  /** Admit a request's sender: start a thread with every reading client on both sides (humans-only if the request was). */
  async accept(request: SignedRequest): Promise<string> {
    await this.addContact(request.body.from);
    return this.startThread([request.body.from], { replyToken: request.body.replyToken, humansOnly: request.body.audience === 'humans' });
  }

  isHumansOnly(thread: string): boolean {
    return this.state.threadMeta[thread]?.humansOnly ?? false;
  }

  /** The humans-only thread beside this one, if it has been opened. */
  humansOnlySibling(thread: string): string | undefined {
    return this.state.siblings[thread];
  }

  /**
   * Start a thread with these people and this client's own other readers. It releases this account's
   * contact view to them first. The welcome to the other side is sealed when they gave a reply token.
   */
  async startThread(with_: string[], options: { replyToken?: string; humansOnly?: boolean; linkedTo?: string } = {}): Promise<string> {
    this.directories.clear();
    const humansOnly = options.humansOnly ?? false;
    const own = await this.require(this.address);
    if (humansOnly && !viewMember(own.view, this.keys.cert.clientId)?.humansOnly) {
      throw new Error('this client is an agent its owner hasn\'t allowed into humans-only threads');
    }
    const others = unique(with_.map(normalizeAddress)).filter((principal) => principal !== this.address);
    await this.releaseView(others);
    const additions: Addition[] = [];
    for (const principal of [this.address, ...others]) {
      const members = readers(await this.require(principal), humansOnly).filter((member) => member.clientId !== this.keys.cert.clientId);
      additions.push(...(await this.claim(principal, members)));
    }
    const { thread, welcome, joiners } = this.mls.createGroup(additions);
    const meta: ThreadMeta = { humansOnly, ...(options.linkedTo ? { linkedTo: options.linkedTo } : {}) };
    this.state.threads.push(thread);
    this.state.threadMeta[thread] = meta;
    if (options.linkedTo) this.state.siblings[options.linkedTo] = thread;
    await this.registerCurrentToken(thread);
    if (welcome) {
      const payload = welcomeFor(thread, welcome, joiners, meta);
      const replyToken = options.replyToken;
      if (joiners.some((joiner) => joiner.principal === this.address)) await this.submit([this.address], 'welcome', payload);
      if (others.length > 0) await this.submit(others, 'welcome', payload, replyToken);
    }
    return thread;
  }

  /**
   * Send to a thread. With `humansOnly` on an ordinary thread, the message goes to its humans-only
   * sibling (same people, only their devices and opted-in agents), opened the first time it's needed.
   * Everything stays inside MLS; the audience is the group's membership.
   */
  async send(thread: string, fields: MessageFields & { files?: FileInput[]; humansOnly?: boolean }): Promise<SignedMessage & { thread: string }> {
    this.directories.clear();
    let id = this.thread(thread);
    const { files = [], humansOnly, ...rest } = fields;
    if (rest.html !== undefined) {
      if (Buffer.byteLength(rest.html) > MAX_HTML_BYTES) throw new Error(`a message's html is at most ${MAX_HTML_BYTES} bytes`);
      // text is always present: an html-only message gets the text a person would read from it.
      if (rest.text.trim() === '') rest.text = htmlToText(rest.html);
    }
    const handsOff = (rest.intents ?? []).some((intent) => intent.name.startsWith('handoff.human'));
    if (this.state.needsHuman[id]?.by === this.address && this.keys.cert.kind !== 'device' && !handsOff) {
      throw new Error(`this thread was handed to a human (${this.state.needsHuman[id].reason}); an agent can't send in it until they reply`);
    }
    if (humansOnly && !this.isHumansOnly(id)) {
      const others = this.principalsOf(this.mls.members(id)).filter((principal) => principal !== this.address);
      id = this.state.siblings[id] ?? (await this.startThread(others, { humansOnly: true, linkedTo: id }));
    }
    if (this.isHumansOnly(id)) rest.audience = 'humans';
    const uploaded = await Promise.all(files.map((file) => this.upload(file)));
    const principals = this.principalsOf(this.mls.members(id));
    const now = Date.now();
    const grants = this.state.grants.filter((grant) => principals.includes(grant.counterparty) && Date.parse(grant.expires) > now);
    const message = composeMessage(this.keys, id, {
      ...rest,
      attachments: [...(rest.attachments ?? []), ...uploaded],
      grants: [...(rest.grants ?? []), ...grants],
      profile: rest.profile ?? (this.options.shareLabel ? { label: this.keys.cert.label } : undefined),
    });
    const token = this.deliveryToken(id);
    const mls = this.mls.encrypt(id, utf8(JSON.stringify(message)));
    await this.submit(principals, 'message', { thread: id, mls } satisfies MlsPayload, token);
    if (handsOff) this.handOff(id, this.address, rest.intents?.find((i) => i.name.startsWith('handoff.human'))?.args.reason as string);
    else if (this.keys.cert.kind === 'device') delete this.state.needsHuman[id];
    return { ...message, thread: id };
  }

  /**
   * Offer to continue a thread as a live A2A session with this agent's gateway. The offer is a signed
   * intent inside the thread, so only members see the URL; the token each side uses is derived from the
   * thread's MLS exporter, so nothing secret is sent and a rekey ends the session.
   */
  async offerLiveSession(thread: string, card: AgentCard, ttlMinutes = 30): Promise<{ sessionId: string }> {
    const sessionId = newSessionId();
    const expires = new Date(Date.now() + ttlMinutes * 60_000).toISOString();
    const cardHash = agentCardHash(card);
    await this.send(thread, {
      subject: 'Live session',
      text: `Continuing live at ${card.url} until ${expires}`,
      intents: [{ name: 'session.offer', args: { protocol: 'a2a', url: card.url, cardHash, sessionId, expires } }],
    });
    this.state.liveSessions[sessionId] = { thread, role: 'host', url: card.url, cardHash, expires };
    return { sessionId };
  }

  /** The current bearer token for a session: only members of the thread at its current epoch can derive it. */
  liveToken(thread: string, sessionId: string): string {
    return b64u(this.mls.exportSecret(this.thread(thread), `${LIVE_LABEL} ${sessionId}`));
  }

  /** For this agent's gateway: the session's thread if the token is current, else null. */
  authorizeLive(sessionId: string, token: string): string | null {
    const session = this.state.liveSessions[sessionId];
    if (!session || session.role !== 'host' || Date.parse(session.expires) <= Date.now()) return null;
    if (!this.state.threads.includes(session.thread) || this.state.needsHuman[session.thread]) return null;
    return tokensMatch(token, this.liveToken(session.thread, sessionId)) ? session.thread : null;
  }

  /** Accept a `session.offer` from a thread message: check the agent card against its hash, then connect. */
  async joinLiveSession(thread: string, message: SignedMessage): Promise<LiveSession> {
    const offer = message.body.intents.find((intent) => intent.name.startsWith('session.offer'));
    if (!offer || message.body.thread !== thread) throw new Error('that message is not a live-session offer for this thread');
    const { url, sessionId, cardHash, expires } = offer.args as { url: string; sessionId: string; cardHash?: string; expires: string };
    if (Date.parse(expires) <= Date.now()) throw new Error('the live-session offer has expired');
    if (this.state.needsHuman[thread]?.by === this.address && this.keys.cert.kind !== 'device') throw new Error('this thread was handed to a human');
    const card = (await this.getJson(`${url}/.well-known/agent-card.json`)) as AgentCard;
    if (cardHash && agentCardHash(card) !== cardHash) throw new Error('agent card does not match the hash in the offer');
    this.state.liveSessions[sessionId] = { thread, role: 'guest', url, cardHash, expires };
    return new LiveSession(url, sessionId, this.liveToken(thread, sessionId), this.fetchImpl);
  }

  /** End a session this client offered, telling the thread. */
  async endLiveSession(sessionId: string, reason = 'ended'): Promise<void> {
    const session = this.state.liveSessions[sessionId];
    if (!session) return;
    delete this.state.liveSessions[sessionId];
    await this.send(session.thread, { subject: 'Live session', text: `Live session ${reason}`, intents: [{ name: 'session.end', args: { sessionId, reason } }] });
  }

  needsHuman(thread: string): { by: string; reason: string; ts: string } | undefined {
    return this.state.needsHuman[thread];
  }

  /** Mark a thread as handed to a human and end its live sessions. */
  private handOff(thread: string, by: string, reason: string | undefined): void {
    this.state.needsHuman[thread] = { by, reason: reason ?? 'needs a human', ts: new Date().toISOString() };
    for (const [sessionId, session] of Object.entries(this.state.liveSessions)) {
      if (session.thread === thread) delete this.state.liveSessions[sessionId];
    }
  }

  /** Claims this account's organisation vouches for ("team:corporate"), signed by its domain key. */
  async ownClaims(): Promise<OrgClaim[]> {
    return ((await this.call('GET', '/v0/claims')) as { claims: OrgClaim[] }).claims;
  }

  /** Ask a thread for information, with the claims the organisation signed about this account. */
  async requestInfo(thread: string, fields: { question: string; purpose?: string; neededBy?: string }): Promise<SignedMessage> {
    const claims = await this.ownClaims();
    return this.send(thread, {
      subject: 'Information request',
      text: fields.question,
      intents: [{ name: 'info.request', args: { question: fields.question, purpose: fields.purpose, neededBy: fields.neededBy, claims } }],
    });
  }

  /**
   * What an answering agent can rely on about an `info.request`: who asked and from which kind of client,
   * the claims that verify against the asker's domain key, and exactly who would read an answer here.
   */
  async disclosureContext(thread: string, message: SignedMessage): Promise<DisclosureContext> {
    const intent = message.body.intents.find((candidate) => candidate.name.startsWith('info.request'));
    if (!intent) throw new DisclosureError('that message is not an information request');
    const { question, purpose, claims = [] } = intent.args as { question: string; purpose?: string; claims?: OrgClaim[] };
    const requester = message.body.from;
    const policy = await this.resolver.policy(splitAddress(requester).domain);
    const verified = claims.filter((claim) => verifyOrgClaim(claim, requester, policy)).map((claim) => claim.body.claim);
    const audience = await this.audience(thread);
    const requesterKind = audience.find((member) => member.clientId === message.body.fromClient)?.kind ?? 'unknown';
    return {
      thread: this.thread(thread),
      requestId: message.body.id,
      question,
      purpose,
      requester,
      requesterKind,
      claims: [...new Set(verified)],
      audience,
      audienceHash: audienceHash(audience.map((member) => member.clientId)),
    };
  }

  /** Every client that would read a message in this thread, with its owner and kind. */
  async audience(thread: string): Promise<AudienceMember[]> {
    const people = await this.participants(thread);
    return people.flatMap((person) => person.clients.map((client) => ({ principal: person.principal, clientId: client.clientId, kind: client.kind, label: client.label })));
  }

  /** Answer directly, when the owner's rules already allow it. The answer names the membership it went to. */
  async answerInfo(context: DisclosureContext, text: string, decision: 'answered' | 'narrowed' = 'answered'): Promise<SignedMessage> {
    const current = audienceHash((await this.audience(context.thread)).map((member) => member.clientId));
    if (current !== context.audienceHash) throw new DisclosureError("the thread's members changed since this was decided");
    return this.send(context.thread, {
      subject: 'Re: information request',
      text,
      inReplyTo: context.requestId,
      intents: [{ name: 'info.answer', args: { requestId: context.requestId, decision, approvedFor: current } }],
    });
  }

  async refuseInfo(context: DisclosureContext, reason: string): Promise<SignedMessage> {
    return this.send(context.thread, {
      subject: 'Re: information request',
      text: reason,
      inReplyTo: context.requestId,
      intents: [{ name: 'info.answer', args: { requestId: context.requestId, decision: 'refused', reason } }],
    });
  }

  /**
   * Hand the decision to the owner: an approval card, with the draft and the exact audience, goes to a
   * thread of this account's own clients only. Nothing reaches the asker until a device releases it.
   */
  async escalateInfo(context: DisclosureContext, draft: string): Promise<void> {
    const card: ApprovalCard = { ...context, draft };
    await this.send(await this.selfThread(), {
      subject: `Approve a disclosure to ${context.requester}?`,
      text: `${context.requester} asks: ${context.question}`,
      intents: [{ name: 'info.approval', args: { ...card } }],
    });
  }

  /** The approval card in a message from this account's own agent, if there is one. */
  approvalCard(message: SignedMessage): ApprovalCard | null {
    if (message.body.from !== this.address) return null;
    const intent = message.body.intents.find((candidate) => candidate.name.startsWith('info.approval'));
    return intent ? (intent.args as unknown as ApprovalCard) : null;
  }

  /**
   * The owner decides on a device. Releasing to the thread is refused if anyone joined or left since the
   * card was drawn: the owner approved that audience, not whoever is there now. Releasing to the
   * requester only goes to the humans-only sibling (their devices, and anything they opted in).
   */
  async decideApproval(card: ApprovalCard, choice: ApprovalChoice): Promise<SignedMessage> {
    if (this.keys.cert.kind !== 'device') throw new DisclosureError("only the owner's devices can release a disclosure");
    const reply = { subject: 'Re: information request', inReplyTo: card.requestId };
    if (choice.release === 'refuse') {
      return this.send(card.thread, { ...reply, text: choice.reason, intents: [{ name: 'info.answer', args: { requestId: card.requestId, decision: 'refused', reason: choice.reason } }] });
    }
    const text = choice.text ?? card.draft;
    const decision = text === card.draft ? 'answered' : 'narrowed';
    if (choice.release === 'requester-only') {
      return this.send(card.thread, { ...reply, text, humansOnly: true, intents: [{ name: 'info.answer', args: { requestId: card.requestId, decision } }] });
    }
    const audience = await this.audience(card.thread);
    const current = audienceHash(audience.map((member) => member.clientId));
    if (current !== card.audienceHash) {
      const approved = new Set(card.audience.map((member) => member.clientId));
      const joined = audience.filter((member) => !approved.has(member.clientId)).map((member) => `${member.principal} (${member.label ?? member.kind})`);
      throw new DisclosureError(`the thread's members changed since you approved${joined.length ? `: ${joined.join(', ')} joined` : ''}. Approve again`);
    }
    return this.send(card.thread, { ...reply, text, intents: [{ name: 'info.answer', args: { requestId: card.requestId, decision, approvedFor: current } }] });
  }

  /** A thread of this account's own clients, for approval cards. Created on first use. */
  private async selfThread(): Promise<string> {
    const existing = this.state.selfThread;
    if (existing && this.state.threads.includes(existing)) return existing;
    const thread = await this.startThread([]);
    this.state.selfThread = thread;
    return thread;
  }

  /** Bring a thread in line with everyone's current views: remove revoked or expired clients, add new readers. */
  async rekey(thread: string): Promise<{ removed: Member[]; added: Joiner[] }> {
    this.directories.clear();
    const id = this.thread(thread);
    const members = this.mls.members(id);
    const principals = this.principalsOf(members);
    const directories = new Map<string, Directory | null>();
    for (const principal of principals) directories.set(principal, await this.cachedLookup(principal));
    const humansOnly = this.isHumansOnly(id);
    const reading = (member: Member) => {
      const current = viewMember(directories.get(member.principal)?.view, member.clientId);
      return current !== undefined && current.sigKey === member.signatureKey && eligible(current, humansOnly);
    };
    const removed = members.filter((member) => member.clientId !== this.keys.cert.clientId && !reading(member));
    const present = new Set(members.map((member) => member.clientId));
    const additions: Addition[] = [];
    for (const principal of principals) {
      const directory = directories.get(principal);
      if (directory?.view) additions.push(...(await this.claim(principal, readers(directory, humansOnly).filter((member) => !present.has(member.clientId)))));
    }
    if (removed.length === 0 && additions.length === 0) return { removed: [], added: [] };
    const token = this.deliveryToken(id);
    const result = this.mls.commitUndoable(id, removed.map((member) => member.leafIndex), additions);
    this.state.lastCommit[id] = { hash: commitHash(result.commit).toString('hex'), undo: result.undo, at: Date.now(), own: true };
    await this.submit(principals, 'commit', { thread: id, mls: result.commit } satisfies MlsPayload, token);
    if (result.welcome) {
      await this.submit(this.principalsOf(result.joiners), 'welcome', welcomeFor(id, result.welcome, result.joiners, this.state.threadMeta[id], { hash: commitHash(result.commit).toString('hex'), epoch: this.mls.epoch(id) }), token);
    }
    await this.registerCurrentToken(id);
    return { removed, added: result.joiners };
  }

  /** Download and decrypt an attachment from a message this client has read. */
  async fetchAttachment(ref: AttachmentRef): Promise<Buffer> {
    let failure: unknown;
    for (const url of [ref.url, ...(ref.mirrors ?? [])]) {
      try {
        const response = await this.fetchImpl(url);
        if (!response.ok) throw new Error(`could not fetch ${ref.name}: ${response.status}`);
        // The digest is checked on every copy, so a copy can't hand over anything but the file.
        return openAttachment(ref, new Uint8Array(await response.arrayBuffer()));
      } catch (error) {
        failure = error;
      }
    }
    throw failure;
  }

  /** Plain email through the home server, for recipients who aren't on Signet. It carries the Signet header. */
  async sendLegacy(to: string[], fields: { subject: string; text: string; html?: string; files?: FileInput[]; humansOnly?: boolean }): Promise<{ messageId: string }> {
    const attachments = (fields.files ?? []).map((file) => ({
      filename: file.name,
      contentType: file.type,
      content: Buffer.from(file.data).toString('base64'),
    }));
    return (await this.call('POST', '/v0/legacy/send', { to, subject: fields.subject, text: fields.text, ...(fields.html === undefined ? {} : { html: fields.html }), attachments, humansOnly: fields.humansOnly })) as {
      messageId: string;
    };
  }

  /** A Signet header for an outgoing plain email, attested by this account's home server with its domain key. */
  async signetHeader(fields: { to: string[]; subject: string; bodyHash: string; htmlHash?: string; humansOnly?: boolean }): Promise<string> {
    return ((await this.call('POST', '/v0/legacy/attest', fields)) as { header: string }).header;
  }

  /**
   * Check a Signet header on plain email. Resolves the address (From, or the header's `addr`) through
   * DNS and the transparency log, compares the fingerprint, and checks the domain's attestation over
   * this message's From, To and Subject. Never trusts the header's `server`.
   */
  async checkSignetHeader(fields: AttestedFields, value: string | undefined): Promise<SignetCheck | null> {
    const header = parseSignetHeader(value);
    if (!header) return null;
    const address = normalizeAddress(header.address ?? fields.from);
    try {
      let directory: Directory | null = null;
      let hidden = false;
      try {
        directory = await this.cachedLookup(address);
      } catch (error) {
        if (!(error instanceof UnlistedAddressError || error instanceof HiddenAddressError)) throw error;
        hidden = true;
      }
      // The attestation must come from the From address's own domain: nobody else can vouch for that mail.
      const fromPolicy = await this.resolver.policy(splitAddress(fields.from).domain).catch(() => null);
      if (fromPolicy) await this.checkDomainKey(fromPolicy, this.trustedLog(fromPolicy));
      const vouched = fromPolicy !== null && verifyAttestation(header, fields, fromPolicy.domainKey);
      // An unlisted sender can't be looked up, but its domain's attestation still names its key.
      const onSignet = directory ? sha256(directory.identityKey) === header.fingerprint : hidden && vouched;
      const authenticated = onSignet && vouched;
      // Remember it: if its domain later calls it unlisted, a first request won't go through the intake.
      if (authenticated) this.state.knownOnSignet[address] = header.fingerprint;
      return { address, onSignet, authenticated };
    } catch {
      return { address, onSignet: false, authenticated: false };
    }
  }

  /** Plain email through the Gmail API (Gmail mode), carrying an attested Signet header. */
  async sendViaGmail(gmail: GmailMailbox, to: string[], fields: { subject: string; text: string; html?: string; files?: FileInput[]; humansOnly?: boolean }): Promise<{ id: string }> {
    const header = await this.signetHeader({ to, subject: fields.subject, bodyHash: hashBody(fields.text), ...(fields.html === undefined ? {} : { htmlHash: hashBody(fields.html) }), humansOnly: fields.humansOnly });
    return gmail.send({ from: this.address, to, subject: fields.subject, text: fields.text, html: fields.html, signetHeader: header, humansOnly: fields.humansOnly, files: fields.files });
  }

  /** New Gmail messages since `historyId` that carry a Signet header, checked; and where to resume. */
  async scanGmail(gmail: GmailMailbox, historyId: string): Promise<{ historyId: string; offers: GmailSignetOffer[] }> {
    this.directories.clear();
    const { historyId: next, messages } = await gmail.newMessages(historyId);
    // Gmail can't seal anything, so here the owner's policy is honoured by the client itself.
    const own = await this.require(this.address);
    const mayReadHumansOnly = viewMember(own.view, this.keys.cert.clientId)?.humansOnly ?? this.keys.cert.kind === 'device';
    const offers: GmailSignetOffer[] = [];
    for (const message of messages) {
      if (!message.signet || (message.humansOnly && !mayReadHumansOnly)) continue;
      const signet = await this.checkSignetHeader(
        { from: message.from, to: message.to, subject: message.subject, bodyHash: hashBody(message.text ?? ''), ...(message.html === undefined ? {} : { htmlHash: hashBody(message.html) }), ...(message.humansOnly ? { audience: 'humans' as const } : {}) },
        message.signet,
      );
      if (signet) offers.push({ gmailId: message.id, from: message.from, subject: message.subject, signet, humansOnly: message.humansOnly });
    }
    return { historyId: next, offers };
  }

  /** Signet when the recipient is enrolled (a request, or the existing thread), plain email otherwise. */
  async mail(to: string, fields: { subject: string; text: string; html?: string; files?: FileInput[]; humansOnly?: boolean }): Promise<{ via: 'signet' | 'smtp'; thread?: string }> {
    this.directories.clear();
    let enrolled: Directory | null = null;
    let unlisted = false;
    try {
      enrolled = await this.cachedLookup(to);
    } catch (error) {
      if (error instanceof UnlistedAddressError) unlisted = true;
      else if (!(error instanceof NotSignetDomainError)) throw error;
    }
    if (!enrolled && !unlisted) {
      await this.sendLegacy([to], fields);
      return { via: 'smtp' };
    }
    const who = normalizeAddress(to);
    const existing = this.state.threads.find((thread) => {
      const people = new Set(this.mls.members(thread).map((member) => member.principal));
      return people.has(who) && [...people].every((principal) => principal === who || principal === this.address);
    });
    if (existing) {
      await this.send(existing, fields);
      return { via: 'signet', thread: existing };
    }
    await this.sendRequest(who, { subject: fields.subject, note: fields.text.slice(0, 500) }, { humansOnly: fields.humansOnly });
    return { via: 'signet' };
  }

  /** Pull new mail from the home server and turn it into events. Bad items become error events. */
  async sync(): Promise<SignetEvent[]> {
    this.directories.clear();
    this.forgetOldIds();
    await this.flushPending();
    await this.pullContacts();
    const events: SignetEvent[] = [];
    let lastAnswered: string[] = [];
    // Joining a thread registers its token, which can release deliveries the server parked; fetch again for those.
    for (let round = 0; round < 3; round += 1) {
      this.released = 0;
      const mailboxes = await this.readMailboxes();
      for (const { home, items } of mailboxes) {
        for (const item of items) {
          this.watch(item.id, home);
          this.state.cursors[home] = item.seq;
          this.state.cursor = item.seq;
          // The prefix keeps an id like __proto__ an ordinary key.
          const key = `id:${item.id}`;
          if (Object.hasOwn(this.state.seen, key)) continue;
          this.state.seen[key] = Date.now();
          if (this.state.sentIds.includes(item.id)) continue;
          try {
            events.push(...(await this.process(item)));
          } catch (error) {
            if (error instanceof NotReadableYet) this.state.held.push({ item, at: Date.now() });
            else events.push({ kind: 'error', item, error: describe(error) });
          }
        }
      }
      lastAnswered = mailboxes.map((mailbox) => mailbox.home);
      if (this.released === 0) break;
    }
    await this.acknowledgeMailboxes();
    events.push(...this.expireHeld());
    // A commit of ours that lost to another is recomputed against the winning epoch (Section 8.8 step 4).
    for (const thread of this.state.rekeyAgain.splice(0)) {
      if (this.state.threads.includes(thread)) await this.rekey(thread).catch(() => undefined);
    }
    events.push(...(await this.retryUnconfirmed()));
    events.push(...(await this.laggingHomes(lastAnswered)));
    await this.topUpKeyPackages();
    events.push(...this.state.keyChanges.splice(0), ...this.state.directoryAlerts.splice(0));
    return events;
  }

  /**
   * Check this address's history in the transparency log. Alerts for anything this device can't
   * account for: a different identity key, the address being unbound, or its own server locking it out.
   */
  async monitor(): Promise<MonitorReport> {
    this.directories.clear();
    const alerts: string[] = [];
    let own: Directory | null = null;
    try {
      own = await this.require(this.address);
    } catch (error) {
      if (describe(error).includes(' 401 ')) {
        alerts.push('your home server no longer accepts this client');
        this.direct = true;
        this.directories.clear();
        try {
          own = await this.require(this.address);
        } catch (retry) {
          if (!(retry instanceof IdentityChangedError)) throw retry;
          alerts.push(`${this.address} is now bound to an identity key you don't hold`);
        }
      } else if (error instanceof IdentityChangedError) {
        alerts.push(`${this.address} is now bound to an identity key you don't hold`);
      } else {
        throw error;
      }
    }
    try {
      return await this.checkHistory(own, alerts);
    } finally {
      this.direct = false;
    }
  }

  /**
   * Look up this address anonymously, as a stranger would, and compare. Catches a domain that tells
   * strangers a listed address is unlisted (to read first requests at its intake), or shows an unlisted
   * one, or shows strangers a different card. Senders cross-check "unlisted" the same way, so the domain
   * can't tell this check from theirs.
   */
  private async checkStrangerView(own: Directory, alerts: string[]): Promise<void> {
    const domain = splitAddress(this.address).domain;
    let seen: DirectoryEntry;
    try {
      seen = await this.anonymousEntry(this.address);
    } catch (error) {
      alerts.push(`couldn't check what strangers see: ${describe(error)}`);
      return;
    }
    if (own.log?.unlisted) {
      if (seen.status === 'enrolled') alerts.push(`${domain} shows ${this.address} to strangers, though it is unlisted`);
      return;
    }
    if (seen.status === 'unlisted') alerts.push(`${domain} tells strangers ${this.address} is unlisted, so their first requests would go through its intake, which can read them`);
    else if (seen.status === 'not-enrolled') alerts.push(`${domain} tells strangers ${this.address} is not on Signet`);
    else if (canonicalJson(seen.card.card) !== canonicalJson(own.card)) alerts.push(`${domain} shows strangers a different card for ${this.address}`);
  }

  private async checkHistory(own: Directory | null, alerts: string[]): Promise<MonitorReport> {
    if (own) await this.checkStrangerView(own, alerts);
    const identityKey = own?.identityKey ?? this.state.pins[this.address];
    // Keys this account rotated or recovered through are its own; only keys off the chain are alarming.
    const ownKeys = own ? cardKeyHistory(own.card).keys.map((entry) => entry.key) : [identityKey];
    const policy = await this.resolver.policy(splitAddress(this.address).domain);
    const log = this.trustedLog(policy);
    const entry = await this.directoryEntry(this.address);
    // An owner always gets its own entry; an unlisted answer here means its server is hiding it from it.
    if (entry.status === 'unlisted') throw new TransparencyError(`${this.address}'s own server answered that it is unlisted`);
    const index = entry.status === 'enrolled' ? verifyDirectoryEntry(entry, policy).index : verifyNotEnrolled(entry, policy);
    const { history, head } = (await this.transparency(log, 'history', { index, domain: splitAddress(this.address).domain })) as {
      history: { leaf: LogLeaf; proof: InclusionProof }[];
      head: TreeHead;
    };
    await this.checkTreeHead(log, head);
    for (const { leaf, proof } of history) {
      verifyLeaf(log, leaf, proof, head);
      checkLeafDomain(leaf, splitAddress(this.address).domain);
      if (leaf.kind === 'unbound') alerts.push(`${leaf.ts}: ${this.address} was unbound from its identity key`);
      else if (!ownKeys.includes(leaf.identityKey ?? '')) alerts.push(`${leaf.ts}: ${this.address} was bound to an identity key you don't hold`);
    }
    if (!own?.view) return { alerts, newClients: [] };
    const newClients = own.view.members
      .filter((member) => !this.state.knownOwnClients.includes(member.clientId))
      .map((member) => ({ clientId: member.clientId, kind: member.kind, label: own?.log?.clients.get(member.clientId)?.label }));
    this.state.knownOwnClients = own.view.members.map((member) => member.clientId);
    return { alerts, newClients };
  }

  private async process(item: MailItem): Promise<SignetEvent[]> {
    switch (item.kind) {
      case 'request':
        return this.onRequest(item.payload as SealedRequest);
      case 'welcome':
        return this.onWelcome(item.payload as WelcomePayload);
      case 'commit':
        return this.onCommit(item.payload as MlsPayload);
      case 'message':
        return this.onMessage(item.payload as MlsPayload);
      case 'legacy': {
        const sealed = item.payload as SealedLegacyMail;
        // No copy means the recipient's policy kept this client out (humans-only mail to an agent).
        return hasLegacyCopy(this.keys, sealed) ? [{ kind: 'legacy', mail: await this.onLegacy(sealed) }] : [];
      }
      case 'bounce': {
        const bounce = item.payload as { id: string; to: string[]; reason: string };
        return [{ kind: 'bounce', ...bounce }];
      }
      case 'receipt': {
        // A retry that landed after the send: the home that queued it passes on the recipient's receipt.
        const { id, receipts } = item.payload as { id: string; receipts: Receipt[] };
        const entry = this.state.unconfirmed.find((send) => send.id === id);
        if (entry) await this.confirm(entry, { receipts });
        return [];
      }
    }
  }

  private async onRequest(sealed: SealedRequest): Promise<SignetEvent[]> {
    if (!myCopy(this.keys, sealed)) return [];
    const request = await openRequest(this.keys, sealed, (address) => this.require(address));
    // Keep the view the sender presented, so accepting can add their clients without a directory grant.
    this.state.views[request.body.from] = request.body.senderView;
    this.directories.delete(request.body.from);
    const admission = await decideAdmission(this.state.admission, this.address, request, (address) => this.require(address));
    return [{ kind: 'request', request, admission }];
  }

  /** Join only if every member of the group is a current client in its owner's contact view. */
  private async onWelcome(payload: WelcomePayload): Promise<SignetEvent[]> {
    if (!payload.for.includes(joinerTag(this.keys.cert.clientId))) return [];
    let replaces = false;
    if (this.state.threads.includes(payload.thread)) {
      // A second welcome for a thread this client just joined: two commits competed. Keep the one that won (Section 8.8).
      const held = this.state.lastCommit[payload.thread];
      if (!held?.joined || payload.commit === undefined || payload.epoch === undefined || Date.now() - held.at > FORK_WINDOW_MS) return [];
      const wins = payload.epoch > this.mls.epoch(payload.thread) || (payload.epoch === this.mls.epoch(payload.thread) && Buffer.compare(Buffer.from(payload.commit, 'hex'), Buffer.from(held.hash, 'hex')) < 0);
      if (!wins) return [];
      replaces = true;
    }
    const taken = this.state.lastCommit[payload.thread];
    const preview = replaces && taken ? this.mls.peekWelcomeBefore(payload.welcome, taken.undo) : this.mls.peekWelcome(payload.welcome);
    if (preview.thread !== payload.thread) throw new Error('welcome is for a different thread than it claims');
    const humansOnly = payload.humansOnly === true;
    for (const member of preview.members) {
      const { member: current } = await this.checkMember(member);
      if (humansOnly && !current.humansOnly) throw new Error(`humans-only thread includes ${member.principal}'s agent, which its owner hasn't allowed`);
    }
    if (replaces && taken) {
      this.mls.rollback(taken.undo);
      this.state.threads = this.state.threads.filter((known) => known !== payload.thread);
      delete this.state.lastCommit[payload.thread];
    }
    const { thread, members, undo } = this.mls.joinUndoable(payload.welcome);
    if (payload.commit !== undefined) this.state.lastCommit[thread] = { hash: payload.commit, undo, at: Date.now(), own: false, joined: true };
    const meta: ThreadMeta = { humansOnly, ...(payload.linkedTo ? { linkedTo: payload.linkedTo } : {}) };
    this.state.threads.push(thread);
    this.state.threadMeta[thread] = meta;
    if (payload.linkedTo && this.state.threads.includes(payload.linkedTo)) this.state.siblings[payload.linkedTo] = thread;
    await this.registerCurrentToken(thread);
    return [{ kind: 'joined', thread, epoch: this.mls.epoch(thread), members, participants: await this.toParticipants(members), ...meta }];
  }

  /** Apply a commit only if its sender and every client it adds are current in their owners' views. */
  private async onCommit(payload: MlsPayload): Promise<SignetEvent[]> {
    if (!this.state.threads.includes(payload.thread)) return [];
    // Two members can commit from the same epoch: the smaller hash wins, and the client that applied the other
    // goes back to before it (Section 8.8). A commit that is not for the current epoch is looked at as if it were.
    const last = this.state.lastCommit[payload.thread];
    let preview: CommitPreview;
    let supersedes = false;
    try {
      preview = this.mls.previewCommit(payload.thread, payload.mls);
    } catch (error) {
      if (!last || Date.now() - last.at > FORK_WINDOW_MS) throw error;
      // A client that just joined has nothing from before its welcome to compare with: the other commit's welcome settles it.
      if (last.joined) return [];
      try {
        preview = this.mls.previewCommitBefore(payload.thread, payload.mls, last.undo);
      } catch {
        throw error;
      }
      if (Buffer.compare(commitHash(payload.mls), Buffer.from(last.hash, 'hex')) >= 0) return [];
      supersedes = true;
    }
    if (!preview.selfRemoved) {
      await this.checkMember(preview.sender);
      for (const member of preview.added) {
        const { member: current } = await this.checkMember(member);
        if (this.isHumansOnly(payload.thread) && !current.humansOnly) {
          throw new Error(`refusing a commit that adds ${member.principal}'s agent to a humans-only thread`);
        }
      }
    }
    if (supersedes && last) {
      this.mls.rollback(last.undo);
      delete this.state.lastCommit[payload.thread];
      if (last.own) this.state.rekeyAgain.push(payload.thread);
    }
    const applied = this.mls.applyCommitUndoable(payload.thread, payload.mls);
    this.state.lastCommit[payload.thread] = { hash: commitHash(payload.mls).toString('hex'), undo: applied.undo, at: Date.now(), own: false };
    if (applied.selfRemoved || !this.mls.isActive(payload.thread)) {
      this.state.threads = this.state.threads.filter((thread) => thread !== payload.thread);
      await this.registerTokens([], this.state.tokens[payload.thread] ?? []);
      delete this.state.tokens[payload.thread];
      return [{ kind: 'removed', thread: payload.thread }];
    }
    await this.registerCurrentToken(payload.thread);
    const members = this.mls.members(payload.thread);
    const base = { thread: payload.thread, epoch: this.mls.epoch(payload.thread), members, participants: await this.toParticipants(members), ...(this.state.threadMeta[payload.thread] ?? { humansOnly: false }) };
    return [...(supersedes ? [{ kind: 'fork-resolved' as const, ...base }] : []), { kind: 'rekeyed', ...base }, ...(await this.retryHeld(payload.thread))];
  }

  /** Messages that could not be read before this commit may be readable now (Section 8.8 step 3). */
  private async retryHeld(thread: string): Promise<SignetEvent[]> {
    const events: SignetEvent[] = [];
    const waiting = this.state.held;
    this.state.held = [];
    for (const entry of waiting) {
      if ((entry.item.payload as MlsPayload).thread !== thread) {
        this.state.held.push(entry);
        continue;
      }
      try {
        events.push(...(await this.process(entry.item)));
      } catch (error) {
        if (error instanceof NotReadableYet) this.state.held.push(entry);
        else events.push({ kind: 'error', item: entry.item, error: describe(error) });
      }
    }
    return events;
  }

  /** Held messages that no commit has made readable in the window are reported as errors (Section 8.8 step 5). */
  private expireHeld(): SignetEvent[] {
    const now = Date.now();
    const expired = this.state.held.filter((entry) => now - entry.at > FORK_WINDOW_MS);
    this.state.held = this.state.held.filter((entry) => now - entry.at <= FORK_WINDOW_MS);
    for (const thread of Object.keys(this.state.lastCommit)) if (now - this.state.lastCommit[thread].at > FORK_WINDOW_MS) delete this.state.lastCommit[thread];
    return expired.map((entry) => ({ kind: 'error' as const, item: entry.item, error: 'could not be decrypted: no commit arrived that makes it readable' }));
  }

  private async onMessage(payload: MlsPayload): Promise<SignetEvent[]> {
    if (!this.state.threads.includes(payload.thread)) return [];
    let decrypted: ReturnType<MlsSession['decrypt']>;
    try {
      decrypted = this.mls.decrypt(payload.thread, payload.mls);
    } catch (error) {
      // It may be for an epoch whose commit has not reached this client yet (Section 8.8 step 5).
      throw new NotReadableYet(error instanceof Error ? error.message : String(error));
    }
    const { sender, plaintext } = decrypted;
    const { directory, member } = await this.checkMember(sender);
    const message = JSON.parse(plaintext.toString('utf8')) as SignedMessage;
    verifyMessage(message, payload.thread, directory, member, this.address);
    // Once a thread is handed to an account's human, that account's agents and tools may only hand off again (Section 12.6).
    const held = this.state.needsHuman[payload.thread];
    if (held && member.kind !== 'device' && message.body.from === held.by && !(message.body.intents.length > 0 && message.body.intents.every((intent) => intent.name.startsWith('handoff.human')))) {
      throw new Error(`${held.by} handed this thread to a human, so its agents may not send in it`);
    }
    if (message.body.profile?.label) this.state.labels[member.clientId] = message.body.profile.label.slice(0, 64);
    const html = message.body.html;
    const events: SignetEvent[] = [
      {
        kind: 'message',
        thread: payload.thread,
        message,
        sender: this.summary(directory, member),
        ...(html === undefined
          ? {}
          : { safeHtml: sanitizeHtml(html, message.body.attachments.flatMap((attachment) => (attachment.cid ? [attachment.cid] : []))), divergent: textDiverges(message.body.text, html) }),
      },
    ];
    for (const intent of message.body.intents) {
      if (intent.name.startsWith('session.end')) delete this.state.liveSessions[intent.args.sessionId as string];
      if (intent.name.startsWith('handoff.human')) {
        this.handOff(payload.thread, message.body.from, intent.args.reason as string);
        if (message.body.from === this.address) events.push({ kind: 'handoff', thread: payload.thread, by: message.body.from, reason: intent.args.reason as string });
      }
    }
    // A human from the account that was handed the thread has replied: agents may carry on.
    const handedTo = this.state.needsHuman[payload.thread];
    if (handedTo && member.kind === 'device' && message.body.from === handedTo.by && !message.body.intents.some((i) => i.name.startsWith('handoff.human'))) {
      delete this.state.needsHuman[payload.thread];
    }
    return events;
  }

  private async onLegacy(sealed: SealedLegacyMail): Promise<LegacyMail> {
    const raw = await openLegacyMail(this.keys, sealed);
    const parsed = await simpleParser(raw);
    const from = parsed.from?.value[0]?.address ?? sealed.envelopeFrom;
    const to = (Array.isArray(parsed.to) ? parsed.to : parsed.to ? [parsed.to] : []).flatMap((group) => group.value.map((entry) => entry.address ?? ''));
    const signet = await this.checkSignetHeader(
      { from, to, subject: parsed.subject ?? '', bodyHash: hashBody(parsed.text ?? ''), ...(typeof parsed.html === 'string' ? { htmlHash: hashBody(parsed.html) } : {}), ...(isHumansOnly(raw) ? { audience: 'humans' as const } : {}) },
      parsed.headers.get(SIGNET_HEADER.toLowerCase())?.toString(),
    );
    const lookalike = lookalikeOf(splitAddress(from).domain, knownDomains(this.state.admission, this.address)) ?? undefined;
    const trusted = sealed.auth.dmarc === 'pass' && isTrusted(this.state.admission, this.address, from) !== null;
    return {
      from,
      subject: parsed.subject ?? '',
      text: parsed.text ?? '',
      ...(typeof parsed.html === 'string' ? { html: sanitizeHtml(parsed.html, []) } : {}),
      date: parsed.date?.toISOString() ?? null,
      auth: sealed.auth,
      tier: trusted && !lookalike ? 'inbox' : 'request',
      signet,
      ...(lookalike ? { lookalike } : {}),
      humansOnly: parsed.headers.get(AUDIENCE_HEADER.toLowerCase())?.toString().trim().toLowerCase() === 'humans',
      attachments: parsed.attachments.map((a) => ({ filename: a.filename ?? 'attachment', contentType: a.contentType, size: a.size })),
    };
  }

  private summary(directory: Directory, member: ViewMember): ClientSummary {
    const label = this.state.labels[member.clientId] ?? directory.log?.clients.get(member.clientId)?.label;
    return { clientId: member.clientId, kind: member.kind, ...(label ? { label } : {}) };
  }

  private async toParticipants(members: Member[]): Promise<Participant[]> {
    const people = new Map<string, Participant>();
    for (const member of members) {
      const directory = await this.cachedLookup(member.principal).catch(() => null);
      const current = viewMember(directory?.view, member.clientId);
      const person = people.get(member.principal) ?? { principal: member.principal, clients: [] };
      person.clients.push(directory && current ? this.summary(directory, current) : { clientId: member.clientId, kind: 'device' });
      people.set(member.principal, person);
    }
    // Yourself last, so the list reads as "who you're talking to".
    return [...people.values()].sort((a, b) => Number(a.principal === this.address) - Number(b.principal === this.address));
  }

  private async checkMember(member: Member): Promise<{ directory: Directory; member: ViewMember }> {
    const directory = await this.require(member.principal);
    const current = viewMember(directory.view, member.clientId);
    if (!current || current.sigKey !== member.signatureKey) throw new Error(`${member.principal}/${member.clientId} is not a current client`);
    return { directory, member: current };
  }

  private cachedLookup(address: string): Promise<Directory | null> {
    const who = normalizeAddress(address);
    let pending = this.directories.get(who);
    if (!pending) {
      pending = this.fetchDirectory(who);
      this.directories.set(who, pending);
      pending.catch(() => this.directories.delete(who));
    }
    return pending;
  }

  private async fetchDirectory(who: string): Promise<Directory | null> {
    const policy = await this.resolver.policy(splitAddress(who).domain);
    const log = this.trustedLog(policy);
    await this.checkDomainKey(policy, log);
    let entry = await this.directoryEntry(who);
    const pinned = this.state.pins[who];

    let fromCard = false;
    if (entry.status === 'unlisted') {
      // Nothing to check against the log: the answer is the same whether or not the address exists.
      verifyUnlisted(entry, policy);
      fromCard = this.state.contactCards[who] !== undefined;
      entry = await this.resolveUnlisted(who);
    }

    if (entry.status === 'not-enrolled') {
      const index = verifyNotEnrolled(entry, policy);
      const latest = await this.latestLeaf(log, index, splitAddress(who).domain);
      if (latest.leaf?.kind === 'bound') throw new TransparencyError(`${who} is enrolled according to the log, but its server says it is not`);
      if (pinned) {
        if (latest.leaf?.kind !== 'unbound') throw new IdentityChangedError(who, pinned, null);
        delete this.state.pins[who];
      }
      return null;
    }

    try {
      return await this.acceptEnrolled(who, entry, policy, log);
    } catch (error) {
      if (fromCard && error instanceof TransparencyError) throw new HiddenAddressError(who, 'your contact card for it is out of date');
      throw error;
    }
  }

  /**
   * An "unlisted" answer, seen through the home server. Use the person's contact card if we hold one.
   * Otherwise ask again anonymously: a domain hiding the address from servers would have to hide it there
   * too, where the owner checks (see `monitor`). Refuse the intake for addresses we already know are on Signet.
   */
  private async resolveUnlisted(who: string): Promise<EnrolledEntry> {
    const card = this.state.contactCards[who];
    if (card) return card;
    const domain = splitAddress(who).domain;
    const anonymous = await this.anonymousEntry(who).catch(() => null);
    if (anonymous?.status === 'enrolled') {
      this.state.directoryAlerts.push({ kind: 'directory-alert', principal: who, alert: `${domain} told your server ${who} is unlisted, but shows it to anonymous lookups` });
      return anonymous;
    }
    if (anonymous?.status === 'not-enrolled') throw new HiddenAddressError(who, 'its domain gives anonymous lookups a different answer');
    if (this.state.pins[who]) throw new HiddenAddressError(who, 'you have its key pinned');
    if (this.state.knownOnSignet[who]) throw new HiddenAddressError(who, 'it sent you email with an authenticated Signet header');
    throw new UnlistedAddressError(who);
  }

  /**
   * A directory read as a stranger would see it: no signature, and through the OHTTP relay when one is
   * configured, so the domain sees neither this client nor its server.
   */
  private async anonymousEntry(who: string): Promise<DirectoryEntry> {
    const { local, domain } = splitAddress(who);
    const policy = await this.resolver.policy(domain);
    const path = `/v0/directory/${encodeURIComponent(local)}`;
    // Any home of the domain can answer; try them in the policy's order.
    let failure: unknown;
    for (const base of policy.operators ? (policy.replicas ?? [policy.server]) : [policy.server]) {
      try {
        return await this.anonymousAt(base, domain, policy, path);
      } catch (error) {
        failure = error;
      }
    }
    throw failure;
  }

  private async anonymousAt(base: string, domain: string, policy: DomainPolicy, path: string): Promise<DirectoryEntry> {
    const gateway = homeGateway(policy, base);
    if (!this.ohttpRelay || !gateway) return (await this.getJson(`${base}${path}`)) as DirectoryEntry;
    const inner = encodeRequest({ method: 'GET', scheme: 'https', authority: new URL(base).host, path, headers: [], body: Buffer.alloc(0) });
    const { message, pending } = await encapsulateRequest(gateway.keys, inner);
    const relayed = await this.fetchImpl(`${this.ohttpRelay}/v0/relay?domain=${encodeURIComponent(domain)}&home=${encodeURIComponent(base)}`, {
      method: 'POST',
      headers: { 'content-type': OHTTP_REQUEST_TYPE },
      body: message,
    });
    if (!relayed.ok) throw new Error(`relay refused: ${relayed.status} ${await relayed.text()}`);
    const response = decodeResponse(decapsulateResponse(pending, Buffer.from(await relayed.arrayBuffer())));
    if (response.status !== 200) throw new Error(`anonymous lookup failed: ${response.status}`);
    return JSON.parse(Buffer.from(response.body).toString('utf8')) as DirectoryEntry;
  }

  /** This account's own entry as a contact card, to hand out as a link or QR code. */
  async contactCard(): Promise<string> {
    const entry = await this.directoryEntry(this.address);
    if (entry.status !== 'enrolled') throw new Error(`${this.address} is not enrolled`);
    const { status, principal, binding, card, vrf } = entry;
    return contactCardLink({ status, principal, binding, card, vrf });
  }

  /** Check someone's contact card against the log and keep it, so they stay reachable directly. */
  async importContactCard(link: string): Promise<Directory> {
    const card = parseContactCard(link);
    const who = normalizeAddress(card.principal);
    const policy = await this.resolver.policy(splitAddress(who).domain);
    const directory = await this.acceptEnrolled(who, card, policy, this.trustedLog(policy));
    this.state.contactCards[who] = card;
    return directory;
  }

  /** Check an enrolled entry against the domain key, the VRF and the log's latest leaf, then pin it. */
  private async acceptEnrolled(who: string, entry: EnrolledEntry | ContactCard, policy: DomainPolicy, log: TrustedLog): Promise<Directory> {
    const pinned = this.state.pins[who];
    const verified = verifyDirectoryEntry(entry, policy);
    const { leaf } = await this.latestLeaf(log, verified.index, splitAddress(who).domain);
    const shown = 'view' in entry ? entry.view : undefined;
    const viewMatches = !shown || leaf?.viewHash === viewHash(shown);
    if (!leaf || leaf.kind !== 'bound' || leaf.identityKey !== verified.identityKey || leaf.cardHash !== cardHash(entry.card) || !viewMatches) {
      throw new TransparencyError(`directory entry for ${who} does not match the transparency log`);
    }
    if (pinned && pinned !== verified.identityKey) {
      // Follow the chain on the card from the key we pinned. Anything else is a rebinding by the domain.
      const how = keyChangeSince(cardKeyHistory(verified.card), pinned);
      if (!how) throw new IdentityChangedError(who, pinned, verified.identityKey);
      if (who !== this.address || how === 'recovered') this.state.keyChanges.push({ kind: 'key-changed', principal: who, how, from: pinned, to: verified.identityKey });
    }
    this.state.pins[who] = verified.identityKey;
    const directory: Directory = { ...verified, viewHash: leaf.viewHash };
    if (shown) {
      this.state.views[who] = shown;
    } else {
      // A view the person presented earlier still counts while it's the one the log holds.
      const presented = this.state.views[who];
      if (presented && viewHash(presented) === leaf.viewHash) directory.view = verifyView(presented, who, verified.identityKey);
    }
    return directory;
  }

  private async latestLeaf(log: TrustedLog, index: string, domain: string): Promise<LatestLeaf> {
    const latest = (await this.transparency(log, 'latest', { index, domain })) as LatestLeaf;
    checkLeafDomain(latest.leaf, domain);
    await this.checkTreeHead(log, latest.head);
    if (latest.leaf && latest.proof) verifyLeaf(log, latest.leaf, latest.proof, latest.head);
    return latest;
  }

  /**
   * Where a request to `address` is sealed: its own request keys, or for an unlisted (or nonexistent)
   * address, the domain's intake key. The intake can read the request; the thread after it is end to end.
   */
  private async recipientFor(address: string): Promise<{ principal: string; card: Pick<Directory['card'], 'requestKeys' | 'humanKeys'> }> {
    try {
      return await this.require(address);
    } catch (error) {
      if (!(error instanceof UnlistedAddressError)) throw error;
      const policy = await this.resolver.policy(splitAddress(error.principal).domain);
      if (!policy.intake) throw error;
      await this.checkDomainKey(policy, this.trustedLog(policy));
      return { principal: error.principal, card: { requestKeys: [policy.intake], humanKeys: [policy.intake] } };
    }
  }

  private async require(address: string): Promise<Directory> {
    const directory = await this.cachedLookup(address);
    if (!directory) throw new Error(`${address} is not enrolled in Signet`);
    return directory;
  }

  /** This account's own signed contact view, which it presents in requests and introductions. */
  private async ownView(): Promise<SignedView> {
    await this.require(this.address);
    const view = this.state.views[this.address];
    if (!view) throw new Error('home server did not return this account’s contact view');
    return view;
  }

  /** Let these people's servers fetch this account's contact view from now on. */
  private async releaseView(to: string[]): Promise<void> {
    const others = to.filter((address) => normalizeAddress(address) !== this.address);
    if (others.length > 0) await this.callEach('POST', '/v0/contacts/grant', { add: others.map(requesterHash) });
  }

  /**
   * A domain key this client has not seen is checked against the domain-key leaf in the log the policy names
   * before the policy is used (Section 6.5). A key the log does not record is refused.
   */
  private async checkDomainKey(policy: DomainPolicy, log: TrustedLog): Promise<void> {
    if (this.state.domainKeys[policy.domain] === policy.domainKey) return;
    const { leaf } = await this.latestLeaf(log, domainKeyIndex(policy.domain), policy.domain);
    if (leaf?.kind !== 'domain-key' || leaf.domainKey !== policy.domainKey) {
      throw new TransparencyError(`${policy.domain}'s domain key is not the one its transparency log records`);
    }
    this.state.domainKeys[policy.domain] = policy.domainKey;
  }

  private trustedLog(policy: DomainPolicy): TrustedLog {
    const log = this.options.trustedLogs.find((candidate) => candidate.url === policy.log.url && candidate.key === policy.log.key);
    if (!log) throw new TransparencyError(`${policy.domain} writes to a transparency log this client does not trust`);
    return log;
  }

  private async directoryEntry(who: string): Promise<DirectoryEntry> {
    if (!this.direct) {
      // A lookup in another domain carries proof that this client is the requester it names, so the target
      // releases its contact view to the right person only (Section 4.7).
      const headers = splitAddress(who).domain === splitAddress(this.address).domain ? undefined : { 'signet-requester': await this.requesterProof(who) };
      return (await this.call('GET', `/v0/lookup?address=${encodeURIComponent(who)}`, undefined, headers)) as DirectoryEntry;
    }
    const { local, domain } = splitAddress(who);
    const { server } = await this.resolver.policy(domain);
    return (await this.getJson(`${server}/v0/directory/${encodeURIComponent(local)}`)) as DirectoryEntry;
  }

  /** Proof for a lookup of `target`. The log is fetched each time: a cached copy would not match the card once a client is enrolled. */
  private async requesterProof(target: string): Promise<string> {
    const own = (await this.call('GET', `/v0/lookup?address=${encodeURIComponent(this.address)}`)) as EnrolledEntry;
    if (!own.log) throw new Error('home server did not return this account’s log');
    return signRequesterProof(this.keys, this.address, own.log, target);
  }

  /** Log queries go through the home server, which authenticates to the log as its domain. */
  private transparency(log: TrustedLog, op: 'latest' | 'history' | 'consistency', params: Record<string, string | number>): Promise<unknown> {
    const values = Object.fromEntries(Object.entries(params).map(([k, v]) => [k, String(v)]));
    if (this.direct) {
      const query = new URLSearchParams(op === 'consistency' ? values : { key: values.index, domain: values.domain });
      return this.getJson(`${log.url}/v0/${op}?${query.toString()}`);
    }
    return this.call('GET', `/v0/transparency/${op}?${new URLSearchParams({ log: log.url, ...values }).toString()}`);
  }

  /** Every tree head must extend the last one this client saw from that log, or the log has forked. */
  private async checkTreeHead(log: TrustedLog, head: TreeHead): Promise<void> {
    if (!verifyTreeHead(log.key, head)) throw new TransparencyError('tree head is not signed by the log');
    if (Date.now() - Date.parse(head.ts) > (this.options.maxHeadAgeMs ?? 24 * 3_600_000)) throw new TransparencyError('tree head is too old');
    const { witnesses } = this.options;
    if (witnesses && countCosignatures(log.key, head, witnesses.keys) < witnesses.threshold) {
      throw new TransparencyError(`tree head has fewer than ${witnesses.threshold} witness cosignatures`);
    }
    const previous = this.state.treeHeads[log.url];
    if (previous && previous.size === head.size && previous.root !== head.root) {
      throw new TransparencyError('log forked: two different trees of the same size');
    }
    if (previous && previous.size < head.size) {
      const { path } = (await this.transparency(log, 'consistency', { first: previous.size, second: head.size })) as { path: string[] };
      if (!verifyConsistency(previous.size, head.size, fromB64u(previous.root), fromB64u(head.root), path)) {
        throw new TransparencyError('log forked: the new tree head does not extend the last one seen');
      }
    }
    if (!previous || previous.size < head.size) this.state.treeHeads[log.url] = head;
  }

  private async claim(principal: string, members: ViewMember[]): Promise<Addition[]> {
    if (members.length === 0) return [];
    const { packages } = (await this.call('POST', '/v0/claim', { address: principal, clients: members.map((member) => member.clientId) })) as {
      packages: ClaimedKeyPackage[];
    };
    return packages.flatMap((claimed) => {
      const member = members.find((candidate) => candidate.clientId === claimed.clientId);
      return member ? [{ cert: { principal, clientId: member.clientId, sigKey: member.sigKey }, claimed }] : [];
    });
  }

  private async topUpKeyPackages(): Promise<void> {
    if (!this.keys.cert.scopes.some((scope) => scope === 'read:*')) return;
    const target = this.options.keyPackageTarget ?? 5;
    // Every home keeps its own pool, so each is topped up.
    await this.eachHome(async (home) => {
      const { count, lastResort } = (await this.request(home, 'GET', '/v0/keypackages/count')) as { count: number; lastResort: boolean };
      const packages = Array.from({ length: Math.max(0, target - count) }, () => ({ kpId: randomId('kp'), keyPackage: this.mls.keyPackage(false) }));
      const fallback = lastResort ? undefined : { kpId: randomId('kp'), keyPackage: this.mls.keyPackage(true) };
      if (packages.length > 0 || fallback) await this.request(home, 'POST', '/v0/keypackages', { packages, lastResort: fallback });
    });
  }

  /** One token bound to the recipient's domain, blinded so neither the issuer nor this client's server can link it. */
  private async privacyPassToken(policy: DomainPolicy): Promise<string> {
    if (!policy.privacyPass) throw new Error(`${policy.domain} does not accept anonymous requests`);
    const issuer = (await this.call('GET', '/v0/issuer')) as IssuerKey;
    if (issuer.name !== policy.privacyPass.issuer) {
      throw new Error(`${policy.domain} accepts tokens from ${policy.privacyPass.issuer}; this server attests for ${issuer.name}`);
    }
    const pending = blindTokenRequest(issuer, policy.domain);
    const { signatures } = (await this.call('POST', '/v0/tokens', { blinded: [pending.blinded] })) as { signatures: string[] };
    return finalizeToken(pending, signatures[0]);
  }

  /** The current epoch's delivery token: an exporter secret only current members can derive. */
  private deliveryToken(thread: string): string {
    return b64u(this.mls.exportSecret(thread, DELIVERY_LABEL));
  }

  private async registerCurrentToken(thread: string): Promise<void> {
    const hash = deliveryTokenHash(this.deliveryToken(thread), this.address);
    const registered = this.state.tokens[thread] ?? [];
    if (registered.includes(hash)) return;
    registered.push(hash);
    const expired = registered.length > TOKEN_EPOCHS_KEPT ? registered.splice(0, registered.length - TOKEN_EPOCHS_KEPT) : [];
    this.state.tokens[thread] = registered;
    await this.registerTokens([hash], expired);
  }

  private async registerTokens(add: string[], remove: string[]): Promise<void> {
    if (add.length === 0 && remove.length === 0) return;
    for (const result of await this.callEach('POST', '/v0/delivery-tokens', { add, remove })) this.released += (result as { released?: number }).released ?? 0;
  }

  private async upload(file: FileInput): Promise<AttachmentRef> {
    const { blob, ref } = sealAttachment(file);
    // The message names where the ciphertext is, so it goes to every home: one operator being down or
    // withholding must not cost the reader the file.
    const urls = await this.eachHome(async (home) => ((await this.request(home, 'POST', '/v0/blobs', blob)) as { url: string }).url);
    return { ...ref, url: urls[0], ...(urls.length > 1 ? { mirrors: urls.slice(1) } : {}) };
  }

  private thread(thread: string): string {
    if (!this.state.threads.includes(thread)) throw new Error(`not a member of thread ${thread}`);
    return thread;
  }

  private principalsOf(people: { principal: string }[]): string[] {
    return unique(people.map((person) => person.principal));
  }

  /** With a token the delivery is sealed; with an anonymous token the request carries no sender. */
  private async submit(to: string[], kind: MailKind, payload: unknown, token?: string, anonymousToken?: string): Promise<void> {
    // The client picks the id, so a send repeated through another home after a lost answer is recognised.
    const body = { id: randomId('i'), to, kind, payload, token, anonymousToken };
    const { result, home } = await this.callFrom('POST', '/v0/submit', body);
    const { id } = result as { id: string };
    this.state.sentIds = [...this.state.sentIds, id].slice(-SENT_IDS_KEPT);
    // Our own home says it delivered. Only the recipients' homes can prove it.
    const entry: UnconfirmedSend = { id, to: [...to], body, at: Date.now(), tries: 0, via: home };
    this.state.unconfirmed = [...this.state.unconfirmed, entry].slice(-UNCONFIRMED_KEPT);
    await this.confirm(entry, result as { unknown?: string[]; rejected?: string[]; receipts?: Receipt[] });
  }

  private async getJson(url: string): Promise<unknown> {
    const response = await this.fetchImpl(url);
    if (!response.ok) throw new Error(`GET ${url} failed: ${response.status} ${await response.text()}`);
    return response.json();
  }

  /**
   * Open a pairing slot on the home server so a new client can enroll with a code (see enrollment.ts).
   * Returns the code to show, and this side's channel. Only a device can do this.
   */
  async openPairing(): Promise<{ code: string; channel: PairingChannel; expires: string }> {
    const { slot, expires } = (await this.call('POST', '/v0/pairing', {})) as { slot: string; expires: string };
    const { server } = await this.resolver.policy(splitAddress(this.address).domain);
    const auth = (method: string, path: string, body: string) => clientAuthHeaders(this.address, this.keys.cert.clientId, this.keys.signing, method, path, body);
    return { code: pairingCode(slot, newPairingSecret()), channel: new HttpPairingChannel(server, slot, 'a', auth, this.fetchImpl), expires };
  }

  /** The homes of this client's own domain, the one that last answered first. One home for any domain without a signed list. */
  private async homeBases(): Promise<string[]> {
    const policy = await this.resolver.policy(splitAddress(this.address).domain);
    const bases = policy.operators ? (policy.replicas ?? [policy.server]) : [policy.server];
    return this.preferredHome && bases.includes(this.preferredHome) ? [this.preferredHome, ...bases.filter((base) => base !== this.preferredHome)] : bases;
  }

  private preferredHome?: string;

  private async request(base: string, method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown, extra?: Record<string, string>): Promise<unknown> {
    const binary = body instanceof Uint8Array;
    const payload = body === undefined ? '' : binary ? body : JSON.stringify(body);
    const headers = {
      ...clientAuthHeaders(this.address, this.keys.cert.clientId, this.keys.signing, method, path, payload),
      ...(body === undefined ? {} : { 'content-type': binary ? 'application/octet-stream' : 'application/json' }),
      ...extra,
    };
    const response = await this.fetchImpl(`${base}${path}`, { method, headers, body: body === undefined ? undefined : payload });
    if (!response.ok) throw new Error(`${method} ${path} failed: ${response.status} ${await response.text()}`);
    return response.json();
  }

  /** Run `act` at every home, ignoring the ones that fail; throws only if every home did. */
  private async eachHome<T>(act: (home: string) => Promise<T>): Promise<T[]> {
    const results: T[] = [];
    let failure: unknown;
    for (const home of await this.homeBases()) {
      try {
        results.push(await act(home));
      } catch (error) {
        failure = error;
      }
    }
    if (results.length === 0) throw failure;
    return results;
  }

  /**
   * Tell each home how far this client has read, so it can delete what every reading client has (Section 10.7).
   * It runs after the items were processed. A home that fails is told again at the next sync.
   */
  private async acknowledgeMailboxes(): Promise<void> {
    for (const home of await this.homeBases()) {
      const through = this.state.cursors[home] ?? 0;
      if (through === 0 || through <= (this.acked[home] ?? 0)) continue;
      try {
        await this.request(home, 'POST', '/v0/mailbox/ack', { through, ...(this.state.epochs[home] ? { epoch: this.state.epochs[home] } : {}) });
        this.acked[home] = through;
      } catch {
        // The next sync tries again.
      }
    }
  }

  private readonly acked: Record<string, number> = {};

  /** The mailbox of every home, each from its own cursor. A home that doesn't answer is skipped. */
  private async readMailboxes(): Promise<{ home: string; items: MailItem[] }[]> {
    const bases = await this.homeBases();
    return this.eachHome(async (home) => {
      const cursor = this.state.cursors[home] ?? (bases.length === 1 ? this.state.cursor : 0);
      const known = this.state.epochs[home];
      const { items, epoch } = (await this.request(home, 'GET', `/v0/mailbox?after=${cursor}${known ? `&epoch=${encodeURIComponent(known)}` : ''}`)) as { items: MailItem[]; epoch?: string };
      // The home started over: it has answered from the start, and our cursor was into a mailbox that is gone.
      if (epoch && known && epoch !== known) this.state.cursors[home] = 0;
      if (epoch) this.state.epochs[home] = epoch;
      return { home, items };
    });
  }

  /** A call to the first home that answers. */
  private async call(method: 'GET' | 'POST', path: string, body?: unknown, extra?: Record<string, string>): Promise<unknown> {
    let failure: unknown;
    for (const home of await this.homeBases()) {
      try {
        const result = await this.request(home, method, path, body, extra);
        this.preferredHome = home;
        return result;
      } catch (error) {
        failure = error;
      }
    }
    throw failure;
  }

  /**
   * A call to every home, for state each of them keeps: tokens, contacts and grants. A home that fails gets the
   * call again at the next sync. Throws only if every home failed.
   */
  private async callEach(method: 'GET' | 'POST', path: string, body?: unknown): Promise<unknown[]> {
    const results: unknown[] = [];
    const failed: string[] = [];
    let failure: unknown;
    for (const home of await this.homeBases()) {
      try {
        results.push(await this.request(home, method, path, body));
      } catch (error) {
        failed.push(home);
        failure = error;
      }
    }
    if (results.length === 0) throw failure;
    if (method === 'POST' && body !== undefined && !(body instanceof Uint8Array)) {
      for (const home of failed) this.state.pending.push({ home, path, body });
      this.state.pending = this.state.pending.slice(-PENDING_KEPT);
    }
    return results;
  }

  /**
   * A call to the first home that answers, other than `avoid` unless it is the only one. Says which home answered.
   */
  private async callFrom(method: 'GET' | 'POST', path: string, body?: unknown, avoid?: string): Promise<{ result: unknown; home: string }> {
    const bases = await this.homeBases();
    const order = avoid ? [...bases.filter((base) => base !== avoid), ...bases.filter((base) => base === avoid)] : bases;
    let failure: unknown;
    for (const home of order) {
      try {
        const result = await this.request(home, method, path, body);
        this.preferredHome = home;
        return { result, home };
      } catch (error) {
        failure = error;
      }
    }
    throw failure;
  }

  /**
   * Count what a send has been proved to reach. An address the server said is unknown or refused is settled; so
   * is one a valid receipt names. A home vouching for a delivery to its own domain through its own mouth doesn't
   * count: it is the home that might have dropped it.
   */
  private async confirm(entry: UnconfirmedSend, result: { unknown?: string[]; rejected?: string[]; receipts?: Receipt[] }): Promise<void> {
    const settled = new Set([...(result.unknown ?? []), ...(result.rejected ?? [])].map(normalizeAddress));
    const ownDomain = splitAddress(this.address).domain;
    for (const receipt of result.receipts ?? []) {
      try {
        const policy = await this.resolver.policy(receipt.body.domain);
        if (!verifyReceipt(receipt, policy, entry.id)) continue;
        const viaKey = policy.operators?.body.homes.find((home) => new URL(home.url).origin === new URL(entry.via).origin)?.key;
        if (receipt.body.domain === ownDomain && receipt.body.home !== undefined && receipt.body.home === viaKey) continue;
        for (const address of [...receipt.body.to, ...receipt.body.held]) settled.add(normalizeAddress(address));
      } catch {
        // A receipt we can't check is no receipt.
      }
    }
    entry.to = entry.to.filter((address) => !settled.has(normalizeAddress(address)));
    if (entry.to.length === 0) this.state.unconfirmed = this.state.unconfirmed.filter((send) => send !== entry && send.id !== entry.id);
  }

  /** Send again, through a different home, what no recipient home has proved it got; report what still can't be. */
  private async retryUnconfirmed(): Promise<SignetEvent[]> {
    const events: SignetEvent[] = [];
    const grace = this.options.receiptGraceMs ?? 300_000;
    const retries = this.options.receiptRetries ?? 3;
    for (const entry of [...this.state.unconfirmed]) {
      if (Date.now() - entry.at < grace) continue;
      if (entry.tries >= retries) {
        events.push({ kind: 'delivery-unconfirmed', id: entry.id, to: entry.to });
        this.state.unconfirmed = this.state.unconfirmed.filter((send) => send.id !== entry.id);
        continue;
      }
      entry.tries += 1;
      entry.at = Date.now();
      try {
        const { result, home } = await this.callFrom('POST', '/v0/submit', { ...entry.body, to: entry.to }, entry.via);
        entry.via = home;
        await this.confirm(entry, result as { unknown?: string[]; rejected?: string[]; receipts?: Receipt[] });
      } catch {
        // No home answered; try again at the next sync.
      }
    }
    return events;
  }

  /** Drop processed ids older than thirty days, and the oldest beyond the cap. */
  private forgetOldIds(): void {
    const cutoff = Date.now() - SEEN_MAX_AGE_MS;
    const entries = Object.entries(this.state.seen);
    for (const [key, at] of entries) if (at < cutoff) delete this.state.seen[key];
    if (entries.length <= SEEN_MAX) return;
    for (const [key] of entries.sort((a, b) => a[1] - b[1]).slice(0, entries.length - SEEN_MAX)) delete this.state.seen[key];
  }

  /** Repeat registrations that a home missed, oldest first, and keep the ones that still can't be delivered. */
  private async flushPending(): Promise<void> {
    if (this.state.pending.length === 0) return;
    const stuck: ClientSnapshot['pending'] = [];
    const blocked = new Set<string>();
    for (const entry of this.state.pending) {
      if (blocked.has(entry.home)) {
        stuck.push(entry);
        continue;
      }
      try {
        await this.request(entry.home, 'POST', entry.path, entry.body);
      } catch {
        blocked.add(entry.home);
        stuck.push(entry);
      }
    }
    this.state.pending = stuck;
  }

  /** Note that `home` had the item, for comparing homes (Section 6.9.6). */
  private watch(id: string, home: string): void {
    const entry = (this.state.homeWatch[id] ??= { homes: [], at: Date.now() });
    if (!entry.homes.includes(home)) entry.homes.push(home);
  }

  /** Homes that answered this sync but still lack an item others delivered, once the grace period has passed. */
  private async laggingHomes(answered: string[]): Promise<SignetEvent[]> {
    const events: SignetEvent[] = [];
    const bases = await this.homeBases();
    const now = Date.now();
    const grace = this.options.homeGraceMs ?? 600_000;
    for (const [id, entry] of Object.entries(this.state.homeWatch)) {
      // Done once every home has it; forgotten once too old to matter.
      if (bases.every((home) => entry.homes.includes(home)) || now - entry.at > WATCH_MAX_AGE_MS) {
        delete this.state.homeWatch[id];
        continue;
      }
      if (!entry.alerted && now - entry.at >= grace) {
        entry.alerted = true;
        for (const home of answered) if (!entry.homes.includes(home)) events.push({ kind: 'home-missing', home, itemId: id });
      }
    }
    const ids = Object.keys(this.state.homeWatch);
    for (const id of ids.slice(0, Math.max(0, ids.length - WATCH_KEPT))) delete this.state.homeWatch[id];
    return events;
  }
}

/**
 * Every device is gone and so is the identity key: prove the recovery key to the home server and get the
 * last published log back, to sign a recovery entry onto with `Identity.recover`.
 */
export async function fetchRecoverableLog(server: string, principal: string, recovery: KeyPair, fetchImpl: typeof fetch = fetch): Promise<LogEntry[]> {
  const local = splitAddress(principal).local;
  const response = await fetchImpl(`${server}/v0/recovery/${encodeURIComponent(local)}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(recoveryProof(principal, recovery)),
  });
  if (!response.ok) throw new Error(`recovery refused: ${response.status} ${await response.text()}`);
  return ((await response.json()) as { entries: LogEntry[] }).entries;
}

/**
 * After the identity holder approved this client's enrollment request (from a QR code or link), fetch
 * its certificate from the home server: the client can already authenticate with its new key, and its
 * owner access returns the log the certificate is in.
 */
export async function fetchApprovedCert(resolver: Resolver, pending: PendingClient, fetchImpl: typeof fetch = fetch): Promise<ClientKeys> {
  const { principal, clientId } = pending.request.body;
  const { server } = await resolver.policy(splitAddress(principal).domain);
  const path = `/v0/lookup?address=${encodeURIComponent(principal)}`;
  const response = await fetchImpl(`${server}${path}`, { headers: clientAuthHeaders(principal, clientId, pending.signing, 'GET', path, '') });
  if (response.status === 401) throw new EnrollmentError('not approved yet');
  if (!response.ok) throw new Error(`lookup failed: ${response.status} ${await response.text()}`);
  const entry = (await response.json()) as DirectoryEntry;
  const cert = entry.status === 'enrolled' && entry.log ? replayLog(entry.log).clients.get(clientId) : undefined;
  if (!cert) throw new EnrollmentError('not approved yet');
  return completeEnrollment(pending, cert);
}

/** The new client's side of pairing with a code: find the address's home server and pair through it. */
export async function joinPairing(
  resolver: Resolver,
  principal: string,
  code: string,
  options: { kind: ClientKind; label: string; scopes: string[]; limits?: Record<string, number> },
  onRequest?: (fingerprint: string) => void,
  fetchImpl: typeof fetch = fetch,
): Promise<ClientKeys> {
  const { server } = await resolver.policy(splitAddress(principal).domain);
  const channel = new HttpPairingChannel(server, parsePairingCode(code).slot, 'b', undefined, fetchImpl);
  return pairAsNewClient(channel, principal, code, options, onRequest);
}
