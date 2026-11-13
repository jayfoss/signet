import { randomBytes, randomInt } from 'node:crypto';
import { join } from 'node:path';
import type {
  Ciphertext,
  Sealed,
  ClaimedKeyPackage,
  ClientCert,
  DirectoryEntry,
  DomainPolicy,
  GatewayKey,
  IssuerKey,
  KeyPair,
  KeyRotation,
  LegacyAuth,
  Operators,
  DomainBinding,
  Receipt,
  LogLeaf,
  MailKind,
  LogEntry,
  SealedRequest,
  Publication,
  Resolver,
  VrfKey,
  TrustedLog,
} from '@signet/lib';
import {
  OHTTP_KEYS_TYPE,
  OHTTP_REQUEST_TYPE,
  OHTTP_RESPONSE_TYPE,
  AUDIENCE_HEADER,
  activeClient,
  activeClients,
  isHumansOnly,
  readsHumansOnly,
  bindIdentity,
  decapsulateRequest,
  decapsulateResponse,
  decodeRequest,
  decodeResponse,
  encapsulateRequest,
  encapsulateResponse,
  encodeKeyConfig,
  encodeRequest,
  encodeResponse,
  fromB64u,
  generateGatewayKey,
  verifyToken,
  deliveryTokenHash,
  domainAuthHeaders,
  homeAuthHeaders,
  checkOperators,
  entryHash,
  attestedSignetHeader,
  signServerUrls,
  underDomain,
  hashBody,
  padJson,
  MAX_HTML_BYTES,
  hasScope,
  cardHash,
  generateVrfKey,
  proveIndex,
  requesterHash,
  verifyDirectoryEntry,
  verifyRequesterProof,
  verifyCard,
  verifyView,
  viewHash,
  randomId,
  replayLog,
  requestInfo,
  requestKeyId,
  signUnlisted,
  signOrgClaim,
  generateAgreementKey,
  open,
  seal,
  MAX_REQUEST_BYTES,
  verifyRecoveryProof,
  sealLegacyMail,
  signNotEnrolled,
  splitAddress,
  verifyClientAuth,
  verifyOrgClaim,
  verifyDomainCall,
  homeGroups,
  homeGateway,
  signReceipt,
} from '@signet/lib';
import { Cluster } from './cluster';
import type { ClusterMember, ClusterOptions } from './cluster';
import type { HttpRequest, HttpResult } from './http';
import { DomainKeyLogger } from './domain-key-log';
import { HttpError, JsonServer, header, json } from './http';

const optionalHeader = (headers: Record<string, string | string[] | undefined>, name: string): string | undefined => {
  const value = headers[name];
  return typeof value === 'string' ? value : undefined;
};
import type { Registrar } from './registrar';
import type { LegacyInbox, OutboundSmtp } from './smtp';
import type { PublishedKeyPackage } from './store';
import type { ContactsDoc, Outbound, Store } from './store';
import { MemoryStore, SqliteStore } from './store';

/** Daily limits. Lookups and claims are counted per requesting domain and per (hashed) requesting user. */
export interface Limits {
  requestsPerSenderPerDay: number;
  requestsPerDomainPerDay: number;
  lookupsPerRequesterPerDay: number;
  lookupsPerDomainPerDay: number;
  /** A lookup that finds nobody counts as this many: enumerators mostly miss, real senders mostly hit. */
  missWeight: number;
  /** After this many lookups in a day, a domain whose lookups mostly miss is cut off for the rest of it. */
  missRatioAfter: number;
  anonymousLookupsPerIpPerDay: number;
  claimsPerRequesterPerClientPerDay: number;
  claimsPerDomainPerDay: number;
  tokensPerUserPerDay: number;
  anonymousRequestsPerRecipientPerDay: number;
  /** Recovery attempts per address, and per source, in a day. Each proof is accepted once. */
  recoveriesPerAddressPerDay: number;
  recoveriesPerSourcePerDay: number;
  /** Pairing slots one account may open in a day. */
  pairingsPerUserPerDay: number;
  /** Messages a source with no account may post to pairing slots in a day. */
  pairingPostsPerIpPerDay: number;
}

export const DEFAULT_LIMITS: Limits = {
  requestsPerSenderPerDay: 5,
  requestsPerDomainPerDay: 100,
  lookupsPerRequesterPerDay: 500,
  lookupsPerDomainPerDay: 20_000,
  missWeight: 10,
  missRatioAfter: 50,
  anonymousLookupsPerIpPerDay: 50,
  claimsPerRequesterPerClientPerDay: 20,
  claimsPerDomainPerDay: 2_000,
  tokensPerUserPerDay: 20,
  anonymousRequestsPerRecipientPerDay: 200,
  recoveriesPerAddressPerDay: 5,
  recoveriesPerSourcePerDay: 20,
  pairingsPerUserPerDay: 10,
  pairingPostsPerIpPerDay: 30,
};

const PAIRING_TTL_MS = 10 * 60_000;
const PAIRING_MESSAGE_BYTES = 16_384;
/** Owner: SPAKE2 message, reply. New client: SPAKE2 message, sealed request. Nothing more fits. */
const PAIRING_MESSAGES = { a: 2, b: 2 } as const;

interface Pairing {
  principal: string;
  expires: number;
  messages: { a: string[]; b: string[] };
}

export interface SignetServerOptions {
  domain: string;
  /**
   * The domain's signing key. A home run by an operator who isn't the domain owner doesn't hold it and is
   * given `homeKey`, `operators`, `domainPublicKey` and a `registrar` instead (Section 6.9).
   */
  domainKey?: KeyPair;
  /** This home's own key, which signs its server calls and directory answers when it has no domain key. */
  homeKey?: KeyPair;
  /** The domain owner's signed statement listing every home, served in the policy. */
  operators?: Operators;
  /** The domain's public key, for the policy, when this home doesn't hold the private key. */
  domainPublicKey?: string;
  /** Asked to bind addresses and record them in the transparency log. Without one, this server does it with the domain key. */
  registrar?: Registrar;
  resolver: Resolver;
  /** The transparency log this domain writes every directory change to. */
  log: TrustedLog;
  /** Logs this server will query on its clients' behalf. Defaults to its own. */
  queryableLogs?: TrustedLog[];
  /** Defaults to the address the server listens on. */
  publicUrl?: string;
  maxAge?: number;
  /** Proof that `domainKey` replaces an earlier key, for the policy to carry while clients may still hold the old one (Section 6.5). */
  rotation?: KeyRotation;
  /** Seconds a mailbox item is kept at most (Section 10.7). Default 30 days; published in the policy when it differs. */
  mailboxRetentionSeconds?: number;
  /** Seconds an attachment is kept at most (Section 8.9). Default 30 days; published in the policy when it differs. */
  blobRetentionSeconds?: number;
  /** Lets anyone enroll an address over HTTP. Demo only: real enrollment goes through the org's admin. */
  openEnrollment?: boolean;
  /** Keep accounts, mailboxes and this server's keys in this folder, so they survive a restart. In memory if unset. */
  dataDir?: string;
  /** Backoff between relay attempts before bouncing. Defaults to about five days in total. */
  retryDelaysMs?: number[];
  limits?: Partial<Limits>;
  /** Plain email out, for recipients who aren't on Signet. */
  outbound?: OutboundSmtp;
  /** VRF key that proves each address's transparency-log index. Generated if not given. */
  vrfKey?: VrfKey;
  /**
   * Whether colleagues on this domain see each other's contact views without a release. On by default:
   * an organisation usually wants its own people to reach each other's devices and agents.
   */
  colleaguesSeeViews?: boolean;
  /**
   * Run a domain intake, so this domain's users can choose to be unlisted. Strangers then get the same
   * answer for unlisted and nonexistent addresses, and send first-contact requests through the intake.
   * Turning it on also hides which addresses exist: every unknown address answers as unlisted.
   */
  intake?: boolean;
  /** This server's OHTTP gateway key. Generated if not given. */
  gatewayKey?: GatewayKey;
  /** The domain intake's HPKE key. Generated if not given. */
  intakeKey?: KeyPair;
  /**
   * Run as one home of several (Section 6.8). Every replica must be given the same domain key, VRF key,
   * gateway key and, with an intake, intake key, since they are one server in several places. Replicas keep
   * their state in memory and rebuild it from the replication log, so `dataDir` isn't used.
   */
  cluster?: Omit<ClusterOptions, 'domain' | 'domainKey'>;
  /** OHTTP relay used for sealed and anonymous deliveries to other domains. Without one they go direct. */
  ohttpRelay?: string;
  /**
   * The Privacy Pass issuer this server works with: as attester it forwards its users' blinded token
   * requests there, and as origin it accepts that issuer's tokens on anonymous requests.
   */
  issuer?: { url: string; key: IssuerKey };
  fetchImpl?: typeof fetch;
}

interface Envelope {
  /** Chosen by the client, so the same message sent again through another home is recognised (Section 6.9.5). */
  id?: string;
  to: string[];
  kind: MailKind;
  payload: unknown;
  /** Present for sealed deliveries: an MLS exporter token instead of a sender identity. */
  token?: string;
  /** Present for anonymous requests: a Privacy Pass token instead of a sender identity. */
  anonymousToken?: string;
}

/** What crosses between servers. Sealed deliveries carry a token and no sender. */
interface Delivery extends Envelope {
  id: string;
  from?: string;
}

interface DeliveryResult {
  unknown: string[];
  rejected: string[];
  queued: string[];
  /** Signed by the recipient's home: proof the delivery reached it (Section 6.9.5). */
  receipts?: Receipt[];
}

class RelayError extends Error {
  constructor(
    message: string,
    readonly permanent: boolean,
  ) {
    super(message);
  }
}

const CLIENT_KINDS: MailKind[] = ['request', 'welcome', 'commit', 'message'];
const SEALABLE_KINDS: MailKind[] = ['welcome', 'commit', 'message'];
const HOUR = 3_600_000;
const DEFAULT_RETENTION_MS = 30 * 24 * HOUR;
/** The most ciphertext (base64url characters) an account's contacts may take: about 1 MiB. */
const MAX_CONTACTS_B64 = 1_400_000;
/** Sealed deliveries wait this long for their recipient to register the token, at most this many per user. */
const PARK_TTL_MS = 24 * HOUR;
const PARK_CAP = 500;
const DEFAULT_RETRY_DELAYS = [60_000, 5 * 60_000, 30 * 60_000, 2 * HOUR, 6 * HOUR, 24 * HOUR, 24 * HOUR, 24 * HOUR, 24 * HOUR];
const describe = (error: unknown) => (error instanceof Error ? error.message : String(error));
const empty = (): DeliveryResult => ({ unknown: [], rejected: [], queued: [] });
const merge = (results: DeliveryResult[]): DeliveryResult => {
  const receipts = results.flatMap((r) => r.receipts ?? []);
  return {
    unknown: results.flatMap((r) => r.unknown),
    rejected: results.flatMap((r) => r.rejected),
    queued: results.flatMap((r) => r.queued),
    ...(receipts.length > 0 ? { receipts } : {}),
  };
};

/**
 * One domain's Signet home server. It serves the policy and directory, hands out key packages,
 * accepts mail from its own clients, relays to other domains, and holds mailboxes and blobs. It never
 * holds a key that opens message content.
 *
 * Its clients never talk to other domains directly: lookups, key-package claims and log queries go
 * through here, signed with the domain key and a hash of the requesting user, so remote servers can
 * rate-limit by requester without learning who it is or seeing client addresses.
 */
export class SignetServer implements LegacyInbox {
  readonly store: Store;
  private readonly http: JsonServer;
  private readonly fetchImpl: typeof fetch;
  private readonly timers = new Set<NodeJS.Timeout>();
  private readonly limits: Limits;
  private readonly gatewayKey: GatewayKey;
  /** The domain intake's HPKE key, when this domain runs one. */
  private readonly intakeKey: KeyPair | null;
  /** Users who opted out of the public directory (`set-listing` in their log). */
  private readonly unlisted = new Set<string>();
  /** Pairing slots relaying a new client's enrollment to its owner's device, by four-digit slot. */
  private readonly pairings = new Map<string, Pairing>();
  private readonly vrfKey: VrfKey;
  /** Set when this server is one home of several. */
  private readonly cluster?: Cluster;
  /** Deliveries that arrived through the OHTTP gateway, for tests and monitoring. */
  receivedViaOhttp = 0;

  constructor(private readonly options: SignetServerOptions) {
    this.fetchImpl = options.resolver.failoverFetch?.(options.fetchImpl ?? fetch) ?? options.fetchImpl ?? fetch;
    if (options.domainKey) this.keyLogger = new DomainKeyLogger({ domain: options.domain, domainKey: options.domainKey, log: options.log, rotation: options.rotation, fetchImpl: options.fetchImpl });
    if (!options.domainKey) {
      if (!options.homeKey || !options.operators || !options.domainPublicKey) throw new Error('a home without the domain key needs homeKey, operators and domainPublicKey');
      const listed = checkOperators(options.operators, options.domain, options.domainPublicKey).some((home) => home.key === options.homeKey?.publicKey);
      if (!listed) throw new Error('homeKey is not in the operators statement');
    }
    this.limits = { ...DEFAULT_LIMITS, ...options.limits };
    if (options.cluster) {
      if (options.dataDir) throw new Error('a cluster replica keeps its state in the replication log, not in dataDir');
      if (!options.vrfKey || !options.gatewayKey || (options.intake && !options.intakeKey)) {
        throw new Error('every replica of a cluster must be given the same vrfKey, gatewayKey and (with an intake) intakeKey');
      }
      this.cluster = new Cluster({ ...options.cluster, domain: options.domain, domainKey: options.homeKey ?? this.domainSigner(), fetchImpl: options.cluster.fetchImpl ?? options.fetchImpl ?? fetch }, () => new MemoryStore());
      this.store = this.cluster.store;
      this.gatewayKey = options.gatewayKey;
      this.intakeKey = options.intake ? (options.intakeKey as KeyPair) : null;
      this.vrfKey = options.vrfKey;
      // What this replica derives from its store is rebuilt, and its retries start, only when it becomes the primary.
      this.cluster.onPrimary(() => this.becamePrimary());
      this.cluster.onStandby(() => this.cancelRetries());
    } else {
      this.store = options.dataDir ? new SqliteStore(join(options.dataDir, 'signet.db')) : new MemoryStore();
      // The server's own keys live with its data, so a restart serves the same policy and VRF indexes.
      const saved = this.store.serverKeys();
      this.gatewayKey = saved?.gateway ?? options.gatewayKey ?? generateGatewayKey();
      this.intakeKey = options.intake ? (saved?.intake ?? options.intakeKey ?? generateAgreementKey()) : null;
      this.vrfKey = saved?.vrf ?? options.vrfKey ?? generateVrfKey();
      this.store.setServerKeys({ vrf: this.vrfKey, gateway: this.gatewayKey, intake: this.intakeKey });
      for (const local of this.store.userLocals()) this.setListing(local, replayLog(this.store.user(local)?.log ?? []).unlisted);
      // Deliveries that were waiting for a retry when the server stopped pick up where they left off.
      for (const entry of this.store.outbound()) this.schedule(entry);
      if (!this.store.epoch()) this.store.setEpoch(randomId('e'));
    }
    this.http = new JsonServer((request) => this.route(request), undefined, () => this.cluster?.responseHeaders() ?? {});
  }

  get domain(): string {
    return this.options.domain;
  }

  /** The key only the domain owner holds. A home without it asks the registrar or refuses (Section 6.9.4). */
  private domainSigner(): KeyPair {
    if (!this.options.domainKey) throw new HttpError(501, 'this home does not hold the domain key');
    return this.options.domainKey;
  }

  /** Who signs directory answers: the domain key, or this home's key, which says so in the answer. */
  private answerSigner(): { key: KeyPair; asHome: boolean } {
    return this.options.domainKey ? { key: this.options.domainKey, asHome: false } : { key: this.options.homeKey as KeyPair, asHome: true };
  }

  /** Bind an address to a key and record it, through the registrar if there is one. */
  private async bindAddress(publication: Publication, principal: string, identityKey: string): Promise<DomainBinding> {
    if (this.options.registrar) return this.options.registrar.bind(publication);
    await this.record(principal, 'bound', identityKey, publication);
    return bindIdentity(this.domainSigner(), principal, identityKey);
  }

  get url(): string {
    return this.http.publicUrl;
  }

  get policy(): DomainPolicy {
    const homes = this.cluster?.homes;
    const server = homes?.[0] ?? this.http.publicUrl;
    return {
      v: 'signet0',
      domain: this.options.domain,
      server,
      ...(homes && homes.length > 1 ? { replicas: homes } : {}),
      mode: 'enforce',
      maxAge: this.options.maxAge ?? 2_592_000,
      ...(this.mailboxRetentionMs !== DEFAULT_RETENTION_MS ? { mailboxRetention: this.mailboxRetentionMs / 1000 } : {}),
      ...(this.blobRetentionMs !== DEFAULT_RETENTION_MS ? { blobRetention: this.blobRetentionMs / 1000 } : {}),
      domainKey: this.options.domainKey?.publicKey ?? (this.options.domainPublicKey as string),
      ...(this.options.operators ? { operators: this.options.operators } : {}),
      ...(this.options.rotation ? { rotation: this.options.rotation } : {}),
      ...this.serverSignature(server, homes),
      vrfKey: this.vrfKey.public,
      log: this.options.log,
      ohttp: { gateway: `${server}/v0/ohttp`, keys: encodeKeyConfig(this.gatewayKey) },
      privacyPass: this.options.issuer ? { issuer: this.options.issuer.key.name } : undefined,
      intake: this.intakeKey ? { keyId: requestKeyId(this.intakeKey.publicKey), agreeKey: this.intakeKey.publicKey } : undefined,
    };
  }

  /**
   * Add a replica to this home's cluster, or remove one (Section 6.8.6 step 10). Primary only, and one change at a time.
   * The operator also publishes the new replica in the DNS record's host list; `policy.replicas` follows the cluster.
   */
  async addReplica(member: ClusterMember): Promise<void> {
    await (this.cluster ?? this.noCluster()).addMember(member);
  }

  async removeReplica(id: string): Promise<void> {
    await (this.cluster ?? this.noCluster()).removeMember(id);
  }

  private noCluster(): never {
    throw new HttpError(409, 'this home does not run as a cluster');
  }

  /** `serverSig` for a policy whose server or replicas are outside the domain, which needs the domain key (Section 6.4). */
  private serverSignature(server: string, homes?: string[]): { serverSig?: string } {
    const replicas = homes && homes.length > 1 ? homes : undefined;
    const outside = [server, ...(replicas ?? [])].some((url) => !underDomain(url, this.options.domain));
    if (!outside || !this.options.domainKey) return {};
    return { serverSig: signServerUrls(this.options.domainKey, { domain: this.options.domain, server, replicas }) };
  }

  private readonly keyLogger?: DomainKeyLogger;

  private get mailboxRetentionMs(): number {
    return (this.options.mailboxRetentionSeconds ?? DEFAULT_RETENTION_MS / 1000) * 1000;
  }

  private get blobRetentionMs(): number {
    return (this.options.blobRetentionSeconds ?? DEFAULT_RETENTION_MS / 1000) * 1000;
  }

  private sweepTimer?: NodeJS.Timeout;

  async listen(port = 0, host = '127.0.0.1'): Promise<string> {
    const url = await this.http.listen(port, host, this.options.publicUrl);
    this.cluster?.start();
    this.sweepTimer = setInterval(() => void this.sweep(), 10 * 60_000);
    this.sweepTimer.unref();
    return url;
  }

  /**
   * Delete what has outlived its retention: mailbox items (Section 10.7) and attachments (Section 8.9).
   * A standby keeps its own attachments by the same rule and leaves the replicated state to the primary.
   */
  async sweep(now = Date.now()): Promise<void> {
    try {
      const before = new Date(now - this.mailboxRetentionMs).toISOString();
      for (const local of this.store.userLocals()) this.store.expireMail(local, before);
      for (const id of this.store.blobsBefore(now - this.blobRetentionMs)) {
        await this.cluster?.deleteBlob(id);
        this.store.deleteBlob(id);
      }
      await this.cluster?.expireBlobs(now - this.blobRetentionMs);
      await this.cluster?.durable();
    } catch {
      // Not the primary, or it lost the role mid-sweep: the next one does it.
    }
  }

  async close(): Promise<void> {
    if (this.sweepTimer) clearInterval(this.sweepTimer);
    this.cluster?.close();
    this.cancelRetries();
    await this.http.close();
    this.store.close();
  }

  /**
   * Check a publication: the log replays, and the card and view are signed by its identity key for its
   * current head. The server can't forge either; it can only store and serve them.
   */
  private checkPublication(publication: Publication): ReturnType<typeof replayLog> {
    const state = replayLog(publication.entries);
    verifyCard(publication.card, state.principal, state.identityKey);
    verifyView(publication.view, state.principal, state.identityKey);
    if (publication.card.card.logHead !== state.head || publication.view.view.logHead !== state.head) {
      throw new HttpError(400, 'card and view must be signed for the current log head');
    }
    if (state.unlisted && !this.intakeKey) throw new HttpError(409, `${this.options.domain} has no intake, so its addresses can't be unlisted`);
    return state;
  }

  /** Bind an address to the identity key that heads this log, record it in the transparency log, then publish it. */
  async enroll(publication: Publication): Promise<void> {
    this.cluster?.requirePrimary();
    const state = this.checkPublication(publication);
    const { local, domain } = splitAddress(state.principal);
    if (domain !== this.options.domain) throw new HttpError(400, `${state.principal} is not on ${this.options.domain}`);
    // Enrollment creates an account; it never replaces one. Changes come as log updates its own key signs.
    if (this.store.hasUser(local)) throw new HttpError(409, `${state.principal} is already enrolled`);
    const binding = await this.bindAddress(publication, state.principal, state.identityKey);
    this.setListing(local, state.unlisted);
    this.store.putUser(local, {
      binding,
      log: structuredClone(publication.entries),
      card: structuredClone(publication.card),
      view: structuredClone(publication.view),
    });
    await this.cluster?.durable();
  }

  /**
   * Hand the stored log to whoever proves they hold the recovery key it names, so an owner who lost every
   * device can sign a recovery entry onto it. Anyone else gets the same 404 as an unknown address.
   */
  private recoveryLog(local: string, proof: { ts: string; sig: string }, source: string): { entries: LogEntry[] } {
    // Limits count every attempt, before anything is checked, so guessing costs the same as failing.
    this.limit(`recovery:${local}`, this.limits.recoveriesPerAddressPerDay, 'recovery attempts for this address');
    this.limit(`recovery:ip:${source}`, this.limits.recoveriesPerSourcePerDay, 'recovery attempts');
    const user = this.store.user(local);
    if (!user || !verifyRecoveryProof(replayLog(user.log), proof)) throw new HttpError(404, 'no recoverable account');
    if (!this.store.recoveryProofs.firstUse(`${local} ${proof.sig}`)) throw new HttpError(404, 'no recoverable account');
    return { entries: structuredClone(user.log) };
  }

  /** Release an address. The unbinding is logged, so correspondents who pinned it are told rather than silently downgraded. */
  async unenroll(local: string): Promise<void> {
    this.cluster?.requirePrimary();
    if (!this.store.hasUser(local)) throw new HttpError(404, `${local} is not enrolled`);
    if (this.options.registrar) await this.options.registrar.unbind(`${local}@${this.options.domain}`);
    else await this.record(`${local}@${this.options.domain}`, 'unbound', null, null);
    this.store.deleteUser(local);
    await this.cluster?.durable();
  }

  /**
   * Accept a newer publication: its log must extend the stored one. A key change in it (signed by the old
   * identity key, or by the recovery key it named) moves the domain binding to the new key.
   */
  async updateLog(local: string, publication: Publication): Promise<void> {
    this.cluster?.requirePrimary();
    const user = this.store.user(local);
    if (!user) throw new HttpError(404, `${local} is not enrolled`);
    const state = this.checkPublication(publication);
    const log = publication.entries;
    const extendsStored = log.length >= user.log.length && user.log.every((entry, i) => entryHash(entry) === entryHash(log[i]));
    if (!extendsStored) throw new HttpError(409, 'log must extend the stored log');
    if (cardHash(publication.card) === cardHash(user.card) && viewHash(publication.view) === viewHash(user.view)) return;
    const binding = await this.bindAddress(publication, state.principal, state.identityKey);
    this.setListing(local, state.unlisted);
    if (state.identityKey !== user.binding.identityKey) user.binding = binding;
    user.log = structuredClone(log);
    user.card = structuredClone(publication.card);
    user.view = structuredClone(publication.view);
    this.store.putUser(local, user);
    await this.cluster?.durable();
  }

  /** Whether this server answers requests: always for a single home, and for a cluster replica only while it is the primary. */
  isPrimary(): boolean {
    return this.cluster ? this.cluster.isPrimary() : true;
  }

  /**
   * Strangers get the public card. Contacts the owner released its view to (and, by default, colleagues)
   * get the contact view too. Only the owner's own clients get the private log. Every answer carries the
   * address's VRF proof; unknown and unenrolled addresses get the same signed not-enrolled answer.
   */
  directory(local: string, access: 'public' | 'contact' | 'owner' = 'public'): DirectoryEntry {
    const principal = `${local}@${this.options.domain}`;
    const user = this.store.user(local);
    // With an intake, strangers can't tell an unlisted address from a missing one: same answer, no VRF proof.
    if (this.intakeKey && access === 'public' && (!user || this.unlisted.has(local))) { const { key, asHome } = this.answerSigner(); return signUnlisted(key, principal, new Date(), asHome); }
    const vrf = proveIndex(this.vrfKey, principal);
    if (!user) { const { key, asHome } = this.answerSigner(); return signNotEnrolled(key, principal, vrf, new Date(), asHome); }
    return {
      status: 'enrolled',
      principal,
      binding: user.binding,
      card: user.card,
      vrf,
      ...(access === 'public' ? {} : { view: user.view }),
      ...(access === 'owner' ? { log: user.log } : {}),
    };
  }

  /**
   * Open a relay slot for pairing a new client. Only a device of the account can open one, and the
   * server never sees the pairing secret: it relays two SPAKE2 messages and two sealed ones, then the
   * slot is full. It expires after ten minutes.
   */
  private openPairing(client: ClientCert): { slot: string; expires: string } {
    if (client.kind !== 'device') throw new HttpError(403, 'only a device can pair a new client');
    this.limit(`pairings:${client.principal}`, this.limits.pairingsPerUserPerDay, 'pairings');
    const now = Date.now();
    for (const [slot, open] of this.pairings) if (open.expires <= now) this.pairings.delete(slot);
    if (this.pairings.size >= 9_000) throw new HttpError(503, 'too many pairings in progress');
    let slot: string;
    do slot = String(1000 + randomInt(9000));
    while (this.pairings.has(slot));
    this.pairings.set(slot, { principal: client.principal, expires: now + PAIRING_TTL_MS, messages: { a: [], b: [] } });
    return { slot, expires: new Date(now + PAIRING_TTL_MS).toISOString() };
  }

  private livePairing(slot: string): Pairing {
    const open = this.pairings.get(slot);
    if (!open || open.expires <= Date.now()) throw new HttpError(404, 'no such pairing, or it expired');
    return open;
  }

  private postPairing(slot: string, side: 'a' | 'b', body: unknown): { ok: true } {
    const open = this.livePairing(slot);
    if (typeof body !== 'string' || body.length > PAIRING_MESSAGE_BYTES) throw new HttpError(400, 'a pairing message is a string of at most 16 KB');
    if (open.messages[side].length >= PAIRING_MESSAGES[side]) throw new HttpError(409, 'this pairing slot has already been used');
    open.messages[side].push(body);
    return { ok: true };
  }

  private pairingMessages(slot: string, side: 'a' | 'b', after: number): { messages: string[] } {
    return { messages: this.livePairing(slot).messages[side].slice(after) };
  }

  /** The organisation's admin sets what it vouches for about a user; its clients fetch them signed. */
  async setClaims(local: string, claims: string[]): Promise<void> {
    // Without the domain key a home keeps only claims the owner has already signed, and checks each one.
    if (!this.options.domainKey) for (const claim of claims) this.checkSignedClaim(`${local}@${this.options.domain}`, claim);
    this.store.setClaims(local, claims);
    await this.cluster?.durable();
  }

  private setListing(local: string, unlisted: boolean): void {
    if (unlisted) this.unlisted.add(local);
    else this.unlisted.delete(local);
  }

  private signedClaim(principal: string, claim: string): ReturnType<typeof signOrgClaim> | undefined {
    try {
      const parsed = JSON.parse(claim) as ReturnType<typeof signOrgClaim>;
      const policy = { domain: this.options.domain, domainKey: this.options.domainKey?.publicKey ?? (this.options.domainPublicKey as string) } as DomainPolicy;
      return verifyOrgClaim(parsed, principal, policy) ? parsed : undefined;
    } catch {
      return undefined;
    }
  }

  private checkSignedClaim(principal: string, claim: string): void {
    if (!this.signedClaim(principal, claim)) throw new HttpError(400, 'this home does not hold the domain key, so it keeps only unexpired claims the domain owner has signed');
  }

  /** A stored claim as the client gets it: one the owner signed, if it is still current; otherwise a plain one, signed with the domain key. */
  private orgClaimFor(principal: string, claim: string): ReturnType<typeof signOrgClaim>[] {
    if (claim.startsWith('{')) return [this.signedClaim(principal, claim)].filter((signed) => signed !== undefined) as ReturnType<typeof signOrgClaim>[];
    return [signOrgClaim(this.domainSigner(), principal, claim)];
  }

  /** Whether a request was sealed to this domain's intake rather than to a user's own keys. */
  private forIntake(kind: string, payload: unknown): payload is SealedRequest {
    if (kind !== 'request' || !this.intakeKey) return false;
    const keyId = requestKeyId(this.intakeKey.publicKey);
    const copies = (payload as SealedRequest | undefined)?.copies;
    return Array.isArray(copies) && copies.some((copy) => copy.clientId === keyId);
  }

  /**
   * Open a request sealed to the intake and pass it on, re-sealed to the recipient's own request keys (or
   * its devices', if the sender asked for humans only). The sender's signature inside is untouched, so the
   * recipient checks it as usual. A request for an address that doesn't exist is dropped without a trace:
   * the sender gets the same answer either way.
   */
  private async intakeRequest(address: string, id: string, from: string | undefined, sealed: SealedRequest): Promise<void> {
    if (!this.intakeKey) return;
    const keyId = requestKeyId(this.intakeKey.publicKey);
    const copy = sealed.copies.find((candidate) => candidate.clientId === keyId);
    const local = splitAddress(address).local;
    const user = this.store.user(local);
    if (!copy || !user || sealed.to !== address) return;
    let bytes: Buffer;
    let body: { to: string; from: string; audience?: string };
    try {
      bytes = await open(this.intakeKey, copy.sealed, requestInfo(address));
      body = (JSON.parse(bytes.toString()) as { body: typeof body }).body;
    } catch {
      return;
    }
    if (bytes.length > MAX_REQUEST_BYTES || body.to !== address || (sealed.from && sealed.from !== body.from)) return;
    const card = user.card.card;
    const keys = body.audience === 'humans' ? card.humanKeys : card.requestKeys;
    const copies = await Promise.all(keys.map(async (key) => ({ clientId: key.keyId, sealed: await seal(key.agreeKey, bytes, requestInfo(address)) })));
    const forwarded: SealedRequest = { from: sealed.from, to: address, copies };
    this.store.push(local, from ? { id, kind: 'request', from, payload: forwarded } : { id, kind: 'request', from: '', sealed: true, payload: forwarded });
  }

  accepts(local: string): boolean {
    return this.store.hasUser(local);
  }

  /** Encrypt inbound plain email to the recipient's reading clients and keep only the ciphertext. */
  async storeLegacy(local: string, raw: Buffer, envelopeFrom: string, auth: LegacyAuth): Promise<void> {
    this.cluster?.requirePrimary();
    const user = this.store.user(local);
    if (!user) throw new HttpError(404, `${local} is not enrolled`);
    const log = replayLog(user.log);
    // A sender's "humans only" is honoured as the recipient set it: devices, opted-in agents, and always escrow.
    const humansOnly = isHumansOnly(raw);
    const readers = activeClients(log).filter(
      (cert) => (hasScope(cert, 'read:*') || cert.kind === 'org-escrow') && (!humansOnly || readsHumansOnly(log, cert)),
    );
    const sealed = await sealLegacyMail(user.binding.principal, raw, readers, envelopeFrom, auth);
    this.store.push(local, { id: randomId('l'), kind: 'legacy', from: envelopeFrom, payload: sealed });
    await this.cluster?.durable();
  }

  /**
   * Store an account's encrypted contacts (Section 7.9). The home server checks the version and that wraps are for
   * active clients; it cannot check, and never sees, what is inside.
   */
  private putContacts(client: ClientCert, body: { expectedVersion?: number; epoch?: number; data?: Ciphertext; wraps?: Record<string, Sealed> }): { version: number } {
    const { local } = splitAddress(client.principal);
    const doc = this.store.contactsDoc(local);
    const sealed = (value: unknown): value is Sealed => typeof value === 'object' && value !== null && typeof (value as Sealed).enc === 'string' && typeof (value as Sealed).ct === 'string';
    const cipher = (value: unknown): value is Ciphertext => typeof value === 'object' && value !== null && typeof (value as Ciphertext).iv === 'string' && typeof (value as Ciphertext).ct === 'string';
    if (!Number.isInteger(body.expectedVersion) || !Number.isInteger(body.epoch)) throw new HttpError(400, 'expectedVersion and epoch are required');
    if (body.data !== undefined && (!cipher(body.data) || body.data.ct.length > MAX_CONTACTS_B64)) throw new HttpError(400, 'data must be ciphertext of a sensible size');
    if (body.expectedVersion !== doc.version) throw new HttpError(409, 'the contacts changed; read them again', { 'signet-version': String(doc.version) });
    const user = this.store.user(local);
    const active = new Set(user ? activeClients(replayLog(user.log)).map((cert) => cert.clientId) : []);
    const wraps = body.wraps ?? {};
    for (const [clientId, wrap] of Object.entries(wraps)) {
      if (!active.has(clientId) || !sealed(wrap)) throw new HttpError(400, `${clientId} is not an active client with a well-formed wrap`);
    }
    let next: ContactsDoc;
    if (doc.epoch >= 1 && body.epoch === doc.epoch) next = { epoch: doc.epoch, version: doc.version + 1, data: body.data ?? doc.data, wraps: { ...doc.wraps, ...wraps } };
    else if (body.epoch === doc.epoch + 1) {
      if (body.data === undefined) throw new HttpError(400, 'a new epoch needs data encrypted under its key');
      next = { epoch: body.epoch, version: doc.version + 1, data: body.data, wraps };
    } else throw new HttpError(400, `epoch must be ${doc.epoch}${doc.epoch >= 1 ? ' or ' : ' (none stored) +1 = '}${doc.epoch + 1}`);
    this.store.putContactsDoc(local, next);
    return { version: next.version };
  }

  /**
   * Record how far a client has read, then delete what every reading client of the account has (Section 10.7).
   * A client that is revoked or holds no read scope is not waited for.
   */
  private acknowledge(client: ClientCert, body: { through?: number; epoch?: string }): { through: number } {
    const epoch = this.store.epoch();
    if (typeof body.through !== 'number' || !Number.isInteger(body.through) || body.through < 0) throw new HttpError(400, 'through must be a sequence number');
    if (body.epoch !== undefined && body.epoch !== epoch) throw new HttpError(409, 'the mailbox store has changed; read it from the start', { 'signet-epoch': epoch ?? '' });
    const { local } = splitAddress(client.principal);
    this.store.ackMail(local, client.clientId, body.through);
    const user = this.store.user(local);
    if (user) {
      const readers = activeClients(replayLog(user.log)).filter((cert) => cert.scopes.some((scope) => scope.startsWith('read:')) || cert.kind === 'org-escrow');
      const acks = this.store.acks(local);
      const floor = Math.min(...readers.map((cert) => acks[cert.clientId] ?? 0));
      if (readers.length > 0 && floor > 0) this.store.dropMail(local, floor);
    }
    return { through: body.through };
  }

  private limit(key: string, max: number, what: string): void {
    if (this.store.bump(key) > max) throw new HttpError(429, `too many ${what} today`);
  }

  private async record(principal: string, kind: LogLeaf['kind'], identityKey: string | null, publication: Publication | null): Promise<void> {
    // The domain's own key goes into the log before its first change, so a client can check the policy against it (Section 5.3.1).
    await this.keyLogger?.ensure();
    const leaf: LogLeaf = {
      v: 0,
      index: proveIndex(this.vrfKey, principal).index,
      domain: this.options.domain,
      kind,
      identityKey,
      cardHash: publication ? cardHash(publication.card) : null,
      viewHash: publication ? viewHash(publication.view) : null,
      ts: new Date().toISOString(),
    };
    const response = await this.signedFetch('POST', `${this.options.log.url}/v0/append`, JSON.stringify(leaf));
    if (!response.ok) throw new HttpError(502, `transparency log refused the change: ${response.status} ${await response.text()}`);
  }

  /** A request to another Signet service, signed with this domain's key over its method, path, query and body. */
  private signedFetch(method: 'GET' | 'POST', url: string, body = '', extra?: Record<string, string>): Promise<Response> {
    const { pathname, search } = new URL(url);
    return this.fetchImpl(url, {
      method,
      headers: {
        ...(method === 'POST' ? { 'content-type': 'application/json' } : {}),
        ...extra,
        ...(this.options.domainKey
          ? domainAuthHeaders(this.options.domain, this.options.domainKey, method, `${pathname}${search}`, body)
          : homeAuthHeaders(this.options.domain, this.options.homeKey as KeyPair, method, `${pathname}${search}`, body)),
      },
      body: method === 'POST' ? body : undefined,
    });
  }

  /**
   * In a cluster, only the primary answers, and only after what it changed is committed (Section 6.8.5).
   * Standbys serve the policy and the replicas' own calls, and send everyone else to the primary.
   */
  private async route(request: HttpRequest): Promise<HttpResult> {
    if (!this.cluster) return this.routeLocal(request);
    if (request.method === 'GET' && request.url.pathname === '/.well-known/signet.json') return this.policy;
    if (request.url.pathname.startsWith('/v0/cluster/')) return this.cluster.handle(request);
    // An attachment is public ciphertext behind an unguessable id, and a standby holds a copy, so it can serve it.
    if (request.method === 'GET' && /^\/v0\/blobs\/[^/]+$/.test(request.url.pathname)) return this.routeLocal(request);
    this.cluster.requirePrimary();
    const result = await this.routeLocal(request);
    await this.cluster.durable();
    return result;
  }

  private async routeLocal(request: HttpRequest): Promise<HttpResult> {
    const { method, url } = request;
    const path = url.pathname;
    const directory = path.match(/^\/v0\/directory\/([^/]+)(\/claim)?$/);
    const log = path.match(/^\/v0\/log\/([^/]+)$/);
    const recovery = path.match(/^\/v0\/recovery\/([^/]+)$/);
    const blob = path.match(/^\/v0\/blobs\/([^/]+)$/);
    const transparency = path.match(/^\/v0\/transparency\/(latest|history|consistency)$/);

    if (method === 'GET' && path === '/.well-known/signet.json') return this.policy;
    if (method === 'GET' && directory && !directory[2]) return this.remoteLookup(request, decodeURIComponent(directory[1]).toLowerCase());
    if (method === 'POST' && directory && directory[2]) return this.remoteClaim(request, decodeURIComponent(directory[1]).toLowerCase());
    if (method === 'POST' && log) {
      await this.updateLog(decodeURIComponent(log[1]).toLowerCase(), json<Publication>(request));
      return { ok: true };
    }
    if (method === 'POST' && recovery) return this.recoveryLog(decodeURIComponent(recovery[1]).toLowerCase(), json<{ ts: string; sig: string }>(request), request.remoteAddress);
    if (method === 'POST' && path === '/v0/enroll') {
      if (!this.options.openEnrollment) throw new HttpError(403, 'enrollment is closed');
      await this.enroll(json<Publication>(request));
      return { ok: true };
    }
    if (method === 'GET' && blob) {
      const data = this.cluster ? await this.cluster.getBlob(decodeURIComponent(blob[1])) : this.store.blob(decodeURIComponent(blob[1]));
      if (!data) throw new HttpError(404, 'no such blob');
      return { raw: data, contentType: 'application/octet-stream' };
    }
    if (method === 'POST' && path === '/v0/deliver') return this.deliverSigned(await this.authenticateDomain(request), json<Delivery>(request));
    if (method === 'POST' && path === '/v0/deliver-sealed') return this.deliverLocal(json<Delivery>(request));
    if (method === 'POST' && path === '/v0/deliver-anonymous') return this.deliverAnonymous(json<Delivery>(request));
    const pairing = path.match(/^\/v0\/pairing\/(\d{4})\/(a|b)$/);
    if (method === 'GET' && pairing) return this.pairingMessages(pairing[1], pairing[2] as 'a' | 'b', Number(url.searchParams.get('after') ?? 0));
    if (method === 'POST' && pairing && pairing[2] === 'b') {
      this.limit(`pairing:ip:${request.remoteAddress}`, this.limits.pairingPostsPerIpPerDay, 'pairing messages');
      return this.postPairing(pairing[1], 'b', json<{ body: string }>(request).body);
    }
    if (method === 'GET' && path === '/.well-known/ohttp-gateway') return { raw: fromB64u(encodeKeyConfig(this.gatewayKey)), contentType: OHTTP_KEYS_TYPE };
    if (method === 'POST' && path === '/v0/ohttp') return this.gateway(request);

    const client = this.authenticateClient(request);
    if (method === 'POST' && path === '/v0/pairing') return this.openPairing(client);
    if (method === 'GET' && path === '/v0/claims') {
      const local = splitAddress(client.principal).local;
      return { claims: this.store.claims(local).flatMap((claim) => this.orgClaimFor(client.principal, claim)) };
    }
    if (method === 'POST' && pairing && pairing[2] === 'a') {
      if (this.livePairing(pairing[1]).principal !== client.principal) throw new HttpError(403, 'not your pairing slot');
      return this.postPairing(pairing[1], 'a', json<{ body: string }>(request).body);
    }
    if (method === 'GET' && path === '/v0/lookup') return this.lookupFor(client, url.searchParams.get('address') ?? '', optionalHeader(request.headers, 'signet-requester'));
    if (method === 'POST' && path === '/v0/claim') return this.claimFor(client, json<{ address: string; clients: string[] }>(request));
    if (method === 'GET' && transparency) return this.logQueryFor(client, transparency[1], url.searchParams);
    if (method === 'POST' && path === '/v0/submit') return this.submit(client, json<Envelope>(request));
    if (method === 'GET' && path === '/v0/mailbox') {
      // A client that knows an older epoch than this store's reads from the start: its cursor points into a store that is gone.
      const epoch = this.store.epoch();
      const known = url.searchParams.get('epoch');
      const after = known !== null && known !== epoch ? 0 : Number(url.searchParams.get('after') ?? 0);
      const { local } = splitAddress(client.principal);
      this.store.expireMail(local, new Date(Date.now() - this.mailboxRetentionMs).toISOString());
      return { items: this.store.mailbox(local, after), epoch };
    }
    if (method === 'POST' && path === '/v0/mailbox/ack') return this.acknowledge(client, json<{ through?: number; epoch?: string }>(request));
    if (method === 'GET' && path === '/v0/contacts') {
      const doc = this.store.contactsDoc(splitAddress(client.principal).local);
      return { epoch: doc.epoch, version: doc.version, data: doc.data, wrap: doc.wraps[client.clientId] ?? null, wrapped: Object.keys(doc.wraps) };
    }
    if (method === 'PUT' && path === '/v0/contacts') return this.putContacts(client, json(request));
    if (method === 'POST' && path === '/v0/contacts/grant') {
      const { add = [], remove = [] } = json<{ add?: string[]; remove?: string[] }>(request);
      this.store.updateViewGrants(splitAddress(client.principal).local, add, remove);
      return { ok: true };
    }
    if (method === 'POST' && path === '/v0/delivery-tokens') {
      const { add = [], remove = [] } = json<{ add?: string[]; remove?: string[] }>(request);
      const { local } = splitAddress(client.principal);
      this.store.updateTokens(local, add, remove);
      return { ok: true, released: this.store.release(local, add) };
    }
    if (method === 'GET' && path === '/v0/keypackages/count') {
      return { count: this.store.countKeyPackages(client.clientId), lastResort: this.store.hasLastResort(client.clientId) };
    }
    if (method === 'POST' && path === '/v0/keypackages') {
      const { packages = [], lastResort } = json<{ packages?: PublishedKeyPackage[]; lastResort?: PublishedKeyPackage }>(request);
      this.store.addKeyPackages(client.clientId, packages);
      if (lastResort) this.store.setLastResort(client.clientId, lastResort);
      return { ok: true };
    }
    if (method === 'POST' && path === '/v0/blobs') {
      // Sixteen random bytes: an id is the only thing that stops someone else fetching the ciphertext (Section 8.9).
      const id = `blob_${randomBytes(16).toString('base64url')}`;
      // A replica keeps blobs beside its log and copies them to another home, so they never enter the log.
      if (this.cluster) await this.cluster.putBlob(id, request.body);
      else this.store.putBlob(id, request.body);
      this.store.noteBlob(id, client.principal, Date.now());
      return { id, url: `${this.http.publicUrl}/v0/blobs/${id}` };
    }
    const owned = path.match(/^\/v0\/blobs\/([^/]+)$/);
    if (method === 'DELETE' && owned) {
      const id = decodeURIComponent(owned[1]);
      const owner = this.store.blobOwner(id);
      if (owner === undefined) throw new HttpError(404, 'no such blob');
      if (owner !== client.principal) throw new HttpError(403, 'not your blob');
      await this.cluster?.deleteBlob(id);
      this.store.deleteBlob(id);
      return { ok: true };
    }
    if (method === 'POST' && path === '/v0/legacy/send') return this.sendLegacy(client, json(request), request);
    if (method === 'POST' && path === '/v0/legacy/attest') {
      const { to, subject, bodyHash, htmlHash, humansOnly } = json<{ to: string[]; subject: string; bodyHash: string; htmlHash?: string; humansOnly?: boolean }>(request);
      return { header: await this.attestHeader(client, to, subject, request, bodyHash, humansOnly ? 'humans' : undefined, htmlHash) };
    }
    if (method === 'GET' && path === '/v0/issuer') {
      if (!this.options.issuer) throw new HttpError(501, 'this server has no Privacy Pass issuer');
      return this.options.issuer.key;
    }
    if (method === 'POST' && path === '/v0/tokens') return this.attest(client, json<{ blinded: string[] }>(request));
    throw new HttpError(404, 'not found');
  }

  /**
   * OHTTP gateway: decrypt the encapsulated request, run it if it's one of the two delivery routes, and
   * encrypt the answer back. Nothing about the original sender reaches this server.
   */
  private async gateway(request: HttpRequest): Promise<HttpResult> {
    if (request.headers['content-type'] !== OHTTP_REQUEST_TYPE) throw new HttpError(415, `expected ${OHTTP_REQUEST_TYPE}`);
    const { request: inner, pending } = await decapsulateRequest(this.gatewayKey, request.body).catch(() => {
      throw new HttpError(400, 'could not decapsulate');
    });
    const message = decodeRequest(inner);
    let status = 200;
    let result: unknown;
    const lookup = message.method === 'GET' ? /^\/v0\/directory\/([^/?]+)$/.exec(message.path) : null;
    if (lookup) {
      // An anonymous lookup, as a stranger would make it: senders cross-checking an "unlisted" answer, and
      // owners checking what strangers see. Same answer and limits as any unsigned lookup.
      try {
        result = this.anonymousLookup(`ohttp:${request.remoteAddress}`, decodeURIComponent(lookup[1]).toLowerCase());
      } catch (error) {
        status = error instanceof HttpError ? error.status : 400;
        result = { error: describe(error) };
      }
    } else if (message.method !== 'POST' || !['/v0/deliver-sealed', '/v0/deliver-anonymous'].includes(message.path)) {
      status = 403;
      result = { error: 'the gateway only accepts deliveries and directory lookups' };
    } else {
      try {
        this.receivedViaOhttp += 1;
        const body = Buffer.from(message.body);
        result = message.path === '/v0/deliver-sealed' ? await this.deliverLocal(JSON.parse(body.toString()) as Delivery) : await this.deliverAnonymous(JSON.parse(body.toString()) as Delivery);
      } catch (error) {
        status = error instanceof HttpError ? error.status : 400;
        result = { error: describe(error) };
      }
    }
    const response = encodeResponse({ status, headers: [['content-type', 'application/json']], body: Buffer.from(JSON.stringify(result)) });
    return { raw: encapsulateResponse(pending, response), contentType: OHTTP_RESPONSE_TYPE };
  }

  /** Attester: rate-limit this user, then get their blinded token requests signed by the issuer. */
  private async attest(client: ClientCert, { blinded }: { blinded: string[] }): Promise<{ signatures: string[] }> {
    if (!this.options.issuer) throw new HttpError(501, 'this server has no Privacy Pass issuer');
    if (!hasScope(client, 'send')) throw new HttpError(403, `${client.label} may not send`);
    for (let i = 0; i < blinded.length; i += 1) this.limit(`tokens:${client.principal}`, this.limits.tokensPerUserPerDay, 'tokens');
    const response = await this.signedFetch('POST', `${this.options.issuer.url}/v0/issue`, JSON.stringify({ blinded }));
    if (!response.ok) throw new HttpError(response.status === 429 ? 429 : 502, `issuer refused: ${response.status} ${await response.text()}`);
    return (await response.json()) as { signatures: string[] };
  }

  /** Origin: an anonymous request is admitted on a valid, unspent token bound to this domain, and nothing else. */
  private async deliverAnonymous({ id, to, kind, payload, anonymousToken }: Delivery): Promise<DeliveryResult> {
    if (kind !== 'request' || !anonymousToken) throw new HttpError(400, 'anonymous deliveries are requests with a token');
    if (!this.options.issuer) throw new HttpError(403, 'this server does not accept anonymous requests');
    let nonce: string;
    try {
      nonce = verifyToken(anonymousToken, this.options.domain, [this.options.issuer.key]);
    } catch (error) {
      throw new HttpError(403, describe(error));
    }
    if (!this.store.spend(nonce)) throw new HttpError(403, 'token has already been spent');
    const result = empty();
    const delivered: string[] = [];
    for (const address of to) {
      const { local, domain } = splitAddress(address);
      if (domain === this.options.domain && this.forIntake(kind, payload)) {
        if (this.store.bump(`anonymous:${local}`) <= this.limits.anonymousRequestsPerRecipientPerDay) await this.intakeRequest(address, id, undefined, payload);
        continue;
      }
      if (domain !== this.options.domain || !this.store.hasUser(local)) {
        result.unknown.push(address);
        continue;
      }
      if (this.store.bump(`anonymous:${local}`) > this.limits.anonymousRequestsPerRecipientPerDay) {
        result.rejected.push(address);
        continue;
      }
      this.store.push(local, { id, kind, from: '', sealed: true, payload });
      delivered.push(address);
    }
    return this.withReceipt(result, id, delivered, []);
  }

  /** A directory read with no requester behind it: the public answer, on a small per-source budget. */
  private anonymousLookup(source: string, local: string): DirectoryEntry {
    const key = `lookup:ip:${source}`;
    if (this.store.count(key) >= this.limits.anonymousLookupsPerIpPerDay) throw new HttpError(429, 'too many anonymous lookups today');
    this.store.bump(key, this.store.hasUser(local) ? 1 : this.limits.missWeight);
    return this.directory(local, 'public');
  }

  /** Who is asking, as another server tells it: the domain it proved, and a hash of the user it vouches for. */
  private async requester(request: HttpRequest): Promise<{ domain: string; user: string } | null> {
    if (!request.headers['signet-domain']) return null;
    const domain = await this.authenticateDomain(request);
    return { domain, user: request.url.searchParams.get('requester') ?? 'unknown' };
  }

  /**
   * A directory read from outside. Servers authenticate as their domain and name a hashed requester;
   * anything else gets a small per-IP budget. Unknown addresses get the same signed not-enrolled answer
   * as real but unenrolled ones, so the directory can't be used to test which addresses exist.
   */
  /**
   * A signed call to another domain, to the first of its homes that answers. A home that can't be reached, says
   * 421, or fails with a 5xx is skipped; any other answer, including a refusal, is the answer.
   */
  private async signedFetchHomes(domain: string, method: 'GET' | 'POST', path: string, body = '', extra?: Record<string, string>): Promise<Response> {
    const policy = await this.options.resolver.policy(domain);
    const bases = policy.operators ? (policy.replicas ?? [policy.server]) : [policy.server];
    let last: Response | undefined;
    let failure: unknown;
    for (const base of bases) {
      try {
        const response = await this.signedFetch(method, `${base}${path}`, body, extra);
        if (response.status < 500 && response.status !== 421) return response;
        last = response;
      } catch (error) {
        failure = error;
      }
    }
    if (last) return last;
    throw failure;
  }

  private async remoteLookup(request: HttpRequest, local: string): Promise<DirectoryEntry> {
    const who = await this.requester(request);
    const keys = who
      ? [
          [`lookup:@${who.domain}`, this.limits.lookupsPerDomainPerDay, 'lookups from this domain'] as const,
          [`lookup:${who.domain}:${who.user}`, this.limits.lookupsPerRequesterPerDay, 'lookups from this user'] as const,
        ]
      : [[`lookup:ip:${request.remoteAddress}`, this.limits.anonymousLookupsPerIpPerDay, 'anonymous lookups'] as const];
    if (who) this.refuseScanningDomain(who.domain);
    for (const [key, max, what] of keys) if (this.store.count(key) >= max) throw new HttpError(429, `too many ${what} today`);
    // A release only counts for a requester that proves it is who the hash names (Section 4.7).
    const granted =
      who !== null &&
      this.store.hasViewGrant(local, who.user) &&
      (await this.requesterProven(optionalHeader(request.headers, 'signet-requester'), who.user, `${local}@${this.options.domain}`));
    const entry = this.directory(local, granted ? 'contact' : 'public');
    // A miss costs more than a hit, and a domain whose lookups mostly miss gets cut off: that is what scanning
    // looks like. The server counts real misses even when its answer doesn't say which it was.
    const miss = !this.store.hasUser(local);
    const weight = miss ? this.limits.missWeight : 1;
    for (const [key] of keys) this.store.bump(key, weight);
    if (who) {
      this.store.bump(`lookups:@${who.domain}`);
      if (miss) this.store.bump(`misses:@${who.domain}`);
    }
    return entry;
  }

  private refuseScanningDomain(domain: string): void {
    const lookups = this.store.count(`lookups:@${domain}`);
    if (lookups >= this.limits.missRatioAfter && this.store.count(`misses:@${domain}`) * 2 > lookups) {
      throw new HttpError(429, `lookups from ${domain} mostly find nobody; refusing for today`);
    }
  }

  /** Key packages are only handed to other Signet servers, with per-requester limits and a reusable last-resort fallback. */
  private async remoteClaim(request: HttpRequest, local: string): Promise<{ packages: ClaimedKeyPackage[] }> {
    const who = await this.requester(request);
    if (!who) throw new HttpError(401, 'key packages are only claimed by Signet servers');
    const { clients } = json<{ clients: string[] }>(request);
    this.limit(`claim:@${who.domain}`, this.limits.claimsPerDomainPerDay, 'key-package claims from this domain');
    return { packages: this.claim(local, clients, `${who.domain}:${who.user}`) };
  }

  private claim(local: string, clients: string[], requester: string): ClaimedKeyPackage[] {
    const user = this.store.user(local);
    if (!user) throw new HttpError(404, `${local} is not enrolled`);
    const log = replayLog(user.log);
    return clients.flatMap((clientId) => {
      if (!activeClient(log, clientId)) return [];
      this.limit(`claim:${requester}:${clientId}`, this.limits.claimsPerRequesterPerClientPerDay, `claims of ${clientId}`);
      const published = this.store.claimKeyPackage(clientId);
      return published ? [{ clientId, kpId: published.kpId, keyPackage: published.keyPackage }] : [];
    });
  }

  /** How this server names one of its clients to the home of the address it is looking up (Section 4.7). */
  private requesterHash(client: ClientCert): string {
    return requesterHash(client.principal);
  }

  /**
   * Whether a lookup that names a requester proves it is that requester (Section 4.7 step 3): the proof is
   * signed by an active client of the requester's account log, and that log is the one the requester's own
   * domain vouches for. The answer is remembered for the proof's lifetime.
   */
  private async requesterProven(proof: string | undefined, hash: string, target: string): Promise<boolean> {
    if (!proof) return false;
    try {
      const state = verifyRequesterProof(proof, hash, target);
      const { local, domain } = splitAddress(state.principal);
      const policy = await this.options.resolver.policy(domain);
      const response = await this.signedFetchHomes(domain, 'GET', `/v0/directory/${encodeURIComponent(local)}`);
      if (!response.ok) return false;
      const entry = (await response.json()) as DirectoryEntry;
      if (entry.status !== 'enrolled') return false;
      const verified = verifyDirectoryEntry(entry, policy);
      return verified.identityKey === state.identityKey && entry.card.card.logHead === state.head;
    } catch {
      return false;
    }
  }

  private async lookupFor(client: ClientCert, address: string, proof?: string): Promise<DirectoryEntry> {
    const { local, domain } = splitAddress(address);
    const target = `${local}@${domain}`;
    if (domain === this.options.domain) {
      if (target === client.principal) return this.directory(local, 'owner');
      const colleague = this.options.colleaguesSeeViews ?? true;
      return this.directory(local, colleague || this.store.hasViewGrant(local, this.requesterHash(client)) ? 'contact' : 'public');
    }
    const query = new URLSearchParams({ requester: this.requesterHash(client) });
    const response = await this.signedFetchHomes(domain, 'GET', `/v0/directory/${encodeURIComponent(local)}?${query.toString()}`, '', proof ? { 'signet-requester': proof } : undefined);
    if (!response.ok) throw new HttpError(response.status === 429 ? 429 : 502, `lookup at ${domain} failed: ${response.status} ${await response.text()}`);
    return (await response.json()) as DirectoryEntry;
  }

  private async claimFor(client: ClientCert, { address, clients }: { address: string; clients: string[] }): Promise<{ packages: ClaimedKeyPackage[] }> {
    const { local, domain } = splitAddress(address);
    if (domain === this.options.domain) return { packages: this.claim(local, clients, `${domain}:${this.requesterHash(client)}`) };
    const query = new URLSearchParams({ requester: this.requesterHash(client) });
    const response = await this.signedFetchHomes(domain, 'POST', `/v0/directory/${encodeURIComponent(local)}/claim?${query.toString()}`, JSON.stringify({ clients }));
    if (!response.ok) throw new HttpError(response.status === 429 ? 429 : 502, `claim at ${domain} failed: ${response.status} ${await response.text()}`);
    return (await response.json()) as { packages: ClaimedKeyPackage[] };
  }

  /** Log queries for clients. Only logs this server is configured to use, so it can't be pointed at arbitrary URLs. */
  private async logQueryFor(client: ClientCert, op: string, params: URLSearchParams): Promise<unknown> {
    const logUrl = params.get('log') ?? this.options.log.url;
    const logs = this.options.queryableLogs ?? [this.options.log];
    if (!logs.some((log) => log.url === logUrl)) throw new HttpError(400, 'this server does not query that log');
    const query = new URLSearchParams({ requester: this.requesterHash(client) });
    if (op === 'consistency') {
      query.set('first', params.get('first') ?? '0');
      query.set('second', params.get('second') ?? '0');
    } else {
      query.set('key', params.get('index') ?? '');
      query.set('domain', params.get('domain') ?? '');
    }
    const response = await this.signedFetch('GET', `${logUrl}/v0/${op}?${query.toString()}`);
    if (!response.ok) throw new HttpError(response.status === 429 ? 429 : 502, `log query failed: ${response.status} ${await response.text()}`);
    return response.json();
  }

  /** A request from one of this domain's own clients, signed by a key active in its principal's log. */
  private authenticateClient(request: HttpRequest): ClientCert {
    const principal = header(request.headers, 'signet-principal');
    const { local, domain } = splitAddress(principal);
    const user = this.store.user(local);
    if (domain !== this.options.domain || !user) throw new HttpError(401, `${principal} is not enrolled here`);
    const cert = activeClient(replayLog(user.log), header(request.headers, 'signet-client'));
    const signed =
      cert &&
      verifyClientAuth(
        cert.sigKey,
        header(request.headers, 'signet-sig'),
        header(request.headers, 'signet-ts'),
        header(request.headers, 'signet-nonce'),
        request.method,
        request.path,
        request.body,
      );
    if (!cert || !signed) throw new HttpError(401, 'client signature is invalid or the client is not active');
    if (!this.store.replays.firstUse(`${principal} ${cert.clientId} ${header(request.headers, 'signet-sig')}`)) throw new HttpError(401, 'this request was already used');
    return cert;
  }

  /** A request from another Signet server, signed with the key in that domain's published policy. */
  private async authenticateDomain(request: HttpRequest): Promise<string> {
    const domain = header(request.headers, 'signet-domain');
    const policy = await this.options.resolver.policy(domain);
    const home = request.headers['signet-home'];
    const ok = verifyDomainCall(
      policy,
      { sig: header(request.headers, 'signet-sig'), ts: header(request.headers, 'signet-ts'), nonce: header(request.headers, 'signet-nonce'), home: typeof home === 'string' ? home : undefined },
      request.method,
      request.path,
      request.body,
    );
    if (!ok) throw new HttpError(401, `request is not signed by ${domain}`);
    if (!this.store.replays.firstUse(`${domain} ${header(request.headers, 'signet-sig')}`)) throw new HttpError(401, 'this request was already used');
    return domain;
  }

  private async submit(client: ClientCert, envelope: Envelope): Promise<DeliveryResult & { id: string }> {
    if (!hasScope(client, 'send')) throw new HttpError(403, `${client.label} may not send`);
    if (!Array.isArray(envelope.to) || envelope.to.length === 0) throw new HttpError(400, 'to must list recipients');
    if (!CLIENT_KINDS.includes(envelope.kind)) throw new HttpError(400, `clients can't submit ${envelope.kind}`);
    if (envelope.token && !SEALABLE_KINDS.includes(envelope.kind)) throw new HttpError(400, `${envelope.kind} can't be sealed`);
    if (envelope.anonymousToken && envelope.kind !== 'request') throw new HttpError(400, 'only requests are sent anonymously');
    if (envelope.id !== undefined && !/^[A-Za-z0-9_-]{8,64}$/.test(envelope.id)) throw new HttpError(400, 'id must be 8 to 64 letters, digits, - or _');
    const id = envelope.id ?? randomId('i');
    // Sealed and anonymous deliveries leave here without a sender; only this server, which already knows its own user, keeps it for bounces.
    const base = { id, to: envelope.to, kind: envelope.kind, payload: envelope.payload };
    const delivery: Delivery = envelope.token
      ? { ...base, token: envelope.token }
      : envelope.anonymousToken
        ? { ...base, anonymousToken: envelope.anonymousToken }
        : { ...base, from: client.principal };
    const byDomain = new Map<string, string[]>();
    for (const address of envelope.to) {
      const { domain } = splitAddress(address);
      byDomain.set(domain, [...(byDomain.get(domain) ?? []), address]);
    }
    const results = await Promise.all(
      [...byDomain].map(([domain, to]) => this.deliverToDomain(domain, { ...delivery, to }, client.principal)),
    );
    return { id, ...merge(results) };
  }

  /** Where else this domain's own mail has to go: the other homes in its operators statement (Section 6.9.5). */
  private peerHomes(): string[] {
    const homes = this.options.operators?.body.homes ?? [];
    return homes.filter((home) => home.key !== this.options.homeKey?.publicKey).map((home) => new URL(home.url).origin);
  }

  /** Deliver to a domain: here if it is this one, to its other homes as well when it has several, and by relay if it is another. */
  private async deliverToDomain(domain: string, delivery: Delivery, sender: string): Promise<DeliveryResult> {
    if (domain !== this.options.domain) return this.relay(domain, delivery, sender);
    const local = () => (delivery.anonymousToken ? this.deliverAnonymous(delivery) : this.deliverLocal(delivery));
    const peers = this.peerHomes();
    return peers.length === 0 ? local() : this.fanOut(domain, delivery, sender, peers, local);
  }

  /**
   * Deliver to every home of a domain at the same time (Section 6.9.5). The domain counts as delivered once
   * any home accepts; a home that couldn't be reached is retried on its own; the sender hears of a bounce
   * only when every home refused for good.
   */
  private async fanOut(domain: string, delivery: Delivery, sender: string, homes: string[], local?: () => Promise<DeliveryResult>): Promise<DeliveryResult> {
    const attempts: { home?: string; run: () => Promise<DeliveryResult> }[] = [
      ...(local ? [{ run: local }] : []),
      ...homes.map((home) => ({ home, run: () => this.relayOnce(domain, delivery, home) })),
    ];
    const settled = await Promise.allSettled(attempts.map((attempt) => attempt.run()));
    const answers: DeliveryResult[] = [];
    const retry: { home: string; reason: string }[] = [];
    let refusal: RelayError | undefined;
    settled.forEach((outcome, i) => {
      if (outcome.status === 'fulfilled') answers.push(outcome.value);
      else if (!attempts[i].home) throw outcome.reason;
      else if (outcome.reason instanceof RelayError && outcome.reason.permanent) refusal = outcome.reason;
      else retry.push({ home: attempts[i].home as string, reason: describe(outcome.reason) });
    });
    const accepted = answers.length > 0;
    for (const { home, reason } of retry) this.queueRetry(domain, delivery, sender, reason, home, accepted);
    if (!accepted) {
      if (retry.length > 0) return { ...empty(), queued: delivery.to };
      this.bounce(sender, delivery, (refusal as RelayError | undefined)?.message ?? `delivery to ${domain} failed`);
      return empty();
    }
    // An address is delivered if any home that answered took it; unknown only if every one says so.
    const result = empty();
    const receipts = answers.flatMap((answer) => answer.receipts ?? []);
    if (receipts.length > 0) result.receipts = receipts;
    for (const address of delivery.to) {
      const took = answers.some((answer) => !answer.unknown.includes(address) && !answer.rejected.includes(address));
      if (took) continue;
      if (answers.every((answer) => answer.unknown.includes(address))) result.unknown.push(address);
      else result.rejected.push(address);
    }
    return result;
  }

  private queueRetry(domain: string, delivery: Delivery, sender: string, reason: string, home: string | undefined, accepted: boolean): void {
    const delays = this.options.retryDelaysMs ?? DEFAULT_RETRY_DELAYS;
    const entry: Outbound = { id: randomId('o'), domain, delivery, sender, attempt: 0, dueAt: Date.now() + (delays[0] ?? 0), reason, ...(home ? { home, accepted } : {}) };
    // Saved before the client hears "queued", so a restart can't lose it.
    this.store.saveOutbound(entry);
    this.schedule(entry);
  }

  private async relay(domain: string, delivery: Delivery, sender: string): Promise<DeliveryResult> {
    const homes = await this.options.resolver.policy(domain).then(
      (policy) => homeGroups(policy).map((group) => group[0]),
      () => [],
    );
    if (homes.length > 1) return this.fanOut(domain, delivery, sender, homes);
    try {
      return await this.relayOnce(domain, delivery);
    } catch (error) {
      if (error instanceof RelayError && error.permanent) {
        this.bounce(sender, delivery, error.message);
        return empty();
      }
      this.queueRetry(domain, delivery, sender, describe(error), undefined, false);
      return { ...empty(), queued: delivery.to };
    }
  }

  /** One attempt at one home: `home` when the domain has several, else the home its policy names. */
  private async relayOnce(domain: string, delivery: Delivery, home?: string): Promise<DeliveryResult> {
    const policy = await this.options.resolver.policy(domain);
    const target = home ?? policy.server;
    // Padded, so the size of a delivery on the wire says little (Section 10.2).
    const body = padJson(delivery as unknown as Record<string, unknown>);
    if (!delivery.token && !delivery.anonymousToken) return this.answer(domain, await this.signedFetch('POST', `${target}/v0/deliver`, body));
    // Sealed and anonymous deliveries aren't signed by this domain: a token authorizes them. Through an OHTTP
    // relay, the receiving server doesn't even see which server sent them.
    const path = delivery.token ? '/v0/deliver-sealed' : '/v0/deliver-anonymous';
    // Each home has its own gateway, vouched for by the owner's statement.
    const gateway = homeGateway(policy, target);
    if (this.options.ohttpRelay && gateway) return this.relayOblivious(domain, target, gateway.keys, path, body);
    return this.answer(domain, await this.fetchImpl(`${target}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body }));
  }

  private async answer(domain: string, response: Response): Promise<DeliveryResult> {
    if (!response.ok) {
      const permanent = response.status >= 400 && response.status < 500 && response.status !== 429 && response.status !== 421;
      throw new RelayError(`delivery to ${domain} failed: ${response.status} ${await response.text()}`, permanent);
    }
    return (await response.json()) as DeliveryResult;
  }

  private async relayOblivious(domain: string, target: string, keys: string, path: string, body: string): Promise<DeliveryResult> {
    const authority = new URL(target).host;
    const inner = encodeRequest({ method: 'POST', scheme: 'https', authority, path, headers: [['content-type', 'application/json']], body: Buffer.from(body) });
    const { message, pending } = await encapsulateRequest(keys, inner);
    const relayed = await this.fetchImpl(`${this.options.ohttpRelay}/v0/relay?domain=${encodeURIComponent(domain)}&home=${encodeURIComponent(target)}`, {
      method: 'POST',
      headers: { 'content-type': OHTTP_REQUEST_TYPE },
      body: message,
    });
    if (!relayed.ok) throw new RelayError(`relay to ${domain} failed: ${relayed.status} ${await relayed.text()}`, false);
    const response = decodeResponse(decapsulateResponse(pending, Buffer.from(await relayed.arrayBuffer())));
    return this.answer(domain, new Response(Buffer.from(response.body), { status: response.status, headers: { 'content-type': 'application/json' } }));
  }

  private cancelRetries(): void {
    for (const timer of this.timers) clearTimeout(timer);
    this.timers.clear();
  }

  /** A new primary rebuilds what it derives from the store and takes over the retry queue. */
  private becamePrimary(): void {
    // The first primary names the mailbox store; the name is replicated, so every replica keeps it.
    if (!this.store.epoch()) this.store.setEpoch(randomId('e'));
    this.unlisted.clear();
    for (const local of this.store.userLocals()) this.setListing(local, replayLog(this.store.user(local)?.log ?? []).unlisted);
    this.cancelRetries();
    for (const entry of this.store.outbound()) this.schedule(entry);
  }

  /** Try a queued delivery when it's due; on failure, save the next attempt or bounce it to the sender. */
  private schedule(entry: Outbound): void {
    const timer = setTimeout(() => {
      this.timers.delete(timer);
      // A standby keeps the queue but doesn't work it; whoever is primary does.
      if (this.cluster && !this.cluster.isPrimary()) return;
      const delivery = entry.delivery as Delivery;
      this.relayOnce(entry.domain, delivery, entry.home).then(
        (result) => {
          this.store.removeOutbound(entry.id);
          // The other homes still being retried for this delivery no longer risk a bounce.
          if (entry.home) for (const other of this.siblings(entry)) this.store.saveOutbound({ ...other, accepted: true });
          // A retry that lands later is proved to the sender in its own mailbox, as a bounce is.
          if (result.receipts?.length) {
            this.store.push(splitAddress(entry.sender).local, { id: randomId('r'), kind: 'receipt', from: `postmaster@${this.options.domain}`, payload: { id: delivery.id, receipts: result.receipts } });
          }
        },
        (error: unknown) => {
          const delays = this.options.retryDelaysMs ?? DEFAULT_RETRY_DELAYS;
          const attempt = entry.attempt + 1;
          const current = this.store.outbound().find((queued) => queued.id === entry.id) ?? entry;
          if ((error instanceof RelayError && error.permanent) || attempt >= delays.length) {
            const reason = error instanceof RelayError && error.permanent ? error.message : `gave up after ${attempt + 1} attempts: ${describe(error)}`;
            const lastHome = this.siblings(entry).length === 0;
            this.store.removeOutbound(entry.id);
            // With several homes, only the last one to give up, and only if none accepted, is a bounce.
            if (!entry.home || (!current.accepted && lastHome)) this.bounce(entry.sender, delivery, reason);
            return;
          }
          const next = { ...current, attempt, dueAt: Date.now() + delays[attempt], reason: describe(error) };
          this.store.saveOutbound(next);
          this.schedule(next);
        },
      );
    }, Math.max(0, entry.dueAt - Date.now()));
    timer.unref();
    this.timers.add(timer);
  }

  /** Other queued retries of the same delivery to the same domain, at its other homes. */
  private siblings(entry: Outbound): Outbound[] {
    return this.store.outbound().filter((other) => other.id !== entry.id && other.domain === entry.domain && (other.delivery as Delivery).id === (entry.delivery as Delivery).id);
  }

  /** Tell the sender, in their own mailbox, that a delivery failed for good. */
  private bounce(sender: string, delivery: Delivery, reason: string): void {
    this.store.push(splitAddress(sender).local, {
      id: randomId('b'),
      kind: 'bounce',
      from: `postmaster@${this.options.domain}`,
      payload: { id: delivery.id, to: delivery.to, reason },
    });
  }

  private deliverSigned(domain: string, delivery: Delivery): Promise<DeliveryResult> {
    if (delivery.token) throw new HttpError(400, 'sealed deliveries go to /v0/deliver-sealed');
    if (!delivery.from || splitAddress(delivery.from).domain !== domain) throw new HttpError(403, `${domain} can't send as ${delivery.from}`);
    return this.deliverLocal(delivery);
  }

  private async deliverLocal({ id, from, to, kind, payload, token }: Delivery): Promise<DeliveryResult> {
    if (!CLIENT_KINDS.includes(kind)) throw new HttpError(400, `unknown kind ${kind}`);
    if (token && !SEALABLE_KINDS.includes(kind)) throw new HttpError(400, `${kind} can't be sealed`);
    if (!token && !from) throw new HttpError(400, 'a delivery needs a sender or a token');
    const result = empty();
    const delivered: string[] = [];
    const held: string[] = [];
    for (const address of to) {
      const { local, domain } = splitAddress(address);
      if (domain === this.options.domain && !token && from && this.forIntake(kind, payload)) {
        // Same per-sender limits as any request, and the same answer whether or not the address exists.
        const fromSender = this.store.bump(`request:${local}:${from}`);
        const fromDomain = this.store.bump(`request:${local}:@${splitAddress(from).domain}`);
        if (fromSender <= this.limits.requestsPerSenderPerDay && fromDomain <= this.limits.requestsPerDomainPerDay) await this.intakeRequest(address, id, from, payload);
        continue;
      }
      if (domain !== this.options.domain || !this.store.hasUser(local)) {
        result.unknown.push(address);
        continue;
      }
      if (token) {
        const hash = deliveryTokenHash(token, address);
        const item = { id, kind, from: '', sealed: true, payload };
        if (this.store.hasToken(local, hash)) {
          this.store.push(local, item);
          delivered.push(address);
        } else if (this.store.park(local, hash, item, PARK_TTL_MS, PARK_CAP)) held.push(address);
        else result.rejected.push(address);
        continue;
      }
      const sender = from as string;
      if (kind === 'request') {
        const fromSender = this.store.bump(`request:${local}:${sender}`);
        const fromDomain = this.store.bump(`request:${local}:@${splitAddress(sender).domain}`);
        if (fromSender > this.limits.requestsPerSenderPerDay || fromDomain > this.limits.requestsPerDomainPerDay) {
          result.rejected.push(address);
          continue;
        }
      }
      this.store.push(local, { id, kind, from: sender, payload });
      delivered.push(address);
    }
    return this.withReceipt(result, id, delivered, held);
  }

  /**
   * Add this home's receipt for what it took. An address delivered through an intake gets none: the answer for
   * an unlisted address must look the same as for one that doesn't exist.
   */
  private withReceipt(result: DeliveryResult, id: string, delivered: string[], held: string[]): DeliveryResult {
    if (delivered.length === 0 && held.length === 0) return result;
    const { key, asHome } = this.answerSigner();
    return { ...result, receipts: [signReceipt(key, { id, domain: this.options.domain, to: delivered, held }, new Date(), asHome)] };
  }

  /**
   * Vouch, with the domain key, that this user is sending plain email with this From, To and Subject.
   * Used for mail this server sends and for mail the client sends itself (Gmail mode).
   */
  private async attestHeader(client: ClientCert, to: string[], subject: string, request: HttpRequest, bodyHash: string, audience?: 'humans', htmlHash?: string): Promise<string> {
    if (!hasScope(client, 'send')) throw new HttpError(403, `${client.label} may not send`);
    const user = this.store.user(splitAddress(client.principal).local);
    if (!user) throw new HttpError(404, 'sender is not enrolled');
    if (!Array.isArray(to) || to.length === 0 || typeof subject !== 'string') throw new HttpError(400, 'to and subject are required');
    if (typeof bodyHash !== 'string' || !bodyHash.startsWith('sha256:')) throw new HttpError(400, 'bodyHash must be a sha256: hash of the message body');
    if (htmlHash !== undefined && (typeof htmlHash !== 'string' || !htmlHash.startsWith('sha256:'))) throw new HttpError(400, 'htmlHash must be a sha256: hash of the html part');
    // Without the domain key, the registrar attests, shown the client's own signed request.
    if (!this.options.domainKey && this.options.registrar) {
      const names = ['signet-principal', 'signet-client', 'signet-ts', 'signet-nonce', 'signet-sig'];
      const headers = Object.fromEntries(names.map((name) => [name, header(request.headers, name)]));
      return this.options.registrar.attest({ principal: client.principal, to, subject, bodyHash, htmlHash, audience, server: this.http.publicUrl, proof: { method: request.method, path: request.path, body: request.body.toString('utf8'), headers } });
    }
    return attestedSignetHeader(this.domainSigner(), this.http.publicUrl, user.binding.identityKey, { from: client.principal, to, subject, bodyHash, htmlHash, audience });
  }

  private async sendLegacy(
    client: ClientCert,
    mail: { to: string[]; subject: string; text: string; html?: string; humansOnly?: boolean; attachments?: { filename: string; contentType: string; content: string }[] },
    request: HttpRequest,
  ): Promise<{ messageId: string }> {
    if (!hasScope(client, 'send')) throw new HttpError(403, `${client.label} may not send`);
    if (!this.options.outbound) throw new HttpError(501, 'this server does not send plain email');
    if (mail.html !== undefined && (typeof mail.html !== 'string' || Buffer.byteLength(mail.html) > MAX_HTML_BYTES)) throw new HttpError(400, `html is at most ${MAX_HTML_BYTES} bytes`);
    const user = this.store.user(splitAddress(client.principal).local);
    if (!user) throw new HttpError(404, 'sender is not enrolled');
    const messageId = await this.options.outbound.send({
      from: client.principal,
      to: mail.to,
      subject: mail.subject,
      text: mail.text,
      ...(mail.html === undefined ? {} : { html: mail.html }),
      headers: { Signet: await this.attestHeader(client, mail.to, mail.subject, request, hashBody(mail.text), mail.humansOnly ? 'humans' : undefined, mail.html === undefined ? undefined : hashBody(mail.html)), ...(mail.humansOnly ? { [AUDIENCE_HEADER]: 'humans' } : {}) },
      attachments: mail.attachments ?? [],
    });
    return { messageId };
  }
}
