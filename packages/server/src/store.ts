import { DatabaseSync } from 'node:sqlite';
import type { DomainBinding, GatewayKey, KeyPair, LogEntry, MailItem, SignedCard, SignedView, VrfKey } from '@signet/lib';
import { AUTH_SKEW_MS, ReplayCache } from '@signet/lib';
import { decode, encode } from './codec';

export interface UserRecord {
  binding: DomainBinding;
  log: LogEntry[];
  card: SignedCard;
  view: SignedView;
}

export interface PublishedKeyPackage {
  kpId: string;
  keyPackage: string;
}

/** The home server's own keys, kept with its data so a restart serves the same policy. */
export interface ServerKeys {
  vrf: VrfKey;
  gateway: GatewayKey;
  intake: KeyPair | null;
}

/** A delivery to another domain that failed for now, waiting for its next attempt. */
export interface Outbound {
  id: string;
  domain: string;
  /** The delivery as sent: JSON the relay code built. */
  delivery: unknown;
  sender: string;
  attempt: number;
  dueAt: number;
  reason: string;
  /** For a domain with several homes: the one this entry retries. Unset means whichever home the policy names. */
  home?: string;
  /** Another home of the domain has already accepted this delivery, so giving up here is not a bounce. */
  accepted?: boolean;
}

type Parked = Omit<MailItem, 'seq' | 'receivedAt'>;

/** Something that answers "first time?" for a key, within a time window. */
export interface SeenOnce {
  firstUse(key: string, now?: number): boolean;
}

/**
 * Everything a home server keeps: accounts, mailboxes (sealed requests, MLS ciphertext and legacy mail
 * encrypted on arrival, never plaintext), key packages, delivery tokens, blobs (ciphertext), spent
 * Privacy Pass nonces, contacts, view grants, daily counters, replay caches, organisation claims, its own
 * keys, and deliveries waiting to be retried. Every method is one atomic change.
 */
export interface Store {
  user(local: string): UserRecord | undefined;
  hasUser(local: string): boolean;
  putUser(local: string, record: UserRecord): void;
  deleteUser(local: string): void;
  userLocals(): string[];

  /** Add an item to a mailbox. An item whose id is already there is not added again; the one already stored is returned (Section 6.9.5). */
  push(local: string, item: Parked): MailItem;
  mailbox(local: string, after?: number): MailItem[];

  addKeyPackages(clientId: string, packages: PublishedKeyPackage[]): void;
  countKeyPackages(clientId: string): number;
  setLastResort(clientId: string, keyPackage: PublishedKeyPackage): void;
  hasLastResort(clientId: string): boolean;
  /** Key packages are single use: claiming one removes it. When none are left, the reusable last-resort one is handed out. */
  claimKeyPackage(clientId: string): PublishedKeyPackage | undefined;

  /** Sealed-sender delivery tokens a user's clients have registered, as hashes. */
  updateTokens(local: string, add: string[], remove: string[]): void;
  hasToken(local: string, hash: string): boolean;
  /**
   * Hold a sealed delivery whose token isn't registered yet: the recipient may simply not have joined
   * the thread. Parked items expire, and each user has a cap, so random tokens can't fill a mailbox.
   */
  park(local: string, hash: string, item: Parked, ttlMs: number, cap: number): boolean;
  /** Move parked deliveries for newly registered tokens into the mailbox, in arrival order. */
  release(local: string, hashes: string[]): number;

  putBlob(id: string, data: Buffer): void;
  blob(id: string): Buffer | undefined;

  /** Record a Privacy Pass token nonce. False if it was already spent. */
  spend(nonce: string): boolean;

  /** A user's contacts and trusted domains, shared by all their clients. */
  addContacts(local: string, contacts: string[], trustedDomains: string[]): void;
  contactsOf(local: string): { contacts: string[]; trustedDomains: string[] };

  /** Hashed requesters a user has released their contact view to. */
  updateViewGrants(local: string, add: string[], remove: string[]): void;
  hasViewGrant(local: string, requester: string): boolean;

  /** Add to an event's count in today's bucket and return the new total. */
  bump(key: string, by?: number, now?: Date): number;
  count(key: string, now?: Date): number;

  /** What the organisation says about its people ("team:corporate"). Set by its admin. */
  claims(local: string): string[];
  setClaims(local: string, claims: string[]): void;

  /** Signed client and server requests already accepted, so a captured one can't be replayed. */
  readonly replays: SeenOnce;
  /** Recovery proofs already used: each opens the log once. */
  readonly recoveryProofs: SeenOnce;

  serverKeys(): ServerKeys | undefined;
  setServerKeys(keys: ServerKeys): void;

  /**
   * Names this mailbox store. It changes if the store is lost and started over, so a client whose cursor
   * points into the old one notices (Section 6.9.6).
   */
  epoch(): string | undefined;
  setEpoch(id: string): void;

  saveOutbound(entry: Outbound): void;
  removeOutbound(id: string): void;
  outbound(): Outbound[];

  close(): void;
}

/** A store that can be written out whole and read back, so a replica can compact its log (Section 6.8.6). */
export interface SnapshotStore extends Store {
  snapshot(): unknown;
  /** Replace everything with a snapshot, or with nothing for null. */
  restore(data: unknown): void;
}

const today = (now: Date) => now.toISOString().slice(0, 10);

/** Everything in memory, for tests and local demos. Gone on restart. */
export class MemoryStore implements SnapshotStore {
  private readonly users = new Map<string, UserRecord>();
  private readonly mailboxes = new Map<string, MailItem[]>();
  private readonly keyPackages = new Map<string, PublishedKeyPackage[]>();
  private readonly lastResort = new Map<string, PublishedKeyPackage>();
  private readonly tokens = new Map<string, Set<string>>();
  private readonly parked = new Map<string, { hash: string; item: Parked; until: number }[]>();
  private readonly blobs = new Map<string, Buffer>();
  private readonly counters = new Map<string, number>();
  private readonly spent = new Set<string>();
  private readonly viewGrants = new Map<string, Set<string>>();
  private readonly contacts = new Map<string, { contacts: Set<string>; trustedDomains: Set<string> }>();
  private readonly orgClaims = new Map<string, string[]>();
  private readonly pending = new Map<string, Outbound>();
  private keys?: ServerKeys;
  private epochId?: string;
  replays = new ReplayCache();
  recoveryProofs = new ReplayCache();

  snapshot(): unknown {
    return encode({
      users: [...this.users],
      mailboxes: [...this.mailboxes],
      keyPackages: [...this.keyPackages],
      lastResort: [...this.lastResort],
      tokens: [...this.tokens].map(([key, set]) => [key, [...set]]),
      parked: [...this.parked],
      blobs: [...this.blobs],
      counters: [...this.counters],
      spent: [...this.spent],
      viewGrants: [...this.viewGrants].map(([key, set]) => [key, [...set]]),
      contacts: [...this.contacts].map(([key, value]) => [key, { contacts: [...value.contacts], trustedDomains: [...value.trustedDomains] }]),
      orgClaims: [...this.orgClaims],
      pending: [...this.pending],
      keys: this.keys ?? null,
      epoch: this.epochId ?? null,
      replays: this.replays.entries(),
      recoveryProofs: this.recoveryProofs.entries(),
    });
  }

  restore(data: unknown): void {
    const saved = (data === null ? {} : decode(data)) as Record<string, [string, unknown][] | string[] | ServerKeys | string | null | undefined>;
    const pairs = <V>(name: string): [string, V][] => (saved[name] ?? []) as [string, V][];
    this.users.clear();
    pairs<UserRecord>('users').forEach(([key, value]) => this.users.set(key, value));
    this.mailboxes.clear();
    pairs<MailItem[]>('mailboxes').forEach(([key, value]) => this.mailboxes.set(key, value));
    this.keyPackages.clear();
    pairs<PublishedKeyPackage[]>('keyPackages').forEach(([key, value]) => this.keyPackages.set(key, value));
    this.lastResort.clear();
    pairs<PublishedKeyPackage>('lastResort').forEach(([key, value]) => this.lastResort.set(key, value));
    this.tokens.clear();
    pairs<string[]>('tokens').forEach(([key, value]) => this.tokens.set(key, new Set(value)));
    this.parked.clear();
    pairs<{ hash: string; item: Parked; until: number }[]>('parked').forEach(([key, value]) => this.parked.set(key, value));
    this.blobs.clear();
    pairs<Buffer>('blobs').forEach(([key, value]) => this.blobs.set(key, value));
    this.counters.clear();
    pairs<number>('counters').forEach(([key, value]) => this.counters.set(key, value));
    this.spent.clear();
    ((saved.spent ?? []) as string[]).forEach((nonce) => this.spent.add(nonce));
    this.viewGrants.clear();
    pairs<string[]>('viewGrants').forEach(([key, value]) => this.viewGrants.set(key, new Set(value)));
    this.contacts.clear();
    pairs<{ contacts: string[]; trustedDomains: string[] }>('contacts').forEach(([key, value]) =>
      this.contacts.set(key, { contacts: new Set(value.contacts), trustedDomains: new Set(value.trustedDomains) }),
    );
    this.orgClaims.clear();
    pairs<string[]>('orgClaims').forEach(([key, value]) => this.orgClaims.set(key, value));
    this.pending.clear();
    pairs<Outbound>('pending').forEach(([key, value]) => this.pending.set(key, value));
    this.keys = (saved.keys as ServerKeys | null | undefined) ?? undefined;
    this.epochId = (saved.epoch as string | null | undefined) ?? undefined;
    this.replays = new ReplayCache(undefined, (saved.replays ?? []) as unknown as [string, number][]);
    this.recoveryProofs = new ReplayCache(undefined, (saved.recoveryProofs ?? []) as unknown as [string, number][]);
  }

  user(local: string): UserRecord | undefined {
    const record = this.users.get(local);
    return record ? structuredClone(record) : undefined;
  }

  hasUser(local: string): boolean {
    return this.users.has(local);
  }

  putUser(local: string, record: UserRecord): void {
    this.users.set(local, structuredClone(record));
  }

  deleteUser(local: string): void {
    this.users.delete(local);
  }

  userLocals(): string[] {
    return [...this.users.keys()];
  }

  push(local: string, item: Parked): MailItem {
    const mailbox = this.mailboxes.get(local) ?? [];
    const existing = mailbox.find((entry) => entry.id === item.id);
    if (existing) return existing;
    const stored = { ...item, seq: mailbox.length + 1, receivedAt: new Date().toISOString() };
    mailbox.push(stored);
    this.mailboxes.set(local, mailbox);
    return stored;
  }

  mailbox(local: string, after = 0): MailItem[] {
    return (this.mailboxes.get(local) ?? []).filter((item) => item.seq > after);
  }

  addKeyPackages(clientId: string, packages: PublishedKeyPackage[]): void {
    this.keyPackages.set(clientId, [...(this.keyPackages.get(clientId) ?? []), ...packages]);
  }

  countKeyPackages(clientId: string): number {
    return this.keyPackages.get(clientId)?.length ?? 0;
  }

  setLastResort(clientId: string, keyPackage: PublishedKeyPackage): void {
    this.lastResort.set(clientId, keyPackage);
  }

  hasLastResort(clientId: string): boolean {
    return this.lastResort.has(clientId);
  }

  claimKeyPackage(clientId: string): PublishedKeyPackage | undefined {
    return this.keyPackages.get(clientId)?.shift() ?? this.lastResort.get(clientId);
  }

  updateTokens(local: string, add: string[], remove: string[]): void {
    const tokens = this.tokens.get(local) ?? new Set<string>();
    add.forEach((hash) => tokens.add(hash));
    remove.forEach((hash) => tokens.delete(hash));
    this.tokens.set(local, tokens);
  }

  hasToken(local: string, hash: string): boolean {
    return this.tokens.get(local)?.has(hash) ?? false;
  }

  park(local: string, hash: string, item: Parked, ttlMs: number, cap: number): boolean {
    const now = Date.now();
    const waiting = (this.parked.get(local) ?? []).filter((entry) => entry.until > now);
    if (waiting.length >= cap) return false;
    waiting.push({ hash, item, until: now + ttlMs });
    this.parked.set(local, waiting);
    return true;
  }

  release(local: string, hashes: string[]): number {
    const now = Date.now();
    const waiting = (this.parked.get(local) ?? []).filter((entry) => entry.until > now);
    const ready = waiting.filter((entry) => hashes.includes(entry.hash));
    this.parked.set(local, waiting.filter((entry) => !hashes.includes(entry.hash)));
    ready.forEach((entry) => this.push(local, entry.item));
    return ready.length;
  }

  putBlob(id: string, data: Buffer): void {
    this.blobs.set(id, data);
  }

  blob(id: string): Buffer | undefined {
    return this.blobs.get(id);
  }

  spend(nonce: string): boolean {
    if (this.spent.has(nonce)) return false;
    this.spent.add(nonce);
    return true;
  }

  addContacts(local: string, contacts: string[], trustedDomains: string[]): void {
    const entry = this.contacts.get(local) ?? { contacts: new Set<string>(), trustedDomains: new Set<string>() };
    contacts.forEach((address) => entry.contacts.add(address.toLowerCase()));
    trustedDomains.forEach((domain) => entry.trustedDomains.add(domain.toLowerCase()));
    this.contacts.set(local, entry);
  }

  contactsOf(local: string): { contacts: string[]; trustedDomains: string[] } {
    const entry = this.contacts.get(local);
    return { contacts: [...(entry?.contacts ?? [])], trustedDomains: [...(entry?.trustedDomains ?? [])] };
  }

  updateViewGrants(local: string, add: string[], remove: string[]): void {
    const grants = this.viewGrants.get(local) ?? new Set<string>();
    add.forEach((hash) => grants.add(hash));
    remove.forEach((hash) => grants.delete(hash));
    this.viewGrants.set(local, grants);
  }

  hasViewGrant(local: string, requester: string): boolean {
    return this.viewGrants.get(local)?.has(requester) ?? false;
  }

  bump(key: string, by = 1, now = new Date()): number {
    const bucket = `${today(now)}:${key}`;
    const total = (this.counters.get(bucket) ?? 0) + by;
    this.counters.set(bucket, total);
    return total;
  }

  count(key: string, now = new Date()): number {
    return this.counters.get(`${today(now)}:${key}`) ?? 0;
  }

  claims(local: string): string[] {
    return this.orgClaims.get(local) ?? [];
  }

  setClaims(local: string, claims: string[]): void {
    this.orgClaims.set(local, claims);
  }

  serverKeys(): ServerKeys | undefined {
    return this.keys;
  }

  epoch(): string | undefined {
    return this.epochId;
  }

  setEpoch(id: string): void {
    this.epochId = id;
  }

  setServerKeys(keys: ServerKeys): void {
    this.keys = keys;
  }

  saveOutbound(entry: Outbound): void {
    this.pending.set(entry.id, entry);
  }

  removeOutbound(id: string): void {
    this.pending.delete(id);
  }

  outbound(): Outbound[] {
    return [...this.pending.values()];
  }

  close(): void {}
}

/** "First time?" kept in the database, so it survives restarts and is shared by every process on the file. */
class SqliteSeenOnce implements SeenOnce {
  private writes = 0;

  constructor(
    private readonly db: DatabaseSync,
    private readonly scope: string,
    private readonly windowMs = 2 * AUTH_SKEW_MS,
  ) {}

  firstUse(key: string, now = Date.now()): boolean {
    if ((this.writes += 1) % 1000 === 0) this.db.prepare('DELETE FROM seen WHERE expires <= ?').run(now);
    // Inserts a new key, or revives one whose window has passed; a live key is left alone and reports no change.
    const { changes } = this.db
      .prepare('INSERT INTO seen (scope, key, expires) VALUES (?, ?, ?) ON CONFLICT (scope, key) DO UPDATE SET expires = excluded.expires WHERE seen.expires <= ?')
      .run(this.scope, key, now + this.windowMs, now);
    return Number(changes) === 1;
  }
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (local TEXT PRIMARY KEY, record TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS mail (local TEXT NOT NULL, seq INTEGER NOT NULL, item TEXT NOT NULL, PRIMARY KEY (local, seq));
CREATE TABLE IF NOT EXISTS key_packages (id INTEGER PRIMARY KEY AUTOINCREMENT, client_id TEXT NOT NULL, kp_id TEXT NOT NULL, key_package TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS key_packages_client ON key_packages (client_id, id);
CREATE TABLE IF NOT EXISTS last_resort (client_id TEXT PRIMARY KEY, kp_id TEXT NOT NULL, key_package TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tokens (local TEXT NOT NULL, hash TEXT NOT NULL, PRIMARY KEY (local, hash));
CREATE TABLE IF NOT EXISTS parked (id INTEGER PRIMARY KEY AUTOINCREMENT, local TEXT NOT NULL, hash TEXT NOT NULL, item TEXT NOT NULL, until INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS parked_local ON parked (local, until);
CREATE TABLE IF NOT EXISTS blobs (id TEXT PRIMARY KEY, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS spent (nonce TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS contacts (local TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (local, kind, value));
CREATE TABLE IF NOT EXISTS view_grants (local TEXT NOT NULL, hash TEXT NOT NULL, PRIMARY KEY (local, hash));
CREATE TABLE IF NOT EXISTS counters (bucket TEXT PRIMARY KEY, total INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS seen (scope TEXT NOT NULL, key TEXT NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY (scope, key));
CREATE TABLE IF NOT EXISTS claims (local TEXT PRIMARY KEY, claims TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS outbound (id TEXT PRIMARY KEY, entry TEXT NOT NULL);
`;

/**
 * The store in SQLite (Node's built-in `node:sqlite`). Each change is its own transaction, in WAL mode with
 * full fsync, so a crash never loses anything the server acknowledged and never leaves half a change.
 * It suits one server process per domain; several behind a load balancer would want the same schema in
 * a networked database.
 */
export class SqliteStore implements Store {
  private readonly db: DatabaseSync;
  readonly replays: SeenOnce;
  readonly recoveryProofs: SeenOnce;

  constructor(file: string) {
    this.db = new DatabaseSync(file);
    this.db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = 5000;');
    this.db.exec(SCHEMA);
    this.replays = new SqliteSeenOnce(this.db, 'replay');
    this.recoveryProofs = new SqliteSeenOnce(this.db, 'recovery');
  }

  private transaction<T>(work: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = work();
      this.db.exec('COMMIT');
      return result;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  user(local: string): UserRecord | undefined {
    const row = this.db.prepare('SELECT record FROM users WHERE local = ?').get(local) as { record: string } | undefined;
    return row ? (JSON.parse(row.record) as UserRecord) : undefined;
  }

  hasUser(local: string): boolean {
    return this.db.prepare('SELECT 1 FROM users WHERE local = ?').get(local) !== undefined;
  }

  putUser(local: string, record: UserRecord): void {
    this.db.prepare('INSERT INTO users (local, record) VALUES (?, ?) ON CONFLICT (local) DO UPDATE SET record = excluded.record').run(local, JSON.stringify(record));
  }

  deleteUser(local: string): void {
    this.db.prepare('DELETE FROM users WHERE local = ?').run(local);
  }

  userLocals(): string[] {
    return (this.db.prepare('SELECT local FROM users').all() as { local: string }[]).map((row) => row.local);
  }

  private pushNow(local: string, item: Parked): MailItem {
    const existing = this.db.prepare("SELECT item FROM mail WHERE local = ? AND json_extract(item, '$.id') = ?").get(local, item.id) as { item: string } | undefined;
    if (existing) return JSON.parse(existing.item) as MailItem;
    const { next } = this.db.prepare('SELECT COALESCE(MAX(seq), 0) + 1 AS next FROM mail WHERE local = ?').get(local) as { next: number };
    const stored = { ...item, seq: Number(next), receivedAt: new Date().toISOString() } as MailItem;
    this.db.prepare('INSERT INTO mail (local, seq, item) VALUES (?, ?, ?)').run(local, stored.seq, JSON.stringify(stored));
    return stored;
  }

  push(local: string, item: Parked): MailItem {
    return this.transaction(() => this.pushNow(local, item));
  }

  mailbox(local: string, after = 0): MailItem[] {
    return (this.db.prepare('SELECT item FROM mail WHERE local = ? AND seq > ? ORDER BY seq').all(local, after) as { item: string }[]).map(
      (row) => JSON.parse(row.item) as MailItem,
    );
  }

  addKeyPackages(clientId: string, packages: PublishedKeyPackage[]): void {
    this.transaction(() => {
      const insert = this.db.prepare('INSERT INTO key_packages (client_id, kp_id, key_package) VALUES (?, ?, ?)');
      for (const { kpId, keyPackage } of packages) insert.run(clientId, kpId, keyPackage);
    });
  }

  countKeyPackages(clientId: string): number {
    return Number((this.db.prepare('SELECT COUNT(*) AS n FROM key_packages WHERE client_id = ?').get(clientId) as { n: number }).n);
  }

  setLastResort(clientId: string, { kpId, keyPackage }: PublishedKeyPackage): void {
    this.db
      .prepare('INSERT INTO last_resort (client_id, kp_id, key_package) VALUES (?, ?, ?) ON CONFLICT (client_id) DO UPDATE SET kp_id = excluded.kp_id, key_package = excluded.key_package')
      .run(clientId, kpId, keyPackage);
  }

  hasLastResort(clientId: string): boolean {
    return this.db.prepare('SELECT 1 FROM last_resort WHERE client_id = ?').get(clientId) !== undefined;
  }

  claimKeyPackage(clientId: string): PublishedKeyPackage | undefined {
    return this.transaction(() => {
      const row = this.db.prepare('SELECT id, kp_id, key_package FROM key_packages WHERE client_id = ? ORDER BY id LIMIT 1').get(clientId) as
        | { id: number; kp_id: string; key_package: string }
        | undefined;
      if (row) {
        this.db.prepare('DELETE FROM key_packages WHERE id = ?').run(row.id);
        return { kpId: row.kp_id, keyPackage: row.key_package };
      }
      const last = this.db.prepare('SELECT kp_id, key_package FROM last_resort WHERE client_id = ?').get(clientId) as { kp_id: string; key_package: string } | undefined;
      return last ? { kpId: last.kp_id, keyPackage: last.key_package } : undefined;
    });
  }

  updateTokens(local: string, add: string[], remove: string[]): void {
    this.transaction(() => {
      for (const hash of add) this.db.prepare('INSERT OR IGNORE INTO tokens (local, hash) VALUES (?, ?)').run(local, hash);
      for (const hash of remove) this.db.prepare('DELETE FROM tokens WHERE local = ? AND hash = ?').run(local, hash);
    });
  }

  hasToken(local: string, hash: string): boolean {
    return this.db.prepare('SELECT 1 FROM tokens WHERE local = ? AND hash = ?').get(local, hash) !== undefined;
  }

  park(local: string, hash: string, item: Parked, ttlMs: number, cap: number): boolean {
    return this.transaction(() => {
      const now = Date.now();
      this.db.prepare('DELETE FROM parked WHERE local = ? AND until <= ?').run(local, now);
      const { n } = this.db.prepare('SELECT COUNT(*) AS n FROM parked WHERE local = ?').get(local) as { n: number };
      if (Number(n) >= cap) return false;
      this.db.prepare('INSERT INTO parked (local, hash, item, until) VALUES (?, ?, ?, ?)').run(local, hash, JSON.stringify(item), now + ttlMs);
      return true;
    });
  }

  release(local: string, hashes: string[]): number {
    if (hashes.length === 0) return 0;
    return this.transaction(() => {
      const now = Date.now();
      const marks = hashes.map(() => '?').join(', ');
      const ready = this.db
        .prepare(`SELECT id, item FROM parked WHERE local = ? AND until > ? AND hash IN (${marks}) ORDER BY id`)
        .all(local, now, ...hashes) as { id: number; item: string }[];
      for (const row of ready) {
        this.db.prepare('DELETE FROM parked WHERE id = ?').run(row.id);
        this.pushNow(local, JSON.parse(row.item) as Parked);
      }
      return ready.length;
    });
  }

  putBlob(id: string, data: Buffer): void {
    this.db.prepare('INSERT OR REPLACE INTO blobs (id, data) VALUES (?, ?)').run(id, data);
  }

  blob(id: string): Buffer | undefined {
    const row = this.db.prepare('SELECT data FROM blobs WHERE id = ?').get(id) as { data: Uint8Array } | undefined;
    return row ? Buffer.from(row.data) : undefined;
  }

  spend(nonce: string): boolean {
    return Number(this.db.prepare('INSERT OR IGNORE INTO spent (nonce) VALUES (?)').run(nonce).changes) === 1;
  }

  addContacts(local: string, contacts: string[], trustedDomains: string[]): void {
    this.transaction(() => {
      const insert = this.db.prepare('INSERT OR IGNORE INTO contacts (local, kind, value) VALUES (?, ?, ?)');
      for (const address of contacts) insert.run(local, 'contact', address.toLowerCase());
      for (const domain of trustedDomains) insert.run(local, 'domain', domain.toLowerCase());
    });
  }

  contactsOf(local: string): { contacts: string[]; trustedDomains: string[] } {
    const rows = this.db.prepare('SELECT kind, value FROM contacts WHERE local = ?').all(local) as { kind: string; value: string }[];
    return { contacts: rows.filter((row) => row.kind === 'contact').map((row) => row.value), trustedDomains: rows.filter((row) => row.kind === 'domain').map((row) => row.value) };
  }

  updateViewGrants(local: string, add: string[], remove: string[]): void {
    this.transaction(() => {
      for (const hash of add) this.db.prepare('INSERT OR IGNORE INTO view_grants (local, hash) VALUES (?, ?)').run(local, hash);
      for (const hash of remove) this.db.prepare('DELETE FROM view_grants WHERE local = ? AND hash = ?').run(local, hash);
    });
  }

  hasViewGrant(local: string, requester: string): boolean {
    return this.db.prepare('SELECT 1 FROM view_grants WHERE local = ? AND hash = ?').get(local, requester) !== undefined;
  }

  bump(key: string, by = 1, now = new Date()): number {
    const row = this.db
      .prepare('INSERT INTO counters (bucket, total) VALUES (?, ?) ON CONFLICT (bucket) DO UPDATE SET total = total + excluded.total RETURNING total')
      .get(`${today(now)}:${key}`, by) as { total: number };
    return Number(row.total);
  }

  count(key: string, now = new Date()): number {
    const row = this.db.prepare('SELECT total FROM counters WHERE bucket = ?').get(`${today(now)}:${key}`) as { total: number } | undefined;
    return Number(row?.total ?? 0);
  }

  claims(local: string): string[] {
    const row = this.db.prepare('SELECT claims FROM claims WHERE local = ?').get(local) as { claims: string } | undefined;
    return row ? (JSON.parse(row.claims) as string[]) : [];
  }

  setClaims(local: string, claims: string[]): void {
    this.db.prepare('INSERT INTO claims (local, claims) VALUES (?, ?) ON CONFLICT (local) DO UPDATE SET claims = excluded.claims').run(local, JSON.stringify(claims));
  }

  serverKeys(): ServerKeys | undefined {
    const row = this.db.prepare("SELECT value FROM settings WHERE name = 'server-keys'").get() as { value: string } | undefined;
    return row ? (JSON.parse(row.value) as ServerKeys) : undefined;
  }

  epoch(): string | undefined {
    return (this.db.prepare("SELECT value FROM settings WHERE name = 'epoch'").get() as { value: string } | undefined)?.value;
  }

  setEpoch(id: string): void {
    this.db.prepare("INSERT INTO settings (name, value) VALUES ('epoch', ?) ON CONFLICT (name) DO UPDATE SET value = excluded.value").run(id);
  }

  setServerKeys(keys: ServerKeys): void {
    this.db.prepare("INSERT INTO settings (name, value) VALUES ('server-keys', ?) ON CONFLICT (name) DO UPDATE SET value = excluded.value").run(JSON.stringify(keys));
  }

  saveOutbound(entry: Outbound): void {
    this.db.prepare('INSERT INTO outbound (id, entry) VALUES (?, ?) ON CONFLICT (id) DO UPDATE SET entry = excluded.entry').run(entry.id, JSON.stringify(entry));
  }

  removeOutbound(id: string): void {
    this.db.prepare('DELETE FROM outbound WHERE id = ?').run(id);
  }

  outbound(): Outbound[] {
    return (this.db.prepare('SELECT entry FROM outbound').all() as { entry: string }[]).map((row) => JSON.parse(row.entry) as Outbound);
  }

  close(): void {
    this.db.close();
  }
}
