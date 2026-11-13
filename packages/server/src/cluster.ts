import type { KeyPair } from '@signet/lib';
import { domainAuthHeaders, verifyDomainAuth } from '@signet/lib';
import type { HttpRequest, HttpResult } from './http';
import { HttpError, header, json } from './http';
import type { AppendRequest, AppendResponse, RaftEntry, RaftStorage, RaftTransport, VoteRequest, VoteResponse } from './raft';
import { MemoryRaftStorage, RaftNode } from './raft';
import { FileRaftStorage } from './raft-storage';
import type { Store } from './store';
import { MemoryStore } from './store';

export interface ClusterMember {
  id: string;
  /** The replica's base URL, where the other replicas and callers reach it. */
  url: string;
  /** A home serves clients and is listed in the policy. A witness only keeps the log and votes. */
  role: 'home' | 'witness';
}

export interface ClusterOptions {
  /** The domain this cluster serves. */
  domain: string;
  /** This replica's identifier; one of the members. */
  id: string;
  /** Every replica, this one included. */
  members: ClusterMember[];
  /** The domain's signing key, shared by every replica. Cluster calls are signed with it. */
  domainKey: KeyPair;
  /** Where the term, vote and log are kept. Section 6.8.6 requires durable storage, so one of `dataDir` and `volatileLog` is required. */
  dataDir?: string;
  /** Keep the term, vote and log in memory. A restart forgets a vote and can elect two primaries in one term: tests and demos only. */
  volatileLog?: boolean;
  /** Election timeout T in milliseconds (Section 6.8.6). */
  electionMs?: number;
  /** This replica lost its storage and rejoins under its old identifier (Section 6.8.8). */
  rejoin?: boolean;
  fetchImpl?: typeof fetch;
  now?: () => number;
  random?: () => number;
}

/** A change to the store, as a method name and its arguments. `replays.firstUse` names the request replay cache. */
export interface Command {
  m: string;
  a: unknown[];
}
type Batch = Command[];

const MUTATORS = new Set([
  'putUser',
  'deleteUser',
  'push',
  'addKeyPackages',
  'setLastResort',
  'claimKeyPackage',
  'updateTokens',
  'park',
  'release',
  'putBlob',
  'spend',
  'addContacts',
  'updateViewGrants',
  'bump',
  'setClaims',
  'setServerKeys',
  'saveOutbound',
  'removeOutbound',
]);

const encode = (value: unknown): unknown =>
  JSON.parse(
    JSON.stringify(value, function (this: Record<string, unknown>, key: string, current: unknown) {
      const original = this[key];
      if (Buffer.isBuffer(original)) return { $b: original.toString('base64') };
      if (original instanceof Date) return { $d: original.toISOString() };
      return current;
    }),
  );

const decode = (value: unknown): unknown => {
  if (Array.isArray(value)) return value.map(decode);
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    if (typeof record.$b === 'string' && Object.keys(record).length === 1) return Buffer.from(record.$b, 'base64');
    if (typeof record.$d === 'string' && Object.keys(record).length === 1) return new Date(record.$d);
    return Object.fromEntries(Object.entries(record).map(([key, item]) => [key, decode(item)]));
  }
  return value;
};

/** Apply one replicated change to a store. */
function applyCommand(store: Store, command: Command): void {
  const args = decode(command.a) as unknown[];
  if (command.m === 'replays.firstUse') store.replays.firstUse(...(args as [string, number]));
  else if (command.m === 'recoveryProofs.firstUse') store.recoveryProofs.firstUse(...(args as [string, number]));
  else (store as unknown as Record<string, (...rest: unknown[]) => unknown>)[command.m](...args);
}

/** Thrown for a change attempted by a replica that is not the primary, so a stray handler can't touch a standby's state. */
export class NotPrimaryError extends HttpError {
  constructor(message = 'not the primary') {
    super(503, message, { 'retry-after': '1' });
  }
}

/**
 * One replica's place in a domain's cluster (Section 6.8): the Raft node, the store it keeps in step, and the
 * calls the other replicas make. The home server's store is a proxy that applies each change locally and
 * records it; `durable()` replicates what was recorded and returns once a majority has it. A standby applies
 * committed batches to its own copy. A replica that loses the primary role throws away its copy and rebuilds
 * it from the committed log, so a change that never committed leaves no trace.
 *
 * Replicas keep their own clocks: a mailbox item's `receivedAt` and the expiry of parked deliveries come from
 * the replica that applied them, so they can differ by the replication delay.
 */
export class Cluster {
  readonly raft: RaftNode<Batch>;
  /** The store the home server uses: reads go to the current copy, changes are recorded for replication. */
  readonly store: Store;
  private readonly members = new Map<string, ClusterMember>();
  private readonly holder: { store: Store };
  private readonly electionMs: number;
  private ticker?: NodeJS.Timeout;
  private ready = false;
  private pending: Batch = [];
  private recorded = 0;
  private committed = 0;
  private localApplied = 0;
  private waiters: { mark: number; resolve: () => void; reject: (error: Error) => void }[] = [];
  private flushQueued = false;
  private primaryHooks: (() => void)[] = [];
  private standbyHooks: (() => void)[] = [];

  /** @param factory Makes an empty store. A witness, which keeps no state, passes none. */
  constructor(
    private readonly options: ClusterOptions,
    private readonly factory?: () => Store,
  ) {
    for (const member of options.members) this.members.set(member.id, member);
    const self = this.members.get(options.id);
    if (!self) throw new Error(`${options.id} is not one of the cluster's members`);
    if (self.role === 'home' && !factory) throw new Error('a home needs a store');
    if (self.role === 'witness' && factory) throw new Error('a witness keeps no store');
    this.electionMs = options.electionMs ?? 1000;
    this.holder = { store: factory ? factory() : new MemoryStore() };
    this.store = this.recordingStore();
    if (!options.dataDir && !options.volatileLog) throw new Error('a cluster replica needs dataDir: without durable storage it can vote twice in one term');
    const storage: RaftStorage<Batch> = options.dataDir ? new FileRaftStorage<Batch>(options.dataDir) : new MemoryRaftStorage<Batch>();
    this.raft = new RaftNode<Batch>({
      id: options.id,
      peers: options.members.filter((member) => member.id !== options.id).map((member) => member.id),
      witness: self.role === 'witness',
      rejoin: options.rejoin,
      storage,
      transport: this.transport(),
      electionMs: this.electionMs,
      now: options.now,
      random: options.random,
      apply: (index, entry) => this.onApply(index, entry),
      onRole: (role, _term, previous) => this.onRole(role, previous),
    });
  }

  get id(): string {
    return this.options.id;
  }

  /** The base URLs of the homes, in the order the policy lists them: members order, witnesses left out. */
  get homes(): string[] {
    return this.options.members.filter((member) => member.role === 'home').map((member) => member.url);
  }

  get selfUrl(): string {
    return (this.members.get(this.options.id) as ClusterMember).url;
  }

  get term(): number {
    return this.raft.term;
  }

  /** Called when this replica becomes primary, after its no-op commits and before it answers anything. */
  onPrimary(hook: () => void): void {
    this.primaryHooks.push(hook);
  }

  onStandby(hook: () => void): void {
    this.standbyHooks.push(hook);
  }

  start(): void {
    const every = Math.max(10, Math.floor(this.electionMs / 10));
    this.ticker = setInterval(() => this.raft.tick(), every);
    this.ticker.unref();
  }

  close(): void {
    if (this.ticker) clearInterval(this.ticker);
    this.failWaiters(new NotPrimaryError('shutting down'));
  }

  /** This replica is the primary: leader, its no-op committed, and a majority heard from within the election timeout. */
  isPrimary(): boolean {
    return this.ready && this.raft.isPrimary();
  }

  /** The base URL of the current primary, if this replica knows one. */
  primaryUrl(): string | undefined {
    const leader = this.raft.leaderId;
    const member = leader ? this.members.get(leader) : undefined;
    return member?.role === 'home' ? member.url : undefined;
  }

  /** Throws the answer a replica that isn't the primary gives (Section 6.8.4). */
  requirePrimary(): void {
    if (this.isPrimary()) return;
    if (this.raft.role === 'leader') throw new HttpError(503, 'the primary has no majority', { 'retry-after': '1' });
    const primary = this.primaryUrl();
    throw new HttpError(421, 'this is not the primary', primary ? { 'signet-primary': primary } : {});
  }

  /** Headers for a response: the primary's term, so callers can see which primary answered. */
  responseHeaders(): Record<string, string> {
    return this.isPrimary() ? { 'signet-term': String(this.raft.term) } : {};
  }

  /** Replicate everything recorded so far and wait until a majority has it. Throws if this replica loses the primary role first. */
  async durable(): Promise<void> {
    const mark = this.recorded;
    this.flush();
    if (this.committed >= mark) return;
    await new Promise<void>((resolve, reject) => this.waiters.push({ mark, resolve, reject }));
  }

  /** A signed call from another replica: POST /v0/cluster/vote or /v0/cluster/append. */
  handle(request: HttpRequest): HttpResult {
    const path = request.url.pathname;
    if (request.method !== 'POST' || (path !== '/v0/cluster/vote' && path !== '/v0/cluster/append')) throw new HttpError(404, 'no such cluster route');
    const ok = verifyDomainAuth(
      header(request.headers, 'signet-domain'),
      this.options.domainKey.publicKey,
      header(request.headers, 'signet-sig'),
      header(request.headers, 'signet-ts'),
      header(request.headers, 'signet-nonce'),
      request.method,
      request.path,
      request.body,
    );
    if (!ok || request.headers['signet-domain'] !== this.options.domain) throw new HttpError(401, 'cluster calls are signed with the domain key');
    if (path === '/v0/cluster/vote') {
      const body = json<VoteRequest>(request);
      this.requireMember(body.candidate);
      return this.raft.handleVote(body);
    }
    const body = json<AppendRequest<Batch>>(request);
    this.requireMember(body.leader);
    return this.raft.handleAppend({ ...body, entries: body.entries ?? [] });
  }

  private requireMember(id: unknown): void {
    if (typeof id !== 'string' || !this.members.has(id)) throw new HttpError(403, 'not a member of this cluster');
  }

  private transport(): RaftTransport<Batch> {
    const fetchImpl = this.options.fetchImpl ?? fetch;
    const post = async <R>(to: string, route: 'vote' | 'append', request: VoteRequest | AppendRequest<Batch>): Promise<R> => {
      const member = this.members.get(to) as ClusterMember;
      const path = `/v0/cluster/${route}`;
      const body = JSON.stringify(request);
      const response = await fetchImpl(`${member.url}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...domainAuthHeaders(this.options.domain, this.options.domainKey, 'POST', path, body) },
        body,
        signal: AbortSignal.timeout(this.electionMs),
      });
      if (!response.ok) throw new Error(`${to} answered ${response.status}`);
      return (await response.json()) as R;
    };
    return {
      vote: (to, request) => post<VoteResponse>(to, 'vote', request),
      append: (to, request) => post<AppendResponse>(to, 'append', request),
    };
  }

  /** A store that reads the current copy and applies and records every change, but only while this replica is the primary. */
  private recordingStore(): Store {
    const record = (command: Command) => {
      this.pending.push(command);
      this.recorded++;
      this.queueFlush();
    };
    const guard = () => {
      if (!(this.ready && this.raft.role === 'leader')) throw new NotPrimaryError();
    };
    const seen = (name: 'replays' | 'recoveryProofs') => ({
      firstUse: (key: string, now = Date.now()): boolean => {
        guard();
        const first = this.holder.store[name].firstUse(key, now);
        if (first) record({ m: `${name}.firstUse`, a: [key, now] });
        return first;
      },
    });
    const replays = seen('replays');
    const recoveryProofs = seen('recoveryProofs');
    return new Proxy({} as Store, {
      get: (_target, property: string) => {
        if (property === 'replays') return replays;
        if (property === 'recoveryProofs') return recoveryProofs;
        const current = this.holder.store as unknown as Record<string, unknown>;
        const value = current[property];
        if (typeof value !== 'function') return value;
        if (!MUTATORS.has(property)) return (value as (...args: unknown[]) => unknown).bind(current);
        return (...args: unknown[]) => {
          guard();
          const result = (value as (...rest: unknown[]) => unknown).apply(current, args);
          record({ m: property, a: encode(args) as unknown[] });
          return result;
        };
      },
    });
  }

  private queueFlush(): void {
    if (this.flushQueued) return;
    this.flushQueued = true;
    queueMicrotask(() => {
      this.flushQueued = false;
      this.flush();
    });
  }

  /** Propose what has been recorded as one entry. */
  private flush(): void {
    if (this.pending.length === 0) return;
    const batch = this.pending;
    const upTo = this.recorded;
    this.pending = [];
    let index: number;
    try {
      index = this.raft.propose(batch);
    } catch {
      this.failWaiters(new NotPrimaryError('lost the primary role'));
      return;
    }
    this.localApplied = index;
    this.raft.waitCommitted(index).then(
      () => {
        this.committed = Math.max(this.committed, upTo);
        this.waiters = this.waiters.filter((waiter) => {
          if (waiter.mark > this.committed) return true;
          waiter.resolve();
          return false;
        });
      },
      () => this.failWaiters(new NotPrimaryError('the change was not committed')),
    );
  }

  private failWaiters(error: Error): void {
    const waiters = this.waiters;
    this.waiters = [];
    for (const waiter of waiters) waiter.reject(error);
  }

  private onApply(index: number, entry: RaftEntry<Batch>): void {
    if (entry.data === null) {
      if (this.raft.role === 'leader' && entry.term === this.raft.term && !this.ready) this.becomePrimary();
      return;
    }
    // The primary applied its own batches when it recorded them.
    if (index <= this.localApplied) return;
    for (const command of entry.data) applyCommand(this.holder.store, command);
  }

  private becomePrimary(): void {
    this.pending = [];
    this.recorded = 0;
    this.committed = 0;
    this.localApplied = 0;
    this.ready = true;
    for (const hook of this.primaryHooks) hook();
  }

  private onRole(role: 'follower' | 'candidate' | 'leader', previous: 'follower' | 'candidate' | 'leader'): void {
    if (previous !== 'leader' || role === 'leader') return;
    const dirty = this.pending.length > 0 || this.localApplied > this.raft.commitIndex;
    this.ready = false;
    this.failWaiters(new NotPrimaryError('lost the primary role'));
    if (dirty) this.rebuild();
    for (const hook of this.standbyHooks) hook();
  }

  /** Throw the copy away and apply the committed log again, so nothing uncommitted survives. */
  private rebuild(): void {
    if (!this.factory) return;
    this.pending = [];
    this.holder.store.close();
    this.holder.store = this.factory();
    this.localApplied = 0;
    this.raft.resetApplied();
  }
}
