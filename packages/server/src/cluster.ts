import { join } from 'node:path';
import type { KeyPair } from '@signet/lib';
import { ReplayCache, domainAuthHeaders, verifyDomainAuth } from '@signet/lib';
import type { BlobStore } from './blobs';
import { BLOB_ID, FileBlobStore, MemoryBlobStore } from './blobs';
import { decode, encode } from './codec';
import type { HttpRequest, HttpResult } from './http';
import { HttpError, header, json } from './http';
import type { AppendRequest, AppendResponse, RaftEntry, RaftStorage, RaftTransport, SnapshotRequest, SnapshotResponse, VoteRequest, VoteResponse } from './raft';
import { MemoryRaftStorage, RaftNode } from './raft';
import { FileRaftStorage } from './raft-storage';
import type { SnapshotStore, Store } from './store';
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
  /** Compact the log into a snapshot after this many applied entries. Defaults to 1000; 0 turns compaction off. */
  snapshotEvery?: number;
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
  'removeContacts',
  'ackMail',
  'dropMail',
  'expireMail',
  'noteBlob',
  'deleteBlob',
  'updateViewGrants',
  'bump',
  'setClaims',
  'setServerKeys',
  'setEpoch',
  'saveOutbound',
  'removeOutbound',
]);

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
  private readonly holder: { store: SnapshotStore };
  /** Attachment ciphertext, kept beside the log and copied to the other homes directly. A witness has none. */
  private readonly blobs?: BlobStore;
  private readonly electionMs: number;
  private ticker?: NodeJS.Timeout;
  private ready = false;
  private pending: Batch = [];
  private recorded = 0;
  private committed = 0;
  private localApplied = 0;
  private waiters: { mark: number; resolve: () => void; reject: (error: Error) => void }[] = [];
  private flushQueued = false;
  /** Signatures of cluster calls already accepted, so a captured call can't be played again. */
  private readonly callReplays = new ReplayCache();
  private primaryHooks: (() => void)[] = [];
  private standbyHooks: (() => void)[] = [];

  /** @param factory Makes an empty store. A witness, which keeps no state, passes none. */
  constructor(
    private readonly options: ClusterOptions,
    private readonly factory?: () => SnapshotStore,
  ) {
    this.currentMembers = options.members;
    for (const member of options.members) this.members.set(member.id, member);
    const self = this.members.get(options.id);
    if (!self) throw new Error(`${options.id} is not one of the cluster's members`);
    if (self.role === 'home' && !factory) throw new Error('a home needs a store');
    if (self.role === 'witness' && factory) throw new Error('a witness keeps no store');
    this.electionMs = options.electionMs ?? 1000;
    this.holder = { store: factory ? factory() : new MemoryStore() };
    if (factory) this.blobs = options.dataDir ? new FileBlobStore(join(options.dataDir, 'blobs')) : new MemoryBlobStore();
    this.store = this.recordingStore();
    if (!options.dataDir && !options.volatileLog) throw new Error('a cluster replica needs dataDir: without durable storage it can vote twice in one term');
    const storage: RaftStorage<Batch> = options.dataDir ? new FileRaftStorage<Batch>(options.dataDir) : new MemoryRaftStorage<Batch>();
    this.raft = new RaftNode<Batch>({
      id: options.id,
      peers: options.members.filter((member) => member.id !== options.id).map((member) => member.id),
      members: options.members.map((member) => ({ ...member })),
      onConfig: (list) => this.adoptMembers(list as unknown as ClusterMember[]),
      witness: self.role === 'witness',
      rejoin: options.rejoin,
      storage,
      transport: this.transport(),
      electionMs: this.electionMs,
      now: options.now,
      random: options.random,
      apply: (index, entry) => this.onApply(index, entry),
      snapshot: () => this.takeSnapshot(),
      restore: (data) => this.holder.store.restore(data),
      snapshotEvery: options.snapshotEvery ?? 1000,
      onRole: (role, _term, previous) => this.onRole(role, previous),
    });
    // A restart may have found a newer membership entry in the log than the one it was configured with.
    this.adoptMembers(this.raft.members as unknown as ClusterMember[]);
  }

  get id(): string {
    return this.options.id;
  }

  /** The voters now: the newest membership entry in the log, committed or not (Section 6.8.6 step 10). */
  private currentMembers: ClusterMember[];

  private adoptMembers(list: ClusterMember[]): void {
    this.currentMembers = list;
    // Keep an address a joining replica was given before it voted, so it can still be reached while it is a learner.
    for (const id of [...this.members.keys()]) if (!list.some((member) => member.id === id) && !this.joining.has(id)) this.members.delete(id);
    for (const member of list) this.members.set(member.id, member);
  }

  private readonly joining = new Set<string>();

  /**
   * Add a replica (primary only): it is told the log as a learner that does not vote, and becomes a voter by a
   * membership entry once it holds everything committed. Add replicas one at a time.
   */
  async addMember(member: ClusterMember, timeoutMs = 15_000): Promise<void> {
    this.requirePrimary();
    if (this.currentMembers.some((known) => known.id === member.id)) throw new Error(`${member.id} is already a member`);
    this.members.set(member.id, member);
    this.joining.add(member.id);
    try {
      this.raft.addLearner(member.id);
      const deadline = Date.now() + timeoutMs;
      while (!this.raft.learnerCaughtUp(member.id)) {
        if (Date.now() > deadline) throw new Error(`${member.id} did not catch up in time`);
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      await this.raft.waitCommitted(this.raft.proposeConfig([...this.currentMembers, member] as never));
    } catch (error) {
      if (!this.currentMembers.some((known) => known.id === member.id)) this.members.delete(member.id);
      throw error;
    } finally {
      this.joining.delete(member.id);
    }
  }

  /** Remove a replica (primary only). A primary that removes itself stops being primary once the change commits. */
  async removeMember(id: string): Promise<void> {
    this.requirePrimary();
    await this.raft.waitCommitted(this.raft.proposeConfig(this.currentMembers.filter((member) => member.id !== id) as never));
  }

  /** The base URLs of the homes, in the order the policy lists them: members order, witnesses left out. */
  get homes(): string[] {
    return this.currentMembers.filter((member) => member.role === 'home').map((member) => member.url);
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

  /**
   * Keep an attachment's ciphertext here and on at least one other home before the upload is answered. It is not
   * part of the replicated log: a 25 MiB file would otherwise sit in every replica's log and every snapshot.
   */
  async putBlob(id: string, data: Buffer): Promise<void> {
    const store = this.blobs as BlobStore;
    store.put(id, data);
    const others = this.currentMembers.filter((member) => member.role === 'home' && member.id !== this.options.id);
    if (others.length === 0) return;
    const sent = await Promise.allSettled(others.map((member) => this.blobCall(member, 'POST', id, data)));
    if (!sent.some((outcome) => outcome.status === 'fulfilled')) throw new HttpError(503, 'could not keep the attachment on a second replica', { 'retry-after': '1' });
  }

  /** Remove an attachment here and at the other replicas that hold a copy (Section 8.9). */
  async deleteBlob(id: string): Promise<void> {
    (this.blobs as BlobStore | undefined)?.delete(id);
    const others = this.currentMembers.filter((member) => member.role === 'home' && member.id !== this.options.id);
    await Promise.allSettled(others.map((member) => this.blobCall(member, 'DELETE', id)));
  }

  /** Remove this replica's attachments uploaded before an instant (ms), whatever the primary knew of them. */
  async expireBlobs(before: number): Promise<void> {
    const store = this.blobs as BlobStore | undefined;
    for (const { id, at } of store?.list() ?? []) if (at < before) store?.delete(id);
  }

  /** A stored attachment, from this replica or, failing that, from another home, which is then kept here. */
  async getBlob(id: string): Promise<Buffer | undefined> {
    const store = this.blobs as BlobStore;
    const here = store.get(id);
    if (here) return here;
    for (const member of this.currentMembers.filter((candidate) => candidate.role === 'home' && candidate.id !== this.options.id)) {
      try {
        const data = await this.blobCall(member, 'GET', id);
        if (data) {
          store.put(id, data);
          return data;
        }
      } catch {
        // Try the next replica.
      }
    }
    return undefined;
  }

  private async blobCall(member: ClusterMember, method: 'GET' | 'POST' | 'DELETE', id: string, data?: Buffer): Promise<Buffer | undefined> {
    const path = `/v0/cluster/blob/${id}`;
    const response = await (this.options.fetchImpl ?? fetch)(`${member.url}${path}`, {
      method,
      headers: { ...domainAuthHeaders(this.options.domain, this.options.domainKey, method, path, data ?? '') },
      body: data,
      signal: AbortSignal.timeout(30_000),
    });
    if (response.status === 404) return undefined;
    if (!response.ok) throw new Error(`${member.id} answered ${response.status}`);
    return method === 'GET' ? Buffer.from(await response.arrayBuffer()) : undefined;
  }

  /** A signed call from another replica: the votes, appends and snapshots of Section 6.8.6, or a blob copied between homes. */
  handle(request: HttpRequest): HttpResult {
    const path = request.url.pathname;
    const blobId = /^\/v0\/cluster\/blob\/([^/]+)$/.exec(path)?.[1];
    const routes = ['/v0/cluster/vote', '/v0/cluster/append', '/v0/cluster/snapshot'];
    if (blobId ? !['GET', 'POST', 'DELETE'].includes(request.method) : request.method !== 'POST' || !routes.includes(path)) throw new HttpError(404, 'no such cluster route');
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
    if (!ok || request.headers['signet-domain'] !== this.options.domain) throw new HttpError(401, 'cluster calls are signed with the replicas\' shared key');
    if (!this.callReplays.firstUse(String(request.headers['signet-sig']))) throw new HttpError(401, 'this cluster call was already used');
    if (blobId) {
      if (!this.blobs || !BLOB_ID.test(blobId)) throw new HttpError(404, 'no attachments here');
      if (request.method === 'POST') {
        this.blobs.put(blobId, request.body);
        return { ok: true };
      }
      if (request.method === 'DELETE') {
        this.blobs.delete(blobId);
        return { ok: true };
      }
      const data = this.blobs.get(blobId);
      if (!data) throw new HttpError(404, 'no such blob');
      return { raw: data, contentType: 'application/octet-stream' };
    }
    if (path === '/v0/cluster/vote') {
      const body = json<VoteRequest>(request);
      this.requireMember(body.candidate);
      return this.raft.handleVote(body);
    }
    if (path === '/v0/cluster/snapshot') {
      const snapshot = json<SnapshotRequest>(request);
      this.requireMember(snapshot.leader);
      return this.raft.handleInstallSnapshot(snapshot);
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
    const post = async <R>(to: string, route: 'vote' | 'append' | 'snapshot', request: VoteRequest | AppendRequest<Batch> | SnapshotRequest): Promise<R> => {
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
      installSnapshot: (to, request) => post<SnapshotResponse>(to, 'snapshot', request),
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

  /**
   * The store as of the last applied entry. The primary's store also holds changes it hasn't committed, so it
   * only snapshots when everything it applied is committed.
   */
  private takeSnapshot(): unknown {
    if (!this.factory) return null;
    if (this.ready && (this.pending.length > 0 || this.localApplied > this.raft.lastApplied)) return undefined;
    return this.holder.store.snapshot();
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
