/**
 * The Raft algorithm (Ongaro and Ousterhout, 2014) in the profile of Section 6.8.6: leader election with
 * terms and a pre-vote round, log replication, commit by majority, a no-op entry for each new leader, a
 * leader that steps down when it hasn't heard from a majority for one election timeout, snapshots that
 * compact the log, and membership changes one replica at a time (Raft dissertation, Section 4.1).
 *
 * The node does no I/O of its own. The host gives it a transport, durable storage, a clock and an
 * `apply` function, and calls `tick` often (every tenth of the election timeout is plenty).
 *
 * Log indexes are absolute and start at 1. After a snapshot, the log holds only the entries after the
 * snapshot's index.
 */

export type Role = 'follower' | 'candidate' | 'leader';

/** A voter. Raft reads only `id`; the host keeps the rest (an address, a role) with it. */
export interface RaftMember {
  id: string;
  [key: string]: unknown;
}

/** `data` is null for the no-op a new leader appends and for a membership entry, which carries `config`. */
export interface RaftEntry<T = unknown> {
  term: number;
  data: T | null;
  /** The complete list of voters from this entry on. A replica uses the newest one in its log, committed or not. */
  config?: RaftMember[];
}

/** The state machine as of `index`, replacing every entry up to and including it. `data` is null for a witness. */
export interface RaftSnapshot {
  index: number;
  term: number;
  data: unknown;
  /** The voters as of `index`. */
  config?: RaftMember[];
}

export interface RaftStorage<T = unknown> {
  load(): { term: number; votedFor: string | null; log: RaftEntry<T>[]; snapshot?: RaftSnapshot };
  /** Must be durable when it returns. */
  saveHard(term: number, votedFor: string | null): void;
  /** Keep entries before absolute index `from`, drop the rest, then add `entries`. Must be durable when it returns. */
  replaceFrom(from: number, entries: RaftEntry<T>[]): void;
  /** Keep this snapshot and, after it, exactly `remaining`, which starts at index `snapshot.index + 1`. Must be durable when it returns. */
  saveSnapshot(snapshot: RaftSnapshot, remaining: RaftEntry<T>[]): void;
}

export class MemoryRaftStorage<T = unknown> implements RaftStorage<T> {
  private term = 0;
  private votedFor: string | null = null;
  private log: RaftEntry<T>[] = [];
  private snapshot?: RaftSnapshot;

  load() {
    return { term: this.term, votedFor: this.votedFor, log: structuredClone(this.log), snapshot: structuredClone(this.snapshot) };
  }

  saveHard(term: number, votedFor: string | null): void {
    this.term = term;
    this.votedFor = votedFor;
  }

  replaceFrom(from: number, entries: RaftEntry<T>[]): void {
    const base = this.snapshot?.index ?? 0;
    this.log = [...this.log.slice(0, from - base - 1), ...structuredClone(entries)];
  }

  saveSnapshot(snapshot: RaftSnapshot, remaining: RaftEntry<T>[]): void {
    this.snapshot = structuredClone(snapshot);
    this.log = structuredClone(remaining);
  }

  /** How many entries the log holds beyond the snapshot, for tests. */
  get length(): number {
    return this.log.length;
  }
}

export interface VoteRequest {
  term: number;
  candidate: string;
  lastIndex: number;
  lastTerm: number;
  /** A pre-vote: would you vote for me in this term? It changes nothing on the voter, and the candidate's term doesn't rise unless a majority says yes. */
  pre?: boolean;
}

export interface VoteResponse {
  term: number;
  granted: boolean;
}

export interface AppendRequest<T = unknown> {
  term: number;
  leader: string;
  prevIndex: number;
  prevTerm: number;
  entries: RaftEntry<T>[];
  commit: number;
}

export interface AppendResponse {
  term: number;
  success: boolean;
  /** On success, the last index the follower now shares with the leader; on failure, a hint for where to retry. */
  matchIndex: number;
}

/** The leader's snapshot, for a follower that needs entries the leader has compacted away. */
export interface SnapshotRequest {
  term: number;
  leader: string;
  index: number;
  snapshotTerm: number;
  data: unknown;
  config?: RaftMember[];
}

export interface SnapshotResponse {
  term: number;
  matchIndex: number;
}

export interface RaftTransport<T = unknown> {
  vote(to: string, request: VoteRequest): Promise<VoteResponse>;
  append(to: string, request: AppendRequest<T>): Promise<AppendResponse>;
  installSnapshot(to: string, request: SnapshotRequest): Promise<SnapshotResponse>;
}

export class NotLeaderError extends Error {
  constructor() {
    super('not the leader');
  }
}

/** The entry a caller waited for was replaced by another leader's. */
export class OverwrittenError extends Error {
  constructor() {
    super('the entry was overwritten by another leader');
  }
}

export interface RaftOptions<T> {
  id: string;
  /** Every other voter, witnesses included, as of the start; later changes come from the log. */
  peers: string[];
  /** The voters, with whatever the host wants to keep about them, as of the start. Defaults to this replica and `peers`. */
  members?: RaftMember[];
  /** Called when the voters change: a membership entry is added to the log, or one is rolled back or compacted. */
  onConfig?: (members: RaftMember[]) => void;
  /** A witness keeps the log and votes. It never stands for election and never applies entries. */
  witness?: boolean;
  /**
   * This replica lost its storage and is rejoining under its old identifier. It may have voted in a term it
   * can no longer remember, so it doesn't vote or stand until it has caught up to a leader's commit index.
   */
  rejoin?: boolean;
  storage: RaftStorage<T>;
  transport: RaftTransport<T>;
  /** Called once per committed entry, in order, including no-ops. Not called on a witness. */
  apply: (index: number, entry: RaftEntry<T>) => void;
  /**
   * The state machine as of the last applied entry, to compact the log. Return undefined if it can't be taken
   * right now (say, because it holds changes that aren't committed yet); the node tries again later.
   */
  snapshot?: () => unknown;
  /** Replace the state machine with a snapshot's data, or with nothing (null) when there is no snapshot. */
  restore?: (data: unknown) => void;
  /** Compact the log once this many entries have been applied since the last snapshot. Off if unset. */
  snapshotEvery?: number;
  /** Called when the role changes. */
  onRole?: (role: Role, term: number, previous: Role) => void;
  /** Election timeout T in milliseconds. Elections start after T to 2T; heartbeats go every T/5. */
  electionMs?: number;
  now?: () => number;
  random?: () => number;
}

const MAX_BATCH = 64;

interface Waiter {
  index: number;
  term: number;
  resolve: () => void;
  reject: (error: Error) => void;
}

export class RaftNode<T = unknown> {
  readonly id: string;
  role: Role = 'follower';
  leaderId: string | null = null;
  commitIndex = 0;
  lastApplied = 0;

  private term_ = 0;
  private votedFor: string | null = null;
  /** Entries after `snapshotIndex`. */
  private log: RaftEntry<T>[];
  private snapshotIndex = 0;
  private snapshotTerm = 0;
  private snapshotData: unknown = null;
  private peers: string[];
  private memberList: RaftMember[];
  private snapshotConfig?: RaftMember[];
  /** Non-voting replicas the leader is catching up before they are added. */
  private readonly learners = new Set<string>();
  private readonly witness: boolean;
  private readonly electionMs: number;
  private readonly now: () => number;
  private readonly random: () => number;
  private caughtUp: boolean;
  private electionDeadline = 0;
  /** When a leader last reached this replica, so a pre-vote isn't granted while one is alive. */
  private lastLeaderContact = Number.NEGATIVE_INFINITY;
  private preVoting = false;
  private nextHeartbeat = 0;
  private noopIndex = 0;
  private readonly nextIndex = new Map<string, number>();
  private readonly matchIndex = new Map<string, number>();
  private readonly lastAck = new Map<string, number>();
  private readonly inflight = new Set<string>();
  private waiters: Waiter[] = [];

  constructor(private readonly options: RaftOptions<T>) {
    this.id = options.id;
    this.peers = [...options.peers];
    this.memberList = options.members ?? [{ id: options.id }, ...options.peers.map((id) => ({ id }))];
    this.witness = options.witness ?? false;
    this.electionMs = options.electionMs ?? 1000;
    this.now = options.now ?? Date.now;
    this.random = options.random ?? Math.random;
    this.caughtUp = !options.rejoin;
    const saved = options.storage.load();
    this.term_ = saved.term;
    this.votedFor = saved.votedFor;
    this.log = saved.log;
    if (saved.snapshot) {
      this.snapshotIndex = saved.snapshot.index;
      this.snapshotTerm = saved.snapshot.term;
      this.snapshotData = saved.snapshot.data;
      this.snapshotConfig = saved.snapshot.config;
      this.commitIndex = this.lastApplied = saved.snapshot.index;
      if (!this.witness) options.restore?.(saved.snapshot.data);
    }
    this.initialMembers = this.memberList;
    this.recomputeConfig(false);
    this.resetElection();
  }

  private readonly initialMembers: RaftMember[];

  /** Who votes now. */
  get members(): RaftMember[] {
    return this.memberList;
  }

  private get voting(): boolean {
    return this.memberList.some((member) => member.id === this.id);
  }

  /** The voters as of the newest membership entry in the log, or the snapshot's, or the start. Uncommitted entries count. */
  private configAt(index: number): RaftMember[] {
    for (let i = Math.min(index, this.lastIndex); i > this.snapshotIndex; i--) {
      const config = this.entryAt(i)?.config;
      if (config) return config;
    }
    return this.snapshotConfig ?? this.initialMembers;
  }

  private recomputeConfig(notify = true): void {
    const members = this.configAt(this.lastIndex);
    const same = members.length === this.memberList.length && members.every((member, i) => member.id === this.memberList[i].id && JSON.stringify(member) === JSON.stringify(this.memberList[i]));
    this.memberList = members;
    this.peers = members.map((member) => member.id).filter((id) => id !== this.id);
    if (this.role === 'leader') {
      for (const peer of this.peers) {
        if (!this.nextIndex.has(peer)) this.nextIndex.set(peer, this.lastIndex + 1);
        if (!this.matchIndex.has(peer)) this.matchIndex.set(peer, 0);
        if (!this.lastAck.has(peer)) this.lastAck.set(peer, this.now());
        this.learners.delete(peer);
      }
    }
    if (notify && !same) this.options.onConfig?.(members);
  }

  /** The replicas the leader sends to: voters, and learners it is catching up. */
  private get targets(): string[] {
    return [...this.peers, ...[...this.learners].filter((id) => !this.peers.includes(id))];
  }

  /** Leader only: start replicating to a replica that does not vote yet, so it can catch up before it is added. */
  addLearner(id: string): void {
    if (this.role !== 'leader') throw new NotLeaderError();
    if (id === this.id || this.peers.includes(id)) return;
    this.learners.add(id);
    this.nextIndex.set(id, this.lastIndex + 1);
    this.matchIndex.set(id, 0);
    this.broadcast();
  }

  /** Whether a learner holds everything the leader has committed. */
  learnerCaughtUp(id: string): boolean {
    return this.role === 'leader' && (this.matchIndex.get(id) ?? 0) >= this.commitIndex && this.commitIndex >= this.noopIndex;
  }

  /**
   * Leader only: change the voters by exactly one replica (Section 6.8.6 step 10). Only one change may be in the
   * log uncommitted at a time, and a replica being added must have caught up as a learner first.
   */
  proposeConfig(members: RaftMember[]): number {
    if (this.role !== 'leader') throw new NotLeaderError();
    for (let i = this.lastIndex; i > this.commitIndex && i > this.snapshotIndex; i--) {
      if (this.entryAt(i)?.config) throw new Error('a membership change is already in progress');
    }
    const now = new Set(this.memberList.map((member) => member.id));
    const next = new Set(members.map((member) => member.id));
    const added = [...next].filter((id) => !now.has(id));
    const removed = [...now].filter((id) => !next.has(id));
    if (next.size !== members.length || added.length + removed.length !== 1) throw new Error('a membership change adds or removes exactly one replica');
    if (added.length === 1 && !this.learnerCaughtUp(added[0])) throw new Error(`${added[0]} has not caught up yet`);
    const index = this.appendLocal({ term: this.term_, data: null, config: members.map((member) => ({ ...member })) });
    this.recomputeConfig();
    this.broadcast();
    return index;
  }

  get term(): number {
    return this.term_;
  }

  get lastIndex(): number {
    return this.snapshotIndex + this.log.length;
  }

  /** The index the log starts after: everything up to it is in the snapshot. */
  get compactedThrough(): number {
    return this.snapshotIndex;
  }

  /** Voters needed for a decision: more than half of everyone now voting. */
  get majority(): number {
    return Math.floor(this.memberList.length / 2) + 1;
  }

  entryAt(index: number): RaftEntry<T> | undefined {
    return index > this.snapshotIndex ? this.log[index - this.snapshotIndex - 1] : undefined;
  }

  private termAt(index: number): number {
    if (index === 0) return 0;
    if (index === this.snapshotIndex) return this.snapshotTerm;
    return this.entryAt(index)?.term ?? 0;
  }

  private resetElection(): void {
    this.electionDeadline = this.now() + this.electionMs * (1 + this.random());
  }

  /** The leader heard from a majority within the last election timeout, counting itself. */
  hasLease(now = this.now()): boolean {
    if (this.role !== 'leader') return false;
    const times = [...(this.voting ? [now] : []), ...this.peers.map((peer) => this.lastAck.get(peer) ?? 0)].sort((a, b) => b - a);
    return now - times[this.majority - 1] < this.electionMs;
  }

  /** A leader whose no-op is committed, so everything before it is, and who still has a majority. */
  isPrimary(): boolean {
    return this.role === 'leader' && this.commitIndex >= this.noopIndex && this.hasLease();
  }

  /** Call often. Starts elections, sends heartbeats and checks the leader's lease. */
  tick(): void {
    const now = this.now();
    if (this.role === 'leader') {
      if (!this.hasLease(now)) {
        this.stepDown(this.term_);
        return;
      }
      if (now >= this.nextHeartbeat) this.broadcast();
      return;
    }
    if (this.witness || !this.caughtUp || !this.voting) return;
    if (now >= this.electionDeadline) this.startPreVote();
  }

  /** Leader only: add an entry to the log. Await `waitCommitted` for the result. */
  propose(data: T): number {
    if (this.role !== 'leader') throw new NotLeaderError();
    const index = this.appendLocal({ term: this.term_, data });
    this.broadcast();
    return index;
  }

  /** Resolves once the entry at `index`, as it is now, is committed; rejects if another leader's entry takes its place. */
  waitCommitted(index: number): Promise<void> {
    const term = this.termAt(index);
    return new Promise<void>((resolve, reject) => {
      this.waiters.push({ index, term, resolve, reject });
      this.settle();
    });
  }

  /** The host threw its state away: restore the snapshot into it and apply the committed log after the snapshot again. */
  resetApplied(): void {
    if (!this.witness && this.snapshotIndex > 0) this.options.restore?.(this.snapshotData);
    this.lastApplied = this.snapshotIndex;
    this.applyCommitted();
  }

  handleVote(request: VoteRequest): VoteResponse {
    if (request.pre) return this.handlePreVote(request);
    if (request.term < this.term_) return { term: this.term_, granted: false };
    if (request.term > this.term_) this.stepDown(request.term);
    const upToDate = this.upToDate(request);
    const free = this.votedFor === null || this.votedFor === request.candidate;
    if (!this.caughtUp || !free || !upToDate) return { term: this.term_, granted: false };
    this.votedFor = request.candidate;
    this.options.storage.saveHard(this.term_, this.votedFor);
    this.resetElection();
    return { term: this.term_, granted: true };
  }

  private upToDate(request: VoteRequest): boolean {
    const lastTerm = this.termAt(this.lastIndex);
    return request.lastTerm > lastTerm || (request.lastTerm === lastTerm && request.lastIndex >= this.lastIndex);
  }

  handleAppend(request: AppendRequest<T>): AppendResponse {
    if (request.term < this.term_) return { term: this.term_, success: false, matchIndex: 0 };
    if (request.term > this.term_ || this.role !== 'follower') this.stepDown(request.term);
    this.leaderId = request.leader;
    this.lastLeaderContact = this.now();
    this.resetElection();
    // Anything before our snapshot is committed, so the leader's log agrees with ours there.
    const matches = request.prevIndex < this.snapshotIndex || (request.prevIndex <= this.lastIndex && this.termAt(request.prevIndex) === request.prevTerm);
    if (!matches) {
      return { term: this.term_, success: false, matchIndex: Math.min(this.lastIndex, Math.max(0, request.prevIndex - 1)) };
    }
    let index = request.prevIndex;
    const added: RaftEntry<T>[] = [];
    let from = 0;
    for (const entry of request.entries) {
      index++;
      if (index <= this.snapshotIndex) continue;
      if (added.length === 0) {
        if (index <= this.lastIndex) {
          if (this.termAt(index) === entry.term) continue;
          if (index <= this.commitIndex) throw new Error(`leader ${request.leader} contradicts committed entry ${index}`);
          this.log.length = index - 1 - this.snapshotIndex;
        }
        from = index;
      }
      added.push(entry);
      this.log.push(entry);
    }
    if (added.length > 0) {
      this.options.storage.replaceFrom(from, added);
      // A membership entry takes effect when it is in the log, and goes with it if the log is cut back.
      this.recomputeConfig();
    }
    const last = request.prevIndex + request.entries.length;
    if (request.commit > this.commitIndex) {
      this.commitIndex = Math.max(this.commitIndex, Math.min(request.commit, last));
      this.applyCommitted();
    }
    if (!this.caughtUp && this.commitIndex >= request.commit) this.caughtUp = true;
    this.settle();
    return { term: this.term_, success: true, matchIndex: Math.max(last, this.snapshotIndex) };
  }

  /** Take the leader's snapshot in place of everything this replica holds up to it. */
  handleInstallSnapshot(request: SnapshotRequest): SnapshotResponse {
    if (request.term < this.term_) return { term: this.term_, matchIndex: 0 };
    if (request.term > this.term_ || this.role !== 'follower') this.stepDown(request.term);
    this.leaderId = request.leader;
    this.lastLeaderContact = this.now();
    this.resetElection();
    // Already past it: nothing to take.
    if (request.index <= this.commitIndex) return { term: this.term_, matchIndex: this.commitIndex };
    this.options.storage.saveSnapshot({ index: request.index, term: request.snapshotTerm, data: request.data, config: request.config }, []);
    this.log = [];
    this.snapshotIndex = request.index;
    this.snapshotTerm = request.snapshotTerm;
    this.snapshotData = request.data;
    this.snapshotConfig = request.config;
    this.recomputeConfig();
    this.commitIndex = this.lastApplied = request.index;
    if (!this.witness) this.options.restore?.(request.data);
    this.settle();
    return { term: this.term_, matchIndex: request.index };
  }

  private appendLocal(entry: RaftEntry<T>): number {
    this.log.push(entry);
    this.options.storage.replaceFrom(this.lastIndex, [entry]);
    return this.lastIndex;
  }

  /** A pre-vote is granted if the candidate's log is current and no leader has been heard from for an election timeout. Nothing is recorded. */
  private handlePreVote(request: VoteRequest): VoteResponse {
    const leaderless = this.role !== 'leader' && this.now() - this.lastLeaderContact >= this.electionMs;
    return { term: this.term_, granted: request.term >= this.term_ && this.upToDate(request) && leaderless && this.caughtUp };
  }

  /** Ask whether a majority would vote for this replica before raising the term, so a replica that is merely cut off doesn't disturb a working primary. */
  private startPreVote(): void {
    this.resetElection();
    if (this.peers.length === 0) {
      this.startElection();
      return;
    }
    if (this.preVoting) return;
    this.preVoting = true;
    const term = this.term_ + 1;
    const request: VoteRequest = { term, candidate: this.id, lastIndex: this.lastIndex, lastTerm: this.termAt(this.lastIndex), pre: true };
    let yes = 1;
    let answered = 0;
    const settle = () => {
      if (++answered === this.peers.length) this.preVoting = false;
    };
    for (const peer of this.peers) {
      this.options.transport.vote(peer, request).then(
        (response) => {
          settle();
          if (response.term > this.term_) {
            this.stepDown(response.term);
            return;
          }
          if (!response.granted || this.role === 'leader' || this.term_ + 1 !== term) return;
          if (++yes === this.majority) {
            this.preVoting = false;
            this.startElection();
          }
        },
        settle,
      );
    }
  }

  private startElection(): void {
    const previous = this.role;
    this.term_++;
    this.role = 'candidate';
    this.votedFor = this.id;
    this.leaderId = null;
    this.options.storage.saveHard(this.term_, this.votedFor);
    this.resetElection();
    if (previous !== 'candidate') this.options.onRole?.('candidate', this.term_, previous);
    const term = this.term_;
    let votes = 1;
    if (votes >= this.majority) {
      this.becomeLeader();
      return;
    }
    const request: VoteRequest = { term, candidate: this.id, lastIndex: this.lastIndex, lastTerm: this.termAt(this.lastIndex) };
    for (const peer of this.peers) {
      this.options.transport.vote(peer, request).then(
        (response) => {
          if (response.term > this.term_) {
            this.stepDown(response.term);
            return;
          }
          if (this.role !== 'candidate' || this.term_ !== term || !response.granted) return;
          if (++votes >= this.majority) this.becomeLeader();
        },
        () => undefined,
      );
    }
  }

  private becomeLeader(): void {
    const previous = this.role;
    this.role = 'leader';
    this.leaderId = this.id;
    this.inflight.clear();
    this.learners.clear();
    for (const peer of this.peers) {
      this.nextIndex.set(peer, this.lastIndex + 1);
      this.matchIndex.set(peer, 0);
      this.lastAck.set(peer, this.now());
    }
    this.noopIndex = this.appendLocal({ term: this.term_, data: null });
    this.options.onRole?.('leader', this.term_, previous);
    this.broadcast();
  }

  private stepDown(term: number): void {
    const previous = this.role;
    if (term > this.term_) {
      this.term_ = term;
      this.votedFor = null;
      this.options.storage.saveHard(this.term_, this.votedFor);
    }
    this.role = 'follower';
    if (previous !== 'follower') this.leaderId = null;
    this.resetElection();
    if (previous !== 'follower') this.options.onRole?.('follower', this.term_, previous);
  }

  private broadcast(): void {
    this.nextHeartbeat = this.now() + this.electionMs / 5;
    for (const peer of this.targets) this.replicate(peer);
    this.advanceCommit();
  }

  private replicate(peer: string): void {
    if (this.role !== 'leader' || this.inflight.has(peer)) return;
    const next = this.nextIndex.get(peer) ?? this.lastIndex + 1;
    if (next <= this.snapshotIndex) {
      this.sendSnapshot(peer);
      return;
    }
    const prevIndex = next - 1;
    const term = this.term_;
    this.inflight.add(peer);
    const entries = this.log.slice(prevIndex - this.snapshotIndex, prevIndex - this.snapshotIndex + MAX_BATCH);
    this.options.transport.append(peer, { term, leader: this.id, prevIndex, prevTerm: this.termAt(prevIndex), entries, commit: this.commitIndex }).then(
      (response) => {
        this.inflight.delete(peer);
        if (response.term > this.term_) {
          this.stepDown(response.term);
          return;
        }
        if (this.role !== 'leader' || this.term_ !== term) return;
        this.lastAck.set(peer, this.now());
        if (response.success) {
          const matched = Math.max(this.matchIndex.get(peer) ?? 0, response.matchIndex);
          this.matchIndex.set(peer, matched);
          this.nextIndex.set(peer, matched + 1);
          this.advanceCommit();
          if (matched < this.lastIndex) this.replicate(peer);
        } else {
          this.nextIndex.set(peer, Math.max(1, Math.min(next - 1, response.matchIndex + 1)));
          this.replicate(peer);
        }
      },
      () => this.inflight.delete(peer),
    );
  }

  private sendSnapshot(peer: string): void {
    const term = this.term_;
    this.inflight.add(peer);
    this.options.transport.installSnapshot(peer, { term, leader: this.id, index: this.snapshotIndex, snapshotTerm: this.snapshotTerm, data: this.snapshotData, config: this.snapshotConfig }).then(
      (response) => {
        this.inflight.delete(peer);
        if (response.term > this.term_) {
          this.stepDown(response.term);
          return;
        }
        if (this.role !== 'leader' || this.term_ !== term) return;
        this.lastAck.set(peer, this.now());
        const matched = Math.max(this.matchIndex.get(peer) ?? 0, response.matchIndex);
        this.matchIndex.set(peer, matched);
        this.nextIndex.set(peer, matched + 1);
        this.advanceCommit();
        if (matched < this.lastIndex) this.replicate(peer);
      },
      () => this.inflight.delete(peer),
    );
  }

  /** Commit the highest entry of this term that a majority holds. Older entries commit with it. */
  private advanceCommit(): void {
    if (this.role !== 'leader') return;
    for (let n = this.lastIndex; n > this.commitIndex; n--) {
      if (this.termAt(n) !== this.term_) break;
      const holders = (this.voting ? 1 : 0) + this.peers.filter((peer) => (this.matchIndex.get(peer) ?? 0) >= n).length;
      if (holders >= this.majority) {
        this.commitIndex = n;
        this.applyCommitted();
        this.settle();
        return;
      }
    }
  }

  private applyCommitted(): void {
    while (this.lastApplied < this.commitIndex) {
      this.lastApplied++;
      const entry = this.entryAt(this.lastApplied) as RaftEntry<T>;
      if (!this.witness) this.options.apply(this.lastApplied, entry);
      // A leader that has just committed its own removal stops leading (Section 6.8.6 step 10).
      if (entry.config && this.role === 'leader' && !this.voting && this.lastApplied >= this.commitIndex) this.stepDown(this.term_);
    }
    if (this.options.snapshotEvery && this.lastApplied - this.snapshotIndex >= this.options.snapshotEvery) this.compact();
  }

  /** Replace the applied part of the log with a snapshot of the state machine. */
  private compact(): void {
    const data = this.witness ? null : this.options.snapshot?.();
    if (data === undefined) return;
    // Settle callers waiting on entries about to be compacted, while their terms can still be checked.
    this.settle();
    const index = this.lastApplied;
    const term = this.termAt(index);
    const remaining = this.log.slice(index - this.snapshotIndex);
    const config = this.configAt(index);
    this.options.storage.saveSnapshot({ index, term, data, config }, remaining);
    this.log = remaining;
    this.snapshotIndex = index;
    this.snapshotTerm = term;
    this.snapshotData = data;
    this.snapshotConfig = config;
  }

  private settle(): void {
    const waiting: Waiter[] = [];
    for (const waiter of this.waiters) {
      const same = this.termAt(waiter.index) === waiter.term && waiter.index <= this.lastIndex;
      if (!same) waiter.reject(new OverwrittenError());
      else if (this.commitIndex >= waiter.index) waiter.resolve();
      else waiting.push(waiter);
    }
    this.waiters = waiting;
  }
}
