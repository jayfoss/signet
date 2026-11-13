/**
 * The Raft algorithm (Ongaro and Ousterhout, 2014) in the profile of Section 6.8.6: leader election with
 * terms, log replication, commit by majority, a no-op entry for each new leader, and a leader that steps
 * down when it hasn't heard from a majority for one election timeout. There is no snapshotting and no
 * membership change.
 *
 * The node does no I/O of its own. The host gives it a transport, durable storage, a clock and an
 * `apply` function, and calls `tick` often (every tenth of the election timeout is plenty).
 */

export type Role = 'follower' | 'candidate' | 'leader';

/** `data` is null for the no-op a new leader appends. */
export interface RaftEntry<T = unknown> {
  term: number;
  data: T | null;
}

export interface RaftStorage<T = unknown> {
  load(): { term: number; votedFor: string | null; log: RaftEntry<T>[] };
  /** Must be durable when it returns. */
  saveHard(term: number, votedFor: string | null): void;
  /** Keep entries before `from` (1-based), drop the rest, then add `entries`. Must be durable when it returns. */
  replaceFrom(from: number, entries: RaftEntry<T>[]): void;
}

export class MemoryRaftStorage<T = unknown> implements RaftStorage<T> {
  private term = 0;
  private votedFor: string | null = null;
  private log: RaftEntry<T>[] = [];

  load() {
    return { term: this.term, votedFor: this.votedFor, log: structuredClone(this.log) };
  }

  saveHard(term: number, votedFor: string | null): void {
    this.term = term;
    this.votedFor = votedFor;
  }

  replaceFrom(from: number, entries: RaftEntry<T>[]): void {
    this.log = [...this.log.slice(0, from - 1), ...structuredClone(entries)];
  }
}

export interface VoteRequest {
  term: number;
  candidate: string;
  lastIndex: number;
  lastTerm: number;
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

export interface RaftTransport<T = unknown> {
  vote(to: string, request: VoteRequest): Promise<VoteResponse>;
  append(to: string, request: AppendRequest<T>): Promise<AppendResponse>;
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
  /** Every other voter, witnesses included. */
  peers: string[];
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
  private readonly log: RaftEntry<T>[];
  private readonly peers: string[];
  private readonly witness: boolean;
  private readonly electionMs: number;
  private readonly now: () => number;
  private readonly random: () => number;
  private caughtUp: boolean;
  private electionDeadline = 0;
  private nextHeartbeat = 0;
  private noopIndex = 0;
  private readonly nextIndex = new Map<string, number>();
  private readonly matchIndex = new Map<string, number>();
  private readonly lastAck = new Map<string, number>();
  private readonly inflight = new Set<string>();
  private waiters: Waiter[] = [];

  constructor(private readonly options: RaftOptions<T>) {
    this.id = options.id;
    this.peers = options.peers;
    this.witness = options.witness ?? false;
    this.electionMs = options.electionMs ?? 1000;
    this.now = options.now ?? Date.now;
    this.random = options.random ?? Math.random;
    this.caughtUp = !options.rejoin;
    const saved = options.storage.load();
    this.term_ = saved.term;
    this.votedFor = saved.votedFor;
    this.log = saved.log;
    this.resetElection();
  }

  get term(): number {
    return this.term_;
  }

  get lastIndex(): number {
    return this.log.length;
  }

  /** Voters needed for a decision: more than half of everyone. */
  get majority(): number {
    return Math.floor((this.peers.length + 1) / 2) + 1;
  }

  entryAt(index: number): RaftEntry<T> | undefined {
    return this.log[index - 1];
  }

  private termAt(index: number): number {
    return index === 0 ? 0 : (this.log[index - 1]?.term ?? 0);
  }

  private resetElection(): void {
    this.electionDeadline = this.now() + this.electionMs * (1 + this.random());
  }

  /** The leader heard from a majority within the last election timeout, counting itself. */
  hasLease(now = this.now()): boolean {
    if (this.role !== 'leader') return false;
    const times = [now, ...this.peers.map((peer) => this.lastAck.get(peer) ?? 0)].sort((a, b) => b - a);
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
    if (this.witness || !this.caughtUp) return;
    if (now >= this.electionDeadline) this.startElection();
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

  /** Apply the committed log again from the start, after the host threw its state away. */
  resetApplied(): void {
    this.lastApplied = 0;
    this.applyCommitted();
  }

  handleVote(request: VoteRequest): VoteResponse {
    if (request.term < this.term_) return { term: this.term_, granted: false };
    if (request.term > this.term_) this.stepDown(request.term);
    const upToDate = request.lastTerm > this.termAt(this.lastIndex) || (request.lastTerm === this.termAt(this.lastIndex) && request.lastIndex >= this.lastIndex);
    const free = this.votedFor === null || this.votedFor === request.candidate;
    if (!this.caughtUp || !free || !upToDate) return { term: this.term_, granted: false };
    this.votedFor = request.candidate;
    this.options.storage.saveHard(this.term_, this.votedFor);
    this.resetElection();
    return { term: this.term_, granted: true };
  }

  handleAppend(request: AppendRequest<T>): AppendResponse {
    if (request.term < this.term_) return { term: this.term_, success: false, matchIndex: 0 };
    if (request.term > this.term_ || this.role !== 'follower') this.stepDown(request.term);
    this.leaderId = request.leader;
    this.resetElection();
    if (request.prevIndex > this.lastIndex || this.termAt(request.prevIndex) !== request.prevTerm) {
      return { term: this.term_, success: false, matchIndex: Math.min(this.lastIndex, Math.max(0, request.prevIndex - 1)) };
    }
    let index = request.prevIndex;
    const added: RaftEntry<T>[] = [];
    let from = 0;
    for (const entry of request.entries) {
      index++;
      if (added.length === 0) {
        if (index <= this.lastIndex) {
          if (this.termAt(index) === entry.term) continue;
          if (index <= this.commitIndex) throw new Error(`leader ${request.leader} contradicts committed entry ${index}`);
          this.log.length = index - 1;
        }
        from = index;
      }
      added.push(entry);
      this.log.push(entry);
    }
    if (added.length > 0) this.options.storage.replaceFrom(from, added);
    const last = request.prevIndex + request.entries.length;
    if (request.commit > this.commitIndex) {
      this.commitIndex = Math.min(request.commit, last);
      this.applyCommitted();
    }
    if (!this.caughtUp && this.commitIndex >= request.commit) this.caughtUp = true;
    this.settle();
    return { term: this.term_, success: true, matchIndex: last };
  }

  private appendLocal(entry: RaftEntry<T>): number {
    this.log.push(entry);
    this.options.storage.replaceFrom(this.log.length, [entry]);
    return this.log.length;
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
    for (const peer of this.peers) this.replicate(peer);
    this.advanceCommit();
  }

  private replicate(peer: string): void {
    if (this.role !== 'leader' || this.inflight.has(peer)) return;
    const next = this.nextIndex.get(peer) ?? this.lastIndex + 1;
    const prevIndex = next - 1;
    const term = this.term_;
    this.inflight.add(peer);
    this.options.transport
      .append(peer, { term, leader: this.id, prevIndex, prevTerm: this.termAt(prevIndex), entries: this.log.slice(prevIndex, prevIndex + MAX_BATCH), commit: this.commitIndex })
      .then(
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

  /** Commit the highest entry of this term that a majority holds. Older entries commit with it. */
  private advanceCommit(): void {
    if (this.role !== 'leader') return;
    for (let n = this.lastIndex; n > this.commitIndex; n--) {
      if (this.termAt(n) !== this.term_) break;
      const holders = 1 + this.peers.filter((peer) => (this.matchIndex.get(peer) ?? 0) >= n).length;
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
      if (!this.witness) this.options.apply(this.lastApplied, this.log[this.lastApplied - 1]);
    }
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
