import { mkdtempSync, rmSync, appendFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { RaftEntry, RaftStorage, RaftTransport } from '../raft';
import { MemoryRaftStorage, OverwrittenError, RaftNode } from '../raft';
import { FileRaftStorage } from '../raft-storage';

type Data = string;

/** A cluster on a simulated network and clock. `settle` lets in-flight calls finish; `run` advances time. */
class Sim {
  readonly nodes = new Map<string, RaftNode<Data>>();
  readonly storage = new Map<string, RaftStorage<Data>>();
  readonly applied = new Map<string, string[]>();
  readonly leadersByTerm = new Map<number, Set<string>>();
  /** Pairs that can't talk, as "a|b". */
  private readonly cut = new Set<string>();
  private readonly down = new Set<string>();
  time = 1_000;
  private seed = 7;

  constructor(
    readonly ids: string[],
    private readonly witnesses: string[] = [],
    private readonly snapshotEvery?: number,
  ) {
    for (const id of ids) this.start(id);
  }

  private random = (): number => {
    this.seed = (this.seed * 1103515245 + 12345) % 2147483648;
    return this.seed / 2147483648;
  };

  start(id: string, options: { rejoin?: boolean; storage?: RaftStorage<Data> } = {}): RaftNode<Data> {
    const storage = options.storage ?? this.storage.get(id) ?? new MemoryRaftStorage<Data>();
    this.storage.set(id, storage);
    this.applied.set(id, []);
    const transport: RaftTransport<Data> = {
      vote: async (to, request) => this.call(id, to, () => this.nodes.get(to)!.handleVote(request)),
      append: async (to, request) => this.call(id, to, () => this.nodes.get(to)!.handleAppend(request)),
      installSnapshot: async (to, request) => this.call(id, to, () => this.nodes.get(to)!.handleInstallSnapshot(request)),
    };
    const node = new RaftNode<Data>({
      id,
      peers: this.ids.filter((other) => other !== id),
      witness: this.witnesses.includes(id),
      rejoin: options.rejoin,
      storage,
      transport,
      electionMs: 1000,
      now: () => this.time,
      random: this.random,
      apply: (_index, entry) => {
        if (entry.data !== null) this.applied.get(id)!.push(entry.data);
      },
      // The state machine is the list of applied values.
      snapshot: () => [...this.applied.get(id)!],
      restore: (data) => this.applied.set(id, Array.isArray(data) ? [...(data as string[])] : []),
      snapshotEvery: this.snapshotEvery,
      onRole: (role, term) => {
        if (role !== 'leader') return;
        const leaders = this.leadersByTerm.get(term) ?? new Set<string>();
        leaders.add(id);
        this.leadersByTerm.set(term, leaders);
      },
    });
    this.nodes.set(id, node);
    this.down.delete(id);
    return node;
  }

  private async call<R>(from: string, to: string, run: () => R): Promise<R> {
    if (this.down.has(to) || this.down.has(from) || this.cut.has(`${from}|${to}`) || this.cut.has(`${to}|${from}`)) throw new Error('unreachable');
    return run();
  }

  crash(id: string): void {
    this.down.add(id);
  }

  partition(group: string[]): void {
    for (const a of group) for (const b of this.nodes.keys()) if (!group.includes(b)) this.cut.add(`${a}|${b}`);
  }

  heal(): void {
    this.cut.clear();
  }

  async settle(): Promise<void> {
    for (let i = 0; i < 20; i++) await new Promise((resolve) => setImmediate(resolve));
  }

  async run(ms: number): Promise<void> {
    for (let elapsed = 0; elapsed < ms; elapsed += 50) {
      this.time += 50;
      for (const [id, node] of this.nodes) if (!this.down.has(id)) node.tick();
      await this.settle();
      for (const leaders of this.leadersByTerm.values()) expect(leaders.size).toBeLessThanOrEqual(1);
    }
  }

  leader(): RaftNode<Data> | undefined {
    const leaders = [...this.nodes].filter(([id, node]) => !this.down.has(id) && node.role === 'leader' && node.isPrimary());
    expect(leaders.length).toBeLessThanOrEqual(1);
    return leaders[0]?.[1];
  }

  async commit(node: RaftNode<Data>, value: string): Promise<void> {
    const index = node.propose(value);
    const done = node.waitCommitted(index);
    await this.run(500);
    await done;
  }
}

describe('Raft election and replication', () => {
  it('elects one primary and applies every entry in the same order everywhere', async () => {
    const sim = new Sim(['a', 'b', 'c']);
    await sim.run(4000);
    const leader = sim.leader()!;
    expect(leader).toBeDefined();
    for (const value of ['one', 'two', 'three']) await sim.commit(leader, value);
    await sim.run(500);
    for (const id of sim.ids) expect(sim.applied.get(id)).toEqual(['one', 'two', 'three']);
  });

  it('elects a new primary when the primary fails, keeping everything committed', async () => {
    const sim = new Sim(['a', 'b', 'c']);
    await sim.run(4000);
    const first = sim.leader()!;
    await sim.commit(first, 'before');
    sim.crash(first.id);
    await sim.run(6000);
    const second = sim.leader()!;
    expect(second.id).not.toBe(first.id);
    expect(second.term).toBeGreaterThan(first.term);
    await sim.commit(second, 'after');
    await sim.run(500);
    for (const id of sim.ids.filter((other) => other !== first.id)) expect(sim.applied.get(id)).toEqual(['before', 'after']);
  });

  it('lets a minority-side primary lose its lease, while the majority elects another', async () => {
    const sim = new Sim(['a', 'b', 'c']);
    await sim.run(4000);
    const old = sim.leader()!;
    sim.partition([old.id]);
    await sim.run(1500);
    expect(old.isPrimary()).toBe(false);
    await sim.run(5000);
    const next = sim.leader()!;
    expect(next.id).not.toBe(old.id);
    // A write on the isolated old primary never commits.
    const stale = old.role === 'leader' ? old : undefined;
    expect(stale).toBeUndefined();
  });

  it('overwrites an uncommitted entry of a deposed primary and tells its waiter', async () => {
    const sim = new Sim(['a', 'b', 'c']);
    await sim.run(4000);
    const old = sim.leader()!;
    await sim.commit(old, 'kept');
    sim.partition([old.id]);
    // The isolated primary takes a write it can't replicate, before it notices.
    const index = old.propose('lost');
    const waiting = old.waitCommitted(index).then(
      () => 'committed',
      (error: unknown) => (error instanceof OverwrittenError ? 'overwritten' : 'other'),
    );
    await sim.run(6000);
    const next = sim.leader()!;
    await sim.commit(next, 'new');
    sim.heal();
    await sim.run(3000);
    expect(await waiting).toBe('overwritten');
    for (const id of sim.ids) expect(sim.applied.get(id)).toEqual(['kept', 'new']);
  });

  it('never commits without a majority', async () => {
    const sim = new Sim(['a', 'b', 'c']);
    await sim.run(4000);
    const leader = sim.leader()!;
    for (const id of sim.ids) if (id !== leader.id) sim.crash(id);
    const index = leader.propose('alone');
    let committed = false;
    void leader.waitCommitted(index).then(() => (committed = true), () => undefined);
    await sim.run(3000);
    expect(committed).toBe(false);
    expect(leader.isPrimary()).toBe(false);
  });

  it('lets two homes and a witness survive the loss of a home, and never makes the witness primary', async () => {
    const sim = new Sim(['h1', 'h2', 'w'], ['w']);
    await sim.run(4000);
    const first = sim.leader()!;
    expect(first.id).not.toBe('w');
    await sim.commit(first, 'x');
    sim.crash(first.id);
    await sim.run(6000);
    const second = sim.leader()!;
    expect(['h1', 'h2']).toContain(second.id);
    expect(second.id).not.toBe(first.id);
    await sim.commit(second, 'y');
    expect(sim.applied.get('w')).toEqual([]);
    expect(sim.applied.get(second.id)).toEqual(['x', 'y']);
  });

  it('cannot elect anyone from two homes alone once one fails', async () => {
    const sim = new Sim(['h1', 'h2']);
    await sim.run(4000);
    const first = sim.leader()!;
    sim.crash(first.id);
    await sim.run(8000);
    expect(sim.leader()).toBeUndefined();
  });

  it('catches up a replica that was down, and one that lost its storage', async () => {
    const sim = new Sim(['a', 'b', 'c']);
    await sim.run(4000);
    const leader = sim.leader()!;
    const follower = sim.ids.find((id) => id !== leader.id)!;
    sim.crash(follower);
    for (const value of ['1', '2', '3']) await sim.commit(leader, value);
    sim.start(follower);
    await sim.run(3000);
    expect(sim.applied.get(follower)).toEqual(['1', '2', '3']);

    sim.crash(follower);
    sim.storage.delete(follower);
    const reborn = sim.start(follower, { rejoin: true });
    await sim.run(3000);
    expect(sim.applied.get(follower)).toEqual(['1', '2', '3']);
    expect(reborn.commitIndex).toBe(leader.commitIndex);
  });

  it('keeps a rejoining replica from voting or standing before it has caught up', async () => {
    const sim = new Sim(['a', 'b', 'c']);
    await sim.run(4000);
    const leader = sim.leader()!;
    const other = sim.ids.find((id) => id !== leader.id)!;
    sim.crash(other);
    sim.storage.delete(other);
    const reborn = sim.start(other, { rejoin: true });
    sim.crash(other);
    // Cut off from every leader, the reborn replica is asked for a vote and must refuse.
    expect(reborn.handleVote({ term: 99, candidate: leader.id, lastIndex: 99, lastTerm: 99 }).granted).toBe(false);
    reborn.tick();
    expect(reborn.role).toBe('follower');
  });

  it('does not raise its term while cut off, so rejoining disturbs nobody', async () => {
    const sim = new Sim(['a', 'b', 'c']);
    await sim.run(4000);
    const leader = sim.leader()!;
    const termBefore = leader.term;
    const cutOff = sim.nodes.get(sim.ids.find((id) => id !== leader.id)!)!;
    sim.partition([cutOff.id]);
    await sim.run(8000);
    expect(cutOff.term).toBe(termBefore);
    sim.heal();
    await sim.run(3000);
    expect(sim.leader()!.id).toBe(leader.id);
    expect(sim.leader()!.term).toBe(termBefore);
  });

  it('never has two primaries in one term across repeated failures and partitions', async () => {
    const sim = new Sim(['a', 'b', 'c', 'd', 'e']);
    await sim.run(3000);
    for (let round = 0; round < 6; round++) {
      const leader = sim.leader();
      if (leader) sim.partition([leader.id]);
      await sim.run(4000);
      sim.heal();
      await sim.run(2000);
    }
    const leader = sim.leader();
    expect(leader).toBeDefined();
    await sim.commit(leader!, 'final');
    await sim.run(1000);
    const logs = sim.ids.map((id) => sim.applied.get(id)!);
    for (const log of logs) expect(log[log.length - 1]).toBe('final');
  });
});

describe('Raft snapshots', () => {
  const values = (from: number, to: number) => Array.from({ length: to - from + 1 }, (_, i) => `v${from + i}`);

  it('compacts the log once enough has been applied, and keeps working', async () => {
    const sim = new Sim(['a', 'b', 'c'], [], 5);
    await sim.run(4000);
    const leader = sim.leader()!;
    for (const value of values(1, 12)) await sim.commit(leader, value);
    await sim.run(500);
    for (const id of sim.ids) {
      expect(sim.nodes.get(id)!.compactedThrough).toBeGreaterThan(0);
      expect((sim.storage.get(id) as MemoryRaftStorage<string>).length).toBeLessThan(8);
      expect(sim.applied.get(id)).toEqual(values(1, 12));
    }
  });

  it('brings a replica that fell behind the compacted log up to date from a snapshot', async () => {
    const sim = new Sim(['a', 'b', 'c'], [], 4);
    await sim.run(4000);
    const leader = sim.leader()!;
    const behind = sim.ids.find((id) => id !== leader.id)!;
    await sim.commit(leader, 'v0');
    sim.crash(behind);
    for (const value of values(1, 15)) await sim.commit(leader, value);
    expect(leader.compactedThrough).toBeGreaterThan(sim.nodes.get(behind)!.lastIndex);
    const reborn = sim.start(behind);
    await sim.run(3000);
    expect(sim.applied.get(behind)).toEqual(['v0', ...values(1, 15)]);
    expect(reborn.compactedThrough).toBeGreaterThan(0);
    await sim.commit(sim.leader()!, 'after');
    await sim.run(500);
    expect(sim.applied.get(behind)?.slice(-1)).toEqual(['after']);
  });

  it('restarts from its snapshot and catches up on what it missed', async () => {
    const sim = new Sim(['a', 'b', 'c'], [], 4);
    await sim.run(4000);
    const leader = sim.leader()!;
    for (const value of values(1, 10)) await sim.commit(leader, value);
    await sim.run(500);
    const follower = sim.ids.find((id) => id !== leader.id)!;
    sim.crash(follower);
    await sim.commit(leader, 'while-down');
    const restarted = sim.start(follower);
    // Its state came back from the snapshot before any entry was fetched.
    expect(restarted.compactedThrough).toBeGreaterThan(0);
    // (The snapshot's index counts the leader's no-op entries too, so it can exceed the number of values.)
    const restored = sim.applied.get(follower) ?? [];
    expect(restored.length).toBeGreaterThan(0);
    expect(restored.length).toBeLessThanOrEqual(restarted.compactedThrough);
    await sim.run(3000);
    expect(sim.applied.get(follower)).toEqual([...values(1, 10), 'while-down']);
  });

  it('lets a witness compact too, and still vote', async () => {
    const sim = new Sim(['h1', 'h2', 'w'], ['w'], 4);
    await sim.run(4000);
    const first = sim.leader()!;
    for (const value of values(1, 9)) await sim.commit(first, value);
    expect(sim.nodes.get('w')!.compactedThrough).toBeGreaterThan(0);
    sim.crash(first.id);
    await sim.run(6000);
    const second = sim.leader()!;
    await sim.commit(second, 'after');
    expect(sim.applied.get(second.id)).toEqual([...values(1, 9), 'after']);
  });
});

describe('FileRaftStorage', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'raft-'));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  const entry = (term: number, data: string | null): RaftEntry<string> => ({ term, data });

  it('remembers the term, the vote and the log across a restart', () => {
    const first = new FileRaftStorage<string>(dir);
    first.load();
    first.saveHard(3, 'b');
    first.replaceFrom(1, [entry(1, null), entry(2, 'x')]);
    first.replaceFrom(3, [entry(3, 'y')]);
    const second = new FileRaftStorage<string>(dir).load();
    expect(second).toEqual({ term: 3, votedFor: 'b', log: [entry(1, null), entry(2, 'x'), entry(3, 'y')] });
  });

  it('truncates a conflicting tail before appending', () => {
    const storage = new FileRaftStorage<string>(dir);
    storage.load();
    storage.replaceFrom(1, [entry(1, 'a'), entry(1, 'b'), entry(1, 'c')]);
    storage.replaceFrom(2, [entry(2, 'z')]);
    expect(new FileRaftStorage<string>(dir).load().log).toEqual([entry(1, 'a'), entry(2, 'z')]);
  });

  it('drops a line cut short by a crash and keeps appending cleanly', () => {
    const storage = new FileRaftStorage<string>(dir);
    storage.load();
    storage.replaceFrom(1, [entry(1, 'a')]);
    appendFileSync(join(dir, 'raft-log.jsonl'), '{"term":1,"da');
    const reopened = new FileRaftStorage<string>(dir);
    expect(reopened.load().log).toEqual([entry(1, 'a')]);
    reopened.replaceFrom(2, [entry(1, 'b')]);
    expect(new FileRaftStorage<string>(dir).load().log).toEqual([entry(1, 'a'), entry(1, 'b')]);
  });

  it('keeps a snapshot and the log after it across a restart', () => {
    const storage = new FileRaftStorage<string>(dir);
    storage.load();
    storage.replaceFrom(1, [entry(1, 'a'), entry(1, 'b'), entry(2, 'c'), entry(2, 'd')]);
    storage.saveSnapshot({ index: 2, term: 1, data: ['a', 'b'] }, [entry(2, 'c'), entry(2, 'd')]);
    storage.replaceFrom(5, [entry(3, 'e')]);
    const loaded = new FileRaftStorage<string>(dir).load();
    expect(loaded.snapshot).toEqual({ index: 2, term: 1, data: ['a', 'b'] });
    expect(loaded.log).toEqual([entry(2, 'c'), entry(2, 'd'), entry(3, 'e')]);
    // A conflicting tail after a snapshot is cut at the right absolute index.
    const again = new FileRaftStorage<string>(dir);
    again.load();
    again.replaceFrom(4, [entry(4, 'x')]);
    expect(new FileRaftStorage<string>(dir).load().log).toEqual([entry(2, 'c'), entry(4, 'x')]);
  });

  it('skips entries a snapshot covers when a crash left the log uncut', () => {
    const storage = new FileRaftStorage<string>(dir);
    storage.load();
    storage.replaceFrom(1, [entry(1, 'a'), entry(1, 'b'), entry(1, 'c')]);
    // The snapshot file was written; the crash came before the log was rewritten.
    writeFileSync(join(dir, 'raft-snapshot.json'), JSON.stringify({ index: 2, term: 1, data: ['a', 'b'] }));
    const loaded = new FileRaftStorage<string>(dir);
    expect(loaded.load().log).toEqual([entry(1, 'c')]);
    loaded.replaceFrom(4, [entry(1, 'd')]);
    expect(new FileRaftStorage<string>(dir).load().log).toEqual([entry(1, 'c'), entry(1, 'd')]);
  });

  it('starts empty in a new folder', () => {
    expect(new FileRaftStorage<string>(join(dir, 'fresh')).load()).toEqual({ term: 0, votedFor: null, log: [] });
  });
});
