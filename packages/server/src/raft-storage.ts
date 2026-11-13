import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import type { RaftEntry, RaftSnapshot, RaftStorage } from './raft';

/** Write `data` to `path` and flush it to disk before returning. */
function writeDurable(path: string, data: string, flags: 'w' | 'a'): void {
  const fd = openSync(path, flags);
  try {
    writeSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function syncDirectory(dir: string): void {
  try {
    const fd = openSync(dir, 'r');
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  } catch {
    // Some platforms can't open a directory; the file itself is already flushed.
  }
}

/**
 * A replica's term, vote, snapshot and log on disk. The term and vote and the snapshot are replaced
 * atomically. The log is a header line naming the index it starts after, then one JSON entry per line,
 * appended and flushed. A snapshot is written before the log is cut down to match it, so a crash between
 * the two leaves a log that starts too early, and the entries the snapshot covers are skipped on load. A line
 * cut short by a crash is dropped: it was never acknowledged.
 */
export class FileRaftStorage<T = unknown> implements RaftStorage<T> {
  private readonly hardPath: string;
  private readonly logPath: string;
  private readonly snapshotPath: string;
  /** The index the log file starts after, and how many entries it holds. */
  private base = 0;
  private count = 0;

  constructor(private readonly dir: string) {
    mkdirSync(dir, { recursive: true });
    this.hardPath = join(dir, 'raft-state.json');
    this.logPath = join(dir, 'raft-log.jsonl');
    this.snapshotPath = join(dir, 'raft-snapshot.json');
  }

  load(): { term: number; votedFor: string | null; log: RaftEntry<T>[]; snapshot?: RaftSnapshot } {
    const hard = existsSync(this.hardPath) ? (JSON.parse(readFileSync(this.hardPath, 'utf8')) as { term: number; votedFor: string | null }) : { term: 0, votedFor: null };
    const snapshot = existsSync(this.snapshotPath) ? (JSON.parse(readFileSync(this.snapshotPath, 'utf8')) as RaftSnapshot) : undefined;
    const lines = existsSync(this.logPath) ? readFileSync(this.logPath, 'utf8').split('\n') : [];
    let base = 0;
    const entries: RaftEntry<T>[] = [];
    lines.forEach((line, i) => {
      if (line === '') return;
      try {
        const parsed = JSON.parse(line) as RaftEntry<T> | { base: number };
        if (i === 0 && 'base' in parsed) base = parsed.base;
        else entries.push(parsed as RaftEntry<T>);
      } catch (error) {
        if (i < lines.length - 1) throw error;
      }
    });
    // A crash after the snapshot but before the log was cut leaves entries the snapshot already covers.
    const covered = snapshot ? Math.max(0, snapshot.index - base) : 0;
    const log = entries.slice(covered);
    this.base = snapshot ? Math.max(base, snapshot.index) : base;
    this.count = log.length;
    // Rewrite without a torn last line or covered entries, so the next append starts on a clean one, and so a new log has its header.
    if (lines.length === 0 || lines[lines.length - 1] !== '' || covered > 0) this.rewrite(log);
    return { term: hard.term, votedFor: hard.votedFor, log, snapshot };
  }

  saveHard(term: number, votedFor: string | null): void {
    const tmp = `${this.hardPath}.tmp`;
    writeDurable(tmp, JSON.stringify({ term, votedFor }), 'w');
    renameSync(tmp, this.hardPath);
    syncDirectory(this.dir);
  }

  replaceFrom(from: number, entries: RaftEntry<T>[]): void {
    const keep = from - this.base - 1;
    if (keep !== this.count) {
      const kept = readFileSync(this.logPath, 'utf8')
        .split('\n')
        .filter((line) => line !== '')
        .slice(1, 1 + keep)
        .map((line) => JSON.parse(line) as RaftEntry<T>);
      this.rewrite(kept);
    }
    writeDurable(this.logPath, entries.map((entry) => `${JSON.stringify(entry)}\n`).join(''), 'a');
    this.count = keep + entries.length;
  }

  saveSnapshot(snapshot: RaftSnapshot, remaining: RaftEntry<T>[]): void {
    const tmp = `${this.snapshotPath}.tmp`;
    writeDurable(tmp, JSON.stringify(snapshot), 'w');
    renameSync(tmp, this.snapshotPath);
    syncDirectory(this.dir);
    this.base = snapshot.index;
    this.rewrite(remaining);
  }

  private rewrite(log: RaftEntry<T>[]): void {
    const tmp = `${this.logPath}.tmp`;
    writeDurable(tmp, [`${JSON.stringify({ base: this.base })}\n`, ...log.map((entry) => `${JSON.stringify(entry)}\n`)].join(''), 'w');
    renameSync(tmp, this.logPath);
    syncDirectory(this.dir);
    this.count = log.length;
  }
}
