import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import type { RaftEntry, RaftStorage } from './raft';

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
 * A replica's term, vote and log on disk. The term and vote are replaced atomically; the log is one JSON
 * entry per line, appended and flushed. A line cut short by a crash is dropped on load: it was never
 * acknowledged.
 */
export class FileRaftStorage<T = unknown> implements RaftStorage<T> {
  private readonly hardPath: string;
  private readonly logPath: string;
  private count = 0;

  constructor(private readonly dir: string) {
    mkdirSync(dir, { recursive: true });
    this.hardPath = join(dir, 'raft-state.json');
    this.logPath = join(dir, 'raft-log.jsonl');
  }

  load(): { term: number; votedFor: string | null; log: RaftEntry<T>[] } {
    const hard = existsSync(this.hardPath) ? (JSON.parse(readFileSync(this.hardPath, 'utf8')) as { term: number; votedFor: string | null }) : { term: 0, votedFor: null };
    const lines = existsSync(this.logPath) ? readFileSync(this.logPath, 'utf8').split('\n') : [];
    const log: RaftEntry<T>[] = [];
    lines.forEach((line, i) => {
      if (line === '') return;
      try {
        log.push(JSON.parse(line) as RaftEntry<T>);
      } catch (error) {
        if (i < lines.length - 1) throw error;
      }
    });
    this.count = log.length;
    // Rewrite without a torn last line, so the next append starts on a clean one.
    if (lines.length > 0 && lines[lines.length - 1] !== '') this.rewrite(log);
    return { term: hard.term, votedFor: hard.votedFor, log };
  }

  saveHard(term: number, votedFor: string | null): void {
    const tmp = `${this.hardPath}.tmp`;
    writeDurable(tmp, JSON.stringify({ term, votedFor }), 'w');
    renameSync(tmp, this.hardPath);
    syncDirectory(this.dir);
  }

  replaceFrom(from: number, entries: RaftEntry<T>[]): void {
    if (from - 1 !== this.count) {
      const kept = readFileSync(this.logPath, 'utf8')
        .split('\n')
        .filter((line) => line !== '')
        .slice(0, from - 1)
        .map((line) => JSON.parse(line) as RaftEntry<T>);
      this.rewrite(kept);
    }
    writeDurable(this.logPath, entries.map((entry) => `${JSON.stringify(entry)}\n`).join(''), 'a');
    this.count = from - 1 + entries.length;
  }

  private rewrite(log: RaftEntry<T>[]): void {
    const tmp = `${this.logPath}.tmp`;
    writeDurable(tmp, log.map((entry) => `${JSON.stringify(entry)}\n`).join(''), 'w');
    renameSync(tmp, this.logPath);
    syncDirectory(this.dir);
    this.count = log.length;
  }
}
