import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/** Where a replica keeps attachment ciphertext, apart from the replicated log (Section 6.8.5). */
export interface BlobStore {
  put(id: string, data: Buffer): void;
  get(id: string): Buffer | undefined;
  delete(id: string): void;
  /** Every stored blob and when it was written (ms). */
  list(): { id: string; at: number }[];
}

/** Ids are made by the primary and carried in paths, so only this shape is ever turned into a file name. */
export const BLOB_ID = /^blob_[A-Za-z0-9_-]{1,80}$/;

export class MemoryBlobStore implements BlobStore {
  private readonly blobs = new Map<string, { data: Buffer; at: number }>();

  put(id: string, data: Buffer): void {
    this.blobs.set(id, { data, at: Date.now() });
  }

  get(id: string): Buffer | undefined {
    return this.blobs.get(id)?.data;
  }

  delete(id: string): void {
    this.blobs.delete(id);
  }

  list(): { id: string; at: number }[] {
    return [...this.blobs].map(([id, { at }]) => ({ id, at }));
  }
}

/** One file per blob, written under a temporary name and renamed, so a crash never leaves half a blob under its id. */
export class FileBlobStore implements BlobStore {
  constructor(private readonly dir: string) {
    mkdirSync(dir, { recursive: true });
  }

  put(id: string, data: Buffer): void {
    if (!BLOB_ID.test(id)) throw new Error('not a blob id');
    const tmp = join(this.dir, `${id}.tmp`);
    writeFileSync(tmp, data);
    renameSync(tmp, join(this.dir, id));
  }

  get(id: string): Buffer | undefined {
    if (!BLOB_ID.test(id)) return undefined;
    const path = join(this.dir, id);
    return existsSync(path) ? readFileSync(path) : undefined;
  }

  delete(id: string): void {
    if (!BLOB_ID.test(id)) return;
    const path = join(this.dir, id);
    if (existsSync(path)) unlinkSync(path);
  }

  list(): { id: string; at: number }[] {
    return readdirSync(this.dir)
      .filter((name) => BLOB_ID.test(name))
      .map((id) => ({ id, at: statSync(join(this.dir, id)).mtimeMs }));
  }
}
