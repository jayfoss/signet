import type { Cosignature, KeyPair, TreeHead } from '@signet/lib';
import { fromB64u, signCosignature, verifyConsistency, verifyTreeHead } from '@signet/lib';
import { HttpError, JsonServer, json } from './http';

/**
 * A witness for a transparency log (Section 5.5.1). It keeps the last head it signed for the log and cosigns
 * a new one only if the log signed it and it extends the last. A log that shows two different histories cannot
 * get both cosigned by this witness.
 */
export class LogWitnessServer {
  private readonly server: JsonServer;
  private last?: TreeHead;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly key: KeyPair,
    private readonly log: { url: string; key: string },
    private readonly fetchImpl: typeof fetch = fetch,
  ) {
    this.server = new JsonServer(async (request) => {
      if (request.method === 'POST' && request.url.pathname === '/v0/cosign') {
        // One at a time, so two concurrent heads cannot both be judged against the same "last".
        const run = this.queue.then(() => this.cosign(json<{ head: TreeHead }>(request).head));
        this.queue = run.catch(() => undefined);
        return run;
      }
      throw new HttpError(404, 'a log witness only cosigns');
    });
  }

  get url(): string {
    return this.server.publicUrl;
  }

  get publicKey(): string {
    return this.key.publicKey;
  }

  listen(port = 0, host = '127.0.0.1', publicUrl?: string): Promise<string> {
    return this.server.listen(port, host, publicUrl);
  }

  close(): Promise<void> {
    return this.server.close();
  }

  private async cosign(head: TreeHead): Promise<Cosignature> {
    if (!verifyTreeHead(this.log.key, head)) throw new HttpError(400, 'the head is not signed by the log');
    const last = this.last;
    if (last) {
      if (head.size < last.size) throw new HttpError(409, 'the log has gone back');
      if (head.size === last.size && head.root !== last.root) throw new HttpError(409, 'the log has forked');
      if (head.size > last.size) {
        const response = await this.fetchImpl(`${this.log.url}/v0/consistency?first=${last.size}&second=${head.size}`);
        if (!response.ok) throw new HttpError(502, 'could not get a consistency proof from the log');
        const { path } = (await response.json()) as { path: string[] };
        if (!verifyConsistency(last.size, head.size, fromB64u(last.root), fromB64u(head.root), path)) throw new HttpError(409, 'the head does not extend the last one');
      }
    }
    if (!last || head.size >= last.size) this.last = head;
    return signCosignature(this.key, this.log.key, head);
  }
}
