import { closeSync, existsSync, fsyncSync, openSync, readFileSync, writeSync } from 'node:fs';
import type { KeyPair, LogLeaf, Resolver } from '@signet/lib';
import { MerkleLog, ReplayCache, verifyDomainCall } from '@signet/lib';
import type { HttpRequest } from './http';
import { HttpError, JsonServer, header, json } from './http';

/**
 * The transparency log service. Domains append a leaf for every directory change; anyone can read
 * signed tree heads, the latest leaf for an address hash, its history, and consistency proofs.
 * Run at least two independent operators before relying on it in production.
 */
export class TransparencyLogServer {
  readonly log: MerkleLog;
  private readonly server: JsonServer;
  private readonly counts = new Map<string, number>();
  private readonly replays = new ReplayCache();

  constructor(
    key: KeyPair,
    private readonly resolver: Resolver,
    private readonly limits = { queriesPerDomainPerDay: 50_000, queriesPerRequesterPerDay: 1_000, anonymousQueriesPerIpPerDay: 20 },
    /** Append-only file of leaves, one JSON line each. Without it the log lives in memory and a restart forks it. */
    private readonly dataFile?: string,
  ) {
    this.log = new MerkleLog(key);
    if (dataFile && existsSync(dataFile)) {
      for (const line of readFileSync(dataFile, 'utf8').split('\n')) if (line.trim()) this.log.append(JSON.parse(line) as LogLeaf);
    }
    this.server = new JsonServer((request) => this.route(request), 64 * 1024);
  }

  get url(): string {
    return this.server.publicUrl;
  }

  get publicKey(): string {
    return this.log.publicKey;
  }

  listen(port = 0, host = '127.0.0.1', publicUrl?: string): Promise<string> {
    return this.server.listen(port, host, publicUrl);
  }

  close(): Promise<void> {
    return this.server.close();
  }

  private async route(request: HttpRequest): Promise<unknown> {
    const { method, url } = request;
    const key = url.searchParams.get('key') ?? '';
    // Leaves are filed by the domain that wrote them and the address's index within it.
    const domain = url.searchParams.get('domain') ?? '';
    if (method === 'GET' && url.pathname === '/v0/tree-head') return this.log.treeHead();
    if (method === 'GET' && url.pathname === '/v0/latest') {
      await this.authorizeQuery(request);
      return this.log.latest(domain, key);
    }
    if (method === 'GET' && url.pathname === '/v0/history') {
      await this.authorizeQuery(request);
      return { history: this.log.history(domain, key), head: this.log.treeHead() };
    }
    if (method === 'GET' && url.pathname === '/v0/consistency') {
      const first = Number(url.searchParams.get('first'));
      const second = Number(url.searchParams.get('second'));
      return { path: this.log.consistency(first, second) };
    }
    if (method === 'POST' && url.pathname === '/v0/append') return this.append(request);
    throw new HttpError(404, 'not found');
  }

  /**
   * Leaves are keyed by a hash of the address, which anyone can compute, so per-address queries would
   * otherwise reveal who is enrolled. Signet servers get a daily budget per domain and per (hashed)
   * requester; anyone else gets a small per-IP budget. Tree heads and consistency proofs stay public.
   */
  private async authorizeQuery(request: HttpRequest): Promise<void> {
    const day = new Date().toISOString().slice(0, 10);
    // A device its own server has locked out (say, after a rebinding) can still check its history, slowly.
    const budgets: (readonly [string, number])[] = [];
    if (request.headers['signet-domain']) {
      // Reads may come from any home of the domain; only the domain itself may write (Section 6.9.3).
      const domain = await this.authenticate(request, 'query', true);
      const requester = request.url.searchParams.get('requester') ?? 'unknown';
      budgets.push([`${day}:@${domain}`, this.limits.queriesPerDomainPerDay], [`${day}:${domain}:${requester}`, this.limits.queriesPerRequesterPerDay]);
    } else {
      budgets.push([`${day}:ip:${request.remoteAddress}`, this.limits.anonymousQueriesPerIpPerDay]);
    }
    for (const [key, max] of budgets) {
      const count = (this.counts.get(key) ?? 0) + 1;
      this.counts.set(key, count);
      if (count > max) throw new HttpError(429, 'too many log queries today');
    }
  }

  private async authenticate(request: HttpRequest, action: string, allowHomes = false): Promise<string> {
    const domain = header(request.headers, 'signet-domain');
    const policy = await this.resolver.policy(domain);
    const home = request.headers['signet-home'];
    const ok =
      (allowHomes || home === undefined) &&
      verifyDomainCall(
        policy,
        { sig: header(request.headers, 'signet-sig'), ts: header(request.headers, 'signet-ts'), nonce: header(request.headers, 'signet-nonce'), home: typeof home === 'string' ? home : undefined },
        request.method,
        request.path,
        request.body,
      );
    if (!ok) throw new HttpError(401, `${action} is not signed by ${domain}`);
    if (!this.replays.firstUse(`${domain} ${header(request.headers, 'signet-sig')}`)) throw new HttpError(401, `${action} was already used`);
    return domain;
  }

  /** Only a domain may write leaves about its own addresses, signed with the key in its published policy. */
  private async append(request: HttpRequest): Promise<{ index: number }> {
    const domain = await this.authenticate(request, 'append');
    const leaf = json<LogLeaf>(request);
    if (leaf.v !== 0 || leaf.domain !== domain) throw new HttpError(403, `${domain} can only log its own addresses`);
    return { index: this.record(leaf) };
  }

  /**
   * Write the leaf to disk, fsynced, before it enters the tree. With the same key and file, a restarted log
   * signs the same roots, so it never signs two different trees of one size.
   */
  record(leaf: LogLeaf): number {
    if (this.dataFile) {
      const fd = openSync(this.dataFile, 'a', 0o600);
      try {
        writeSync(fd, `${JSON.stringify(leaf)}\n`);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
    }
    return this.log.append(leaf);
  }
}
