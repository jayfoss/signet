import type { IssuerKey, IssuerKeyPair, Resolver } from '@signet/lib';
import { ReplayCache, blindSign, generateIssuerKey, verifyDomainAuth } from '@signet/lib';
import type { HttpRequest } from './http';
import { HttpError, JsonServer, header, json } from './http';

/**
 * Privacy Pass issuer (RFC 9576 split model). Home servers act as attesters: they know their users
 * and rate-limit them, then forward blinded token requests here signed as their domain. The issuer
 * signs without seeing the tokens, so it can't link a token to the request that produced it, and
 * caps how many tokens each domain may get per day.
 */
export class IssuerServer {
  readonly key: IssuerKeyPair;
  private readonly server: JsonServer;
  private readonly counts = new Map<string, number>();
  private readonly replays = new ReplayCache();

  constructor(
    name: string,
    private readonly resolver: Resolver,
    private readonly tokensPerDomainPerDay = 100_000,
    key?: IssuerKeyPair,
  ) {
    this.key = key ?? generateIssuerKey(name);
    this.server = new JsonServer((request) => this.route(request), 256 * 1024);
  }

  get url(): string {
    return this.server.publicUrl;
  }

  get publicKey(): IssuerKey {
    return { name: this.key.name, publicKey: this.key.publicKey };
  }

  listen(port = 0, host = '127.0.0.1', publicUrl?: string): Promise<string> {
    return this.server.listen(port, host, publicUrl);
  }

  close(): Promise<void> {
    return this.server.close();
  }

  private async route(request: HttpRequest): Promise<unknown> {
    if (request.method === 'GET' && request.url.pathname === '/v0/issuer-key') return this.publicKey;
    if (request.method === 'POST' && request.url.pathname === '/v0/issue') return this.issue(request);
    throw new HttpError(404, 'not found');
  }

  private async issue(request: HttpRequest): Promise<{ signatures: string[] }> {
    const domain = header(request.headers, 'signet-domain');
    const { domainKey } = await this.resolver.policy(domain);
    const ok = verifyDomainAuth(
      domain,
      domainKey,
      header(request.headers, 'signet-sig'),
      header(request.headers, 'signet-ts'),
      header(request.headers, 'signet-nonce'),
      request.method,
      request.path,
      request.body,
    );
    if (!ok) throw new HttpError(401, `token request is not signed by ${domain}`);
    if (!this.replays.firstUse(`${domain} ${header(request.headers, 'signet-sig')}`)) throw new HttpError(401, 'token request was already used');
    const { blinded } = json<{ blinded: string[] }>(request);
    const key = `${new Date().toISOString().slice(0, 10)}:${domain}`;
    const total = (this.counts.get(key) ?? 0) + blinded.length;
    this.counts.set(key, total);
    if (total > this.tokensPerDomainPerDay) throw new HttpError(429, `${domain} has used today's tokens`);
    return { signatures: blinded.map((message) => blindSign(this.key, message)) };
  }
}
