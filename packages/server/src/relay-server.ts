import type { Resolver } from '@signet/lib';
import { OHTTP_REQUEST_TYPE, OHTTP_RESPONSE_TYPE, homeGateway } from '@signet/lib';
import type { HttpRequest, HttpResult } from './http';
import { Mix } from './mix';
import type { Rate } from './rate-limit';
import { RateLimiter } from './rate-limit';
import { HttpError, JsonServer } from './http';

/**
 * Oblivious HTTP relay (RFC 9458). It forwards encapsulated requests to a Signet domain's gateway and
 * passes the encapsulated response back. It learns which server is sending and which domain it is
 * sending to, but not the content; the gateway learns the content but sees only the relay. Run it
 * apart from any home server, by an operator that doesn't collude with gateways.
 *
 * It keeps no logs and forwards no headers beyond the content type.
 */
/**
 * What a relay will forward for one source, if it is told to limit anything (Section 10.4.2). `perSource` bounds
 * everything one source sends; `perTarget` bounds what one source sends to one domain, so a source cannot use the relay
 * to flood a gateway. `maxHeld` bounds the requests held for a window, whoever sent them.
 */
export interface RelayLimits {
  perSource: Rate;
  perTarget: Rate;
  maxHeld: number;
  /** How many sources and (source, target) pairs are remembered at once. */
  maxKeys?: number;
}

export class RelayServer {
  /** Count of forwarded requests, for tests and monitoring. Nothing about them is kept. */
  forwarded = 0;
  private readonly server: JsonServer;
  private readonly mix: Mix;
  private readonly bySource?: RateLimiter;
  private readonly byTarget?: RateLimiter;

  /** Requests refused for being over a limit, for tests and monitoring. */
  get refused(): number {
    return (this.bySource?.refused ?? 0) + (this.byTarget?.refused ?? 0);
  }

  constructor(
    private readonly resolver: Resolver,
    private readonly fetchImpl: typeof fetch = fetch,
    /** Hold what is forwarded until the end of a clock-aligned window of this many milliseconds, and forward a window's requests in random order of source (Section 10.6.1). 0 forwards at once. */
    batchMs = 0,
    /** Limit what is forwarded for each source (Section 10.4.2). Without it nothing is limited. */
    private readonly limits?: RelayLimits,
    now: () => number = Date.now,
  ) {
    this.mix = new Mix(batchMs);
    if (limits) {
      this.bySource = new RateLimiter(limits.perSource, limits.maxKeys, now);
      this.byTarget = new RateLimiter(limits.perTarget, limits.maxKeys, now);
    }
    this.server = new JsonServer((request) => this.route(request), 40 * 1024 * 1024);
  }

  get url(): string {
    return this.server.publicUrl;
  }

  listen(port = 0, host = '127.0.0.1', publicUrl?: string): Promise<string> {
    return this.server.listen(port, host, publicUrl);
  }

  async close(): Promise<void> {
    await this.mix.flush();
    return this.server.close();
  }

  /**
   * Refuse a source that is sending too much, before anything is looked up or held for it. The source is the address
   * that connected, which is the sending home; a relay behind a proxy has to be given the proxy's view of it some other way.
   */
  private admit(source: string, domain: string): void {
    if (!this.limits) return;
    if (this.mix.held >= this.limits.maxHeld) throw new HttpError(503, 'too many requests are waiting', { 'retry-after': '2' });
    const wait = this.bySource?.take(source) || this.byTarget?.take(`${source} ${domain.toLowerCase()}`);
    if (wait) throw new HttpError(429, 'too many requests', { 'retry-after': String(wait) });
  }

  private async route(request: HttpRequest): Promise<HttpResult> {
    if (request.method !== 'POST' || request.url.pathname !== '/v0/relay') throw new HttpError(404, 'not found');
    if (request.headers['content-type'] !== OHTTP_REQUEST_TYPE) throw new HttpError(415, `expected ${OHTTP_REQUEST_TYPE}`);
    const domain = request.url.searchParams.get('domain');
    if (!domain) throw new HttpError(400, 'domain is required');
    this.admit(request.remoteAddress ?? 'unknown', domain);
    // Only forward to gateways that Signet domains publish, so the relay can't be pointed at arbitrary URLs.
    // `home` picks one of the domain's homes; without it, the domain's first.
    const policy = await this.resolver.policy(domain);
    const home = request.url.searchParams.get('home');
    const ohttp = homeGateway(policy, home ?? policy.server);
    if (!ohttp) throw new HttpError(404, `${domain} has no OHTTP gateway${home ? ` at ${home}` : ''}`);
    // Requests from one home keep their order; the relay forwards the homes' requests of a window in random order.
    return this.mix.run(request.remoteAddress ?? 'unknown', async () => {
      const response = await this.fetchImpl(ohttp.gateway, { method: 'POST', headers: { 'content-type': OHTTP_REQUEST_TYPE }, body: request.body });
      if (!response.ok) throw new HttpError(502, `gateway answered ${response.status}`);
      this.forwarded += 1;
      return { raw: Buffer.from(await response.arrayBuffer()), contentType: OHTTP_RESPONSE_TYPE };
    });
  }
}
