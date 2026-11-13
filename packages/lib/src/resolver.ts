import { resolveTxt } from 'node:dns/promises';
import type { DomainPolicy } from './directory';
import { HomeRegistry, failoverFetch } from './homes';

export interface Resolver {
  policy(domain: string): Promise<DomainPolicy>;
  /** `base`, but falling back across a domain's homes (Section 6.8.4). Resolvers that know no homes leave it out. */
  failoverFetch?(base?: typeof fetch): typeof fetch;
}

export class NotSignetDomainError extends Error {
  constructor(readonly domain: string) {
    super(`${domain} does not support Signet`);
  }
}

/**
 * Caches each policy for its max_age. While a policy is cached, a failed refresh keeps using it,
 * so an attacker who blocks DNS or HTTPS can't quietly downgrade a domain we already know.
 */
abstract class CachingResolver implements Resolver {
  private readonly cache = new Map<string, { policy: DomainPolicy; until: number }>();
  /** The homes of every domain this resolver has seen, so a fetch aimed at one can fall back to the others. */
  readonly homes = new HomeRegistry();

  constructor(protected readonly fetchImpl: typeof fetch = fetch) {}

  /** `base`, but trying a domain's other homes when the one it was aimed at can't answer (Section 6.8.4). */
  failoverFetch(base: typeof fetch = fetch): typeof fetch {
    return failoverFetch(this.homes, base);
  }

  /** Where the policy may live, tried in order. */
  protected abstract policyUrls(domain: string): Promise<string[]>;

  async policy(domain: string): Promise<DomainPolicy> {
    const cached = this.cache.get(domain);
    try {
      const policy = await this.fetchPolicy(domain);
      this.cache.set(domain, { policy, until: Date.now() + policy.maxAge * 1000 });
      this.homes.register(policy);
      return policy;
    } catch (error) {
      if (cached && cached.until > Date.now() && cached.policy.mode === 'enforce') return cached.policy;
      throw error;
    }
  }

  private async fetchPolicy(domain: string): Promise<DomainPolicy> {
    for (const url of await this.policyUrls(domain)) {
      // Redirects are refused: a marketing site bouncing /.well-known to www must not pick the policy.
      const response = await this.fetchImpl(url, { redirect: 'manual' }).catch(() => null);
      if (!response?.ok) continue;
      const policy = (await response.json().catch(() => null)) as DomainPolicy | null;
      if (policy?.v === 'signet0' && policy.domain === domain) return policy;
    }
    throw new NotSignetDomainError(domain);
  }
}

/**
 * Reads `_signet.<domain>` TXT, e.g. `v=signet0; host=signet.example.com`. The optional `host` says
 * where the policy is served, MTA-STS style, so it needn't live on the apex (often a marketing site).
 * It may list several hosts separated by commas (Section 6.8.3). Each must be the domain or one of its subdomains, so control stays with whoever runs the zone. Without
 * it, `signet.<domain>` is tried first, then the apex.
 */
export function parseSignetTxt(records: string[][], domain: string): { hosts: string[] } | null {
  const record = records.map((parts) => parts.join('')).find((text) => /^v=signet0(;|$)/.test(text.trim()));
  if (!record) return null;
  const fields = new Map(
    record
      .split(';')
      .map((part) => part.trim().split('='))
      .filter((pair) => pair.length === 2)
      .map(([key, value]) => [key.trim().toLowerCase(), value.trim().toLowerCase()]),
  );
  const host = fields.get('host');
  if (host !== undefined) {
    const hosts = host.split(',').map((part) => part.trim());
    const valid = (name: string) => /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(name) && (name === domain || name.endsWith(`.${domain}`));
    if (!hosts.every(valid)) return null;
    return { hosts: [...new Set(hosts)] };
  }
  return { hosts: [`signet.${domain}`, domain] };
}

export type TxtLookup = (name: string) => Promise<string[][]>;

/** Looks for `_signet.<domain>` TXT, then fetches the policy over HTTPS from the host it names. */
export class DnsResolver extends CachingResolver {
  constructor(
    fetchImpl: typeof fetch = fetch,
    private readonly txt: TxtLookup = resolveTxt,
  ) {
    super(fetchImpl);
  }

  protected async policyUrls(domain: string): Promise<string[]> {
    const parsed = parseSignetTxt(await this.txt(`_signet.${domain}`).catch(() => []), domain);
    if (!parsed) throw new NotSignetDomainError(domain);
    return parsed.hosts.map((host) => `https://${host}/.well-known/signet.json`);
  }
}

/**
 * Maps domains straight to server URLs, for local demos and tests where there is no DNS. A domain may map to
 * several URLs, which are tried in order like the hosts of a `_signet` record.
 */
export class StaticResolver extends CachingResolver {
  constructor(
    private readonly servers: Map<string, string | string[]>,
    fetchImpl: typeof fetch = fetch,
  ) {
    super(fetchImpl);
  }

  protected async policyUrls(domain: string): Promise<string[]> {
    const servers = this.servers.get(domain);
    if (!servers) throw new NotSignetDomainError(domain);
    return [servers].flat().map((server) => `${server}/.well-known/signet.json`);
  }
}
