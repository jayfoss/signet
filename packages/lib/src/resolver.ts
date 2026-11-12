import { resolveTxt } from 'node:dns/promises';
import type { DomainPolicy } from './directory';

export interface Resolver {
  policy(domain: string): Promise<DomainPolicy>;
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

  constructor(protected readonly fetchImpl: typeof fetch = fetch) {}

  /** Where the policy may live, tried in order. */
  protected abstract policyUrls(domain: string): Promise<string[]>;

  async policy(domain: string): Promise<DomainPolicy> {
    const cached = this.cache.get(domain);
    try {
      const policy = await this.fetchPolicy(domain);
      this.cache.set(domain, { policy, until: Date.now() + policy.maxAge * 1000 });
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
 * It must be the domain or one of its subdomains, so control stays with whoever runs the zone. Without
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
    const valid = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(host);
    if (!valid || (host !== domain && !host.endsWith(`.${domain}`))) return null;
    return { hosts: [host] };
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

/** Maps domains straight to server URLs, for local demos and tests where there is no DNS. */
export class StaticResolver extends CachingResolver {
  constructor(
    private readonly servers: Map<string, string>,
    fetchImpl: typeof fetch = fetch,
  ) {
    super(fetchImpl);
  }

  protected async policyUrls(domain: string): Promise<string[]> {
    const server = this.servers.get(domain);
    if (!server) throw new NotSignetDomainError(domain);
    return [`${server}/.well-known/signet.json`];
  }
}
