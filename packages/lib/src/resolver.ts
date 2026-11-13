import { resolveTxt } from 'node:dns/promises';
import type { DomainPolicy } from './directory';
import { HomeRegistry, failoverFetch } from './homes';
import { OperatorsError, checkOperators } from './operators';

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
  /** The highest operators statement seen for each domain; a lower one is refused (Section 6.9.2). */
  private readonly seqs = new Map<string, number>();

  constructor(protected readonly fetchImpl: typeof fetch = fetch) {}

  /** `base`, but trying a domain's other homes when the one it was aimed at can't answer (Section 6.8.4). */
  failoverFetch(base: typeof fetch = fetch): typeof fetch {
    return failoverFetch(this.homes, base);
  }

  /** Where the policy may live, tried in order. */
  protected abstract policyUrls(domain: string): Promise<string[]>;

  /** The domain key the DNS record pins, if it does (Section 6.9.2). */
  protected pinnedKey(_domain: string): string | undefined {
    return undefined;
  }

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

  /**
   * Hold a policy to the DNS pin and, when it carries operators, to the owner's signature, expiry and
   * sequence number. A statement that passes replaces the policy's unsigned homes and server.
   */
  private vet(domain: string, policy: DomainPolicy): boolean {
    const pin = this.pinnedKey(domain);
    if (pin !== undefined && policy.domainKey !== pin) return false;
    if (!policy.operators) return true;
    if (pin === undefined) return false;
    try {
      const homes = checkOperators(policy.operators, domain, policy.domainKey);
      const seq = policy.operators.body.seq;
      if (seq < (this.seqs.get(domain) ?? 0)) return false;
      this.seqs.set(domain, seq);
      policy.homes = homes.map((home) => home.url);
      policy.server = homes[0].url;
      return true;
    } catch (error) {
      if (error instanceof OperatorsError || error instanceof TypeError) return false;
      throw error;
    }
  }

  private async fetchPolicy(domain: string): Promise<DomainPolicy> {
    for (const url of await this.policyUrls(domain)) {
      // Redirects are refused: a marketing site bouncing /.well-known to www must not pick the policy.
      const response = await this.fetchImpl(url, { redirect: 'manual' }).catch(() => null);
      if (!response?.ok) continue;
      const policy = (await response.json().catch(() => null)) as DomainPolicy | null;
      if (policy?.v === 'signet0' && policy.domain === domain && this.vet(domain, policy)) return policy;
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
export function parseSignetTxt(records: string[][], domain: string): { hosts: string[]; dk?: string } | null {
  const record = records.map((parts) => parts.join('')).find((text) => /^v=signet0(;|$)/.test(text.trim()));
  if (!record) return null;
  const fields = new Map(
    record
      .split(';')
      .map((part) => part.trim().split('='))
      .filter((pair) => pair.length === 2)
      // Keys are case-insensitive, and so are hosts; a pinned public key is not.
      .map(([key, value]) => [key.trim().toLowerCase(), key.trim().toLowerCase() === 'dk' ? value.trim() : value.trim().toLowerCase()]),
  );
  const host = fields.get('host');
  if (host !== undefined) {
    const hosts = host.split(',').map((part) => part.trim());
    const valid = (name: string) => /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(name) && (name === domain || name.endsWith(`.${domain}`));
    if (!hosts.every(valid)) return null;
    return { hosts: [...new Set(hosts)], dk: fields.get('dk') };
  }
  return { hosts: [`signet.${domain}`, domain], dk: fields.get('dk') };
}

export type TxtLookup = (name: string) => Promise<string[][]>;

/** Looks for `_signet.<domain>` TXT, then fetches the policy over HTTPS from the host it names. */
export class DnsResolver extends CachingResolver {
  private readonly pins = new Map<string, string | undefined>();

  constructor(
    fetchImpl: typeof fetch = fetch,
    private readonly txt: TxtLookup = resolveTxt,
  ) {
    super(fetchImpl);
  }

  protected override pinnedKey(domain: string): string | undefined {
    return this.pins.get(domain);
  }

  protected async policyUrls(domain: string): Promise<string[]> {
    const parsed = parseSignetTxt(await this.txt(`_signet.${domain}`).catch(() => []), domain);
    if (!parsed) throw new NotSignetDomainError(domain);
    this.pins.set(domain, parsed.dk);
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
    /** Domain keys to hold policies to, as a `dk` field would in DNS. A domain with operators needs one. */
    private readonly pins: Map<string, string> = new Map(),
  ) {
    super(fetchImpl);
  }

  protected override pinnedKey(domain: string): string | undefined {
    return this.pins.get(domain);
  }

  protected async policyUrls(domain: string): Promise<string[]> {
    const servers = this.servers.get(domain);
    if (!servers) throw new NotSignetDomainError(domain);
    return [servers].flat().map((server) => `${server}/.well-known/signet.json`);
  }
}
