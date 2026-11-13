import type { DomainPolicy } from './directory';

/** The base URLs of a domain's homes, in the policy's order of preference. A policy without `homes` has one. */
export function policyHomes(policy: Pick<DomainPolicy, 'server' | 'homes'>): string[] {
  const homes = policy.homes?.length ? policy.homes : [policy.server];
  return [...new Set(homes.map(originOf))];
}

const originOf = (url: string): string => new URL(url).origin;

interface HomeGroup {
  homes: string[];
  /** The home that last answered, tried first. */
  preferred: string;
}

/** Which homes belong together, learned from the policies a resolver has fetched. */
export class HomeRegistry {
  private readonly groups = new Map<string, HomeGroup>();

  /** Record a policy's homes. A domain keeps its last good home across refreshes while that home is still listed. */
  register(policy: Pick<DomainPolicy, 'server' | 'homes'>): void {
    const homes = policyHomes(policy);
    const group: HomeGroup = { homes, preferred: homes[0] };
    for (const origin of homes) {
      const old = this.groups.get(origin);
      if (old && homes.includes(old.preferred)) group.preferred = old.preferred;
    }
    for (const origin of homes) this.groups.set(origin, group);
  }

  groupOf(origin: string): HomeGroup | undefined {
    return this.groups.get(origin);
  }
}

const SIGNET_PRIMARY = 'signet-primary';

const resendable = (init?: RequestInit): boolean => init?.body === undefined || init.body === null || typeof init.body === 'string' || Buffer.isBuffer(init.body) || init.body instanceof Uint8Array;

/**
 * A fetch that tries a domain's other homes when the one it was aimed at can't answer (Section 6.8.4).
 * It moves on after a connection failure or a response of 500 or above, and follows a 421's
 * `Signet-Primary` once, but only to a home the policy lists. Requests to any other host pass through.
 * The URL's path and query are kept, so signatures over them stay valid at every home.
 */
export function failoverFetch(registry: HomeRegistry, base: typeof fetch = fetch): typeof fetch {
  return async (input, init) => {
    const target = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    const group = registry.groupOf(target.origin);
    if (!group || group.homes.length < 2 || !resendable(init)) return base(input, init);
    const queue = [group.preferred, ...group.homes.filter((origin) => origin !== group.preferred)];
    const tried = new Set<string>();
    let lastResponse: Response | undefined;
    let lastError: unknown;
    while (queue.length > 0) {
      const origin = queue.shift() as string;
      if (tried.has(origin)) continue;
      tried.add(origin);
      let response: Response;
      try {
        response = await base(`${origin}${target.pathname}${target.search}`, init);
      } catch (error) {
        lastError = error;
        continue;
      }
      if (response.status === 421) {
        lastResponse = response;
        const hint = response.headers.get(SIGNET_PRIMARY);
        const hinted = hint ? safeOrigin(hint) : undefined;
        if (hinted && group.homes.includes(hinted) && !tried.has(hinted)) queue.unshift(hinted);
        continue;
      }
      if (response.status >= 500) {
        lastResponse = response;
        continue;
      }
      group.preferred = origin;
      return response;
    }
    if (lastResponse) return lastResponse;
    throw lastError ?? new Error(`no home of ${target.origin} answered`);
  };
}

const safeOrigin = (url: string): string | undefined => {
  try {
    return new URL(url).origin;
  } catch {
    return undefined;
  }
};
