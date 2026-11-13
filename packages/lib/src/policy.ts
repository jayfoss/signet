import type { KeyPair } from './crypto';
import { sha256, signJson, verifyJson } from './crypto';
import type { DomainPolicy } from './directory';

/** The signed change of a domain key (Section 6.5): the old key vouches for the new one. */
export interface KeyRotation {
  from: string;
  sig: string;
}

const rotationBody = (domain: string, from: string, to: string) => ({ v: 'signet0', domain, from, to });

/** Rotate `oldKey` to `newPublicKey`: the proof a policy carries in `rotation`. */
export function signRotation(oldKey: KeyPair, domain: string, newPublicKey: string): KeyRotation {
  return { from: oldKey.publicKey, sig: signJson(oldKey, rotationBody(domain, oldKey.publicKey, newPublicKey)) };
}

/** Whether `rotation` moves `domain` from `cachedKey` to `newKey`. */
export function verifyRotation(rotation: KeyRotation | undefined, domain: string, cachedKey: string, newKey: string): boolean {
  return (
    rotation !== undefined &&
    typeof rotation.from === 'string' &&
    typeof rotation.sig === 'string' &&
    rotation.from === cachedKey &&
    verifyJson(rotation.from, rotationBody(domain, rotation.from, newKey), rotation.sig)
  );
}

/** Where a domain records its own key in the transparency log (Section 5.3.1). A domain's name is public, so this is no VRF. */
export const domainKeyIndex = (domain: string): string => sha256(`signet0 domain-key|${domain.toLowerCase()}`).slice('sha256:'.length);

const serverBody = (policy: Pick<DomainPolicy, 'domain' | 'server' | 'replicas'>) => ({
  v: 'signet0',
  domain: policy.domain,
  server: policy.server,
  ...(policy.replicas ? { replicas: policy.replicas } : {}),
});

/** The domain key's signature over the policy's server URLs, required for a URL outside the domain (Section 6.4). */
export const signServerUrls = (domainKey: KeyPair, policy: Pick<DomainPolicy, 'domain' | 'server' | 'replicas'>): string => signJson(domainKey, serverBody(policy));

export const underDomain = (url: string, domain: string): boolean => {
  const host = new URL(url).hostname.toLowerCase();
  return host === domain || host.endsWith(`.${domain}`);
};

/**
 * The rules of Section 6.4 for the policy's server and replicas: https with no user information, query or
 * fragment; and a URL outside the domain only with a `dk` pin and the domain key's signature over the URLs.
 * Returns an error message, or null if the policy passes.
 */
export function serverUrlProblem(policy: DomainPolicy, pin: string | undefined, requireHttps: boolean): string | null {
  const urls = [policy.server, ...(policy.replicas ?? [])];
  let outside = false;
  for (const raw of urls) {
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      return `${raw} is not a URL`;
    }
    if (requireHttps && url.protocol !== 'https:') return `${raw} is not https`;
    if (url.username || url.password || url.search || url.hash) return `${raw} carries user information, a query or a fragment`;
    if (!underDomain(raw, policy.domain)) outside = true;
  }
  if (!outside) return null;
  if (pin === undefined || policy.domainKey !== pin) return 'a server outside the domain needs dk in the DNS record';
  if (typeof policy.serverSig !== 'string' || !verifyJson(policy.domainKey, serverBody(policy), policy.serverSig)) return 'serverSig does not verify';
  return null;
}
