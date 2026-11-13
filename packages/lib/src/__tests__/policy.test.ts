import { generateSigningKey } from '../crypto';
import type { DomainPolicy } from '../directory';
import { signRotation, signServerUrls, verifyRotation } from '../policy';
import { DnsResolver, DomainKeyChangedError, NotSignetDomainError } from '../resolver';

const DOMAIN = 'example.com';

/** A resolver whose DNS says `dk` (if any) and whose policy host serves whatever `policies` holds for the URL. */
function resolver(policies: Record<string, DomainPolicy>, dk?: string) {
  const serve = async (url: string | URL | Request) => {
    const policy = policies[String(url)];
    return policy ? Response.json(policy) : new Response('no', { status: 404 });
  };
  return new DnsResolver(serve as typeof fetch, async () => [[`v=signet0; host=signet.${DOMAIN}${dk ? `; dk=${dk}` : ''}`]]);
}

const base = (domainKey: string, extra: Partial<DomainPolicy> = {}): DomainPolicy => ({
  v: 'signet0',
  domain: DOMAIN,
  server: `https://signet.${DOMAIN}`,
  mode: 'enforce',
  maxAge: 3600,
  domainKey,
  vrfKey: 'vrf',
  log: { url: 'https://log.example.org', key: 'log' },
  ...extra,
});

const URL_OF = `https://signet.${DOMAIN}/.well-known/signet.json`;

describe('domain key continuity (Section 6.5)', () => {
  const oldKey = generateSigningKey();
  const newKey = generateSigningKey();

  it('verifies a rotation only from the key the client holds', () => {
    const rotation = signRotation(oldKey, DOMAIN, newKey.publicKey);
    expect(verifyRotation(rotation, DOMAIN, oldKey.publicKey, newKey.publicKey)).toBe(true);
    expect(verifyRotation(rotation, DOMAIN, generateSigningKey().publicKey, newKey.publicKey)).toBe(false);
    expect(verifyRotation(rotation, DOMAIN, oldKey.publicKey, generateSigningKey().publicKey)).toBe(false);
    expect(verifyRotation(rotation, 'other.com', oldKey.publicKey, newKey.publicKey)).toBe(false);
    expect(verifyRotation(undefined, DOMAIN, oldKey.publicKey, newKey.publicKey)).toBe(false);
  });

  it('keeps the cached policy when a refresh swaps the key without proof, and takes the key with proof', async () => {
    const policies: Record<string, DomainPolicy> = { [URL_OF]: base(oldKey.publicKey) };
    const dns = resolver(policies);
    expect((await dns.policy(DOMAIN)).domainKey).toBe(oldKey.publicKey);

    policies[URL_OF] = base(newKey.publicKey);
    expect((await dns.policy(DOMAIN)).domainKey).toBe(oldKey.publicKey);

    policies[URL_OF] = base(newKey.publicKey, { rotation: signRotation(generateSigningKey(), DOMAIN, newKey.publicKey) });
    expect((await dns.policy(DOMAIN)).domainKey).toBe(oldKey.publicKey);

    policies[URL_OF] = base(newKey.publicKey, { rotation: signRotation(oldKey, DOMAIN, newKey.publicKey) });
    expect((await dns.policy(DOMAIN)).domainKey).toBe(newKey.publicKey);
  });

  it('trusts the first key it sees when it holds no policy', async () => {
    const dns = resolver({ [URL_OF]: base(newKey.publicKey) });
    expect((await dns.policy(DOMAIN)).domainKey).toBe(newKey.publicKey);
  });

  it('reports the unproven change when there is nothing cached to fall back on', () => {
    expect(new DomainKeyChangedError(DOMAIN).message).toContain('without a proof');
  });
});

describe('server URLs (Section 6.4)', () => {
  const key = generateSigningKey();

  it('accepts servers under the domain without further proof', async () => {
    const dns = resolver({ [URL_OF]: base(key.publicKey, { server: `https://home.eu.${DOMAIN}` }) });
    expect((await dns.policy(DOMAIN)).server).toBe(`https://home.eu.${DOMAIN}`);
  });

  it('refuses http, user information and queries', async () => {
    for (const server of [`http://signet.${DOMAIN}`, `https://user:pw@signet.${DOMAIN}`, `https://signet.${DOMAIN}/?x=1`]) {
      await expect(resolver({ [URL_OF]: base(key.publicKey, { server }) }).policy(DOMAIN)).rejects.toBeInstanceOf(NotSignetDomainError);
    }
  });

  it('refuses a server outside the domain unless the DNS pins the key and the domain key signed the URLs', async () => {
    const hosted = { server: 'https://tenant.hosting.example' };
    const signed = base(key.publicKey, { ...hosted, serverSig: signServerUrls(key, { domain: DOMAIN, ...hosted }) });
    await expect(resolver({ [URL_OF]: base(key.publicKey, hosted) }).policy(DOMAIN)).rejects.toBeInstanceOf(NotSignetDomainError);
    await expect(resolver({ [URL_OF]: signed }).policy(DOMAIN)).rejects.toBeInstanceOf(NotSignetDomainError);
    await expect(resolver({ [URL_OF]: { ...signed, serverSig: signServerUrls(generateSigningKey(), { domain: DOMAIN, ...hosted }) } }, key.publicKey).policy(DOMAIN)).rejects.toBeInstanceOf(NotSignetDomainError);
    expect((await resolver({ [URL_OF]: signed }, key.publicKey).policy(DOMAIN)).server).toBe(hosted.server);
  });

  it('covers the replicas too', async () => {
    const replicas = [`https://a.${DOMAIN}`, 'https://b.hosting.example'];
    const signed = base(key.publicKey, { server: replicas[0], replicas, serverSig: signServerUrls(key, { domain: DOMAIN, server: replicas[0], replicas }) });
    expect((await resolver({ [URL_OF]: signed }, key.publicKey).policy(DOMAIN)).replicas).toEqual(replicas);
    await expect(resolver({ [URL_OF]: { ...signed, replicas: [replicas[0], 'https://c.hosting.example'] } }, key.publicKey).policy(DOMAIN)).rejects.toBeInstanceOf(NotSignetDomainError);
  });
});
