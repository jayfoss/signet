import { lookalikeOf } from '../admission';
import { generateSigningKey } from '../crypto';
import { attestedSignetHeader, formatSignetHeader, hashBody, parseSignetHeader, verifyAttestation } from '../legacy';
import { DnsResolver, NotSignetDomainError, parseSignetTxt } from '../resolver';

const policyFor = (domain: string) => ({ v: 'signet0', domain, server: `https://signet.${domain}`, mode: 'enforce', maxAge: 60 });

describe('policy discovery', () => {
  it('reads a delegated host from the TXT record, restricted to the domain and its subdomains', () => {
    expect(parseSignetTxt([['v=signet0; host=signet.example.com']], 'example.com')).toEqual({ hosts: ['signet.example.com'] });
    expect(parseSignetTxt([['v=signet0;', ' host=Example.com']], 'example.com')).toEqual({ hosts: ['example.com'] });
    expect(parseSignetTxt([['v=signet0']], 'example.com')).toEqual({ hosts: ['signet.example.com', 'example.com'] });
    expect(parseSignetTxt([['v=signet0; host=evil.net']], 'example.com')).toBeNull();
    expect(parseSignetTxt([['v=signet0; host=notexample.com']], 'example.com')).toBeNull();
    expect(parseSignetTxt([['v=spf1 include:_spf.google.com ~all']], 'example.com')).toBeNull();
  });

  it('fetches the policy from the delegated host, falls back to the apex, and refuses redirects', async () => {
    const fetched: string[] = [];
    const site = (responses: Record<string, Response>) => async (url: string | URL | Request) => {
      fetched.push(String(url));
      return responses[String(url)] ?? new Response('not found', { status: 404 });
    };
    const txt = (record: string) => async () => [[record]];

    const delegated = new DnsResolver(site({ 'https://signet.example.com/.well-known/signet.json': Response.json(policyFor('example.com')) }) as typeof fetch, txt('v=signet0; host=signet.example.com'));
    await expect(delegated.policy('example.com')).resolves.toMatchObject({ domain: 'example.com' });

    fetched.length = 0;
    const apex = new DnsResolver(site({ 'https://example.com/.well-known/signet.json': Response.json(policyFor('example.com')) }) as typeof fetch, txt('v=signet0'));
    await expect(apex.policy('example.com')).resolves.toMatchObject({ domain: 'example.com' });
    expect(fetched).toEqual(['https://signet.example.com/.well-known/signet.json', 'https://example.com/.well-known/signet.json']);

    const redirecting = new DnsResolver(
      site({ 'https://example.com/.well-known/signet.json': new Response(null, { status: 301, headers: { location: 'https://www.example.com/' } }) }) as typeof fetch,
      txt('v=signet0; host=example.com'),
    );
    await expect(redirecting.policy('example.com')).rejects.toBeInstanceOf(NotSignetDomainError);

    const wrongDomain = new DnsResolver(site({ 'https://signet.example.com/.well-known/signet.json': Response.json(policyFor('other.com')) }) as typeof fetch, txt('v=signet0; host=signet.example.com'));
    await expect(wrongDomain.policy('example.com')).rejects.toBeInstanceOf(NotSignetDomainError);
  });
});

describe('Signet header on plain email', () => {
  const domainKey = generateSigningKey();
  const fields = { from: 'alice@alpha.test', to: ['jerzy@beta.test'], subject: 'Docs', bodyHash: hashBody('See attached.\n') };

  it('verifies only for the exact From, To and Subject the domain attested', () => {
    const header = parseSignetHeader(attestedSignetHeader(domainKey, 'https://signet.alpha.test', 'identity-key', fields));
    if (!header) throw new Error('header did not parse');

    expect(verifyAttestation(header, fields, domainKey.publicKey)).toBe(true);
    expect(verifyAttestation(header, { ...fields, subject: 'Urgent: new bank details' }, domainKey.publicKey)).toBe(false);
    expect(verifyAttestation(header, { ...fields, to: ['someone@else.test'] }, domainKey.publicKey)).toBe(false);
    expect(verifyAttestation(header, { ...fields, from: 'mallory@alpha.test' }, domainKey.publicKey)).toBe(false);
    expect(verifyAttestation(header, fields, generateSigningKey().publicKey)).toBe(false);
    expect(verifyAttestation(header, fields, domainKey.publicKey, new Date(Date.now() + 2 * 3_600_000))).toBe(false);
    expect(verifyAttestation(header, fields, domainKey.publicKey, new Date(Date.now() + 30 * 60_000))).toBe(true);
  });

  it('covers the body and the humans-only audience', () => {
    const header = parseSignetHeader(attestedSignetHeader(domainKey, 'https://signet.alpha.test', 'identity-key', { ...fields, audience: 'humans' }));
    if (!header) throw new Error('header did not parse');

    expect(verifyAttestation(header, { ...fields, audience: 'humans' }, domainKey.publicKey)).toBe(true);
    // Another body, or the audience header removed in transit, no longer authenticates.
    expect(verifyAttestation(header, { ...fields, audience: 'humans', bodyHash: hashBody('Send the money.') }, domainKey.publicKey)).toBe(false);
    expect(verifyAttestation(header, fields, domainKey.publicKey)).toBe(false);
    // Line ending and trailing whitespace differences in transit do not change the hash.
    expect(hashBody('See attached.\r\n\r\n')).toEqual(hashBody('See attached.'));
  });

  it('treats a header with only a fingerprint as unauthenticated', () => {
    const header = parseSignetHeader(formatSignetHeader('https://signet.alpha.test', 'identity-key'));
    if (!header) throw new Error('header did not parse');

    expect(verifyAttestation(header, fields, domainKey.publicKey)).toBe(false);
  });

  it('survives header folding', () => {
    const folded = attestedSignetHeader(domainKey, 'https://signet.alpha.test', 'identity-key', fields).replace(/; /g, ';\r\n ');
    const header = parseSignetHeader(folded);

    expect(header && verifyAttestation(header, fields, domainKey.publicKey)).toBe(true);
  });
});

describe('lookalike domains', () => {
  it('flags confusable and one-edit domains, and leaves real and unrelated ones alone', () => {
    const known = ['acme.com', 'alpha.test'];

    expect(lookalikeOf('acrne.com', known)).toBe('acme.com');
    expect(lookalikeOf('acme.c0m', known)).toBe('acme.com');
    expect(lookalikeOf('ac-me.com', known)).toBe('acme.com');
    expect(lookalikeOf('acmee.com', known)).toBe('acme.com');
    expect(lookalikeOf('a1pha.test', known)).toBe('alpha.test');
    expect(lookalikeOf('acme.com', known)).toBeNull();
    expect(lookalikeOf('gmail.com', known)).toBeNull();
  });
});
