import type { DomainPolicy } from '..';
import {
  NotSignetDomainError,
  StaticResolver,
  checkOperators,
  domainAuthHeaders,
  generateSigningKey,
  generateVrfKey,
  homeAuthHeaders,
  parseSignetTxt,
  proveIndex,
  signNotEnrolled,
  signOperators,
  signReceipt,
  verifyDomainCall,
  verifyReceipt,
  verifyNotEnrolled,
} from '..';

const domain = 'example.net';
const farFuture = '2099-01-01T00:00:00.000Z';

function setup() {
  const domainKey = generateSigningKey();
  const alpha = generateSigningKey();
  const beta = generateSigningKey();
  const homes = [
    { url: 'https://home.alpha.example', key: alpha.publicKey, replicas: ['https://r2.alpha.example'] },
    { url: 'https://home.beta.example', key: beta.publicKey },
  ];
  const operators = signOperators(domainKey, { domain, seq: 1, notAfter: farFuture, homes });
  const policy: DomainPolicy = {
    v: 'signet0',
    domain,
    server: homes[0].url,
    replicas: homes.map((home) => home.url),
    mode: 'enforce',
    maxAge: 3600,
    domainKey: domainKey.publicKey,
    vrfKey: generateVrfKey().public,
    log: { url: 'https://log.example.org', key: 'k' },
    operators,
  };
  return { domainKey, alpha, beta, homes, operators, policy };
}

/** A resolver whose fetch serves whatever policy the test hands it. */
function resolverFor(policy: DomainPolicy, pins: Map<string, string>) {
  const served = { policy };
  const fetchImpl = (async () => new Response(JSON.stringify(served.policy), { status: 200 })) as unknown as typeof fetch;
  return { served, resolver: new StaticResolver(new Map([[domain, 'https://home.alpha.example']]), fetchImpl, pins) };
}

describe('the operators statement', () => {
  it('verifies for its domain and key, and nothing else', () => {
    const { domainKey, operators, homes } = setup();
    expect(checkOperators(operators, domain, domainKey.publicKey)).toEqual(homes);
    expect(() => checkOperators(operators, 'other.net', domainKey.publicKey)).toThrow('not for other.net');
    expect(() => checkOperators(operators, domain, generateSigningKey().publicKey)).toThrow('not signed by the domain key');
    expect(() => checkOperators(operators, domain, domainKey.publicKey, new Date('2100-01-01'))).toThrow('expired');
    const tampered = { ...operators, body: { ...operators.body, homes: [...operators.body.homes, { url: 'https://evil.example', key: 'x' }] } };
    expect(() => checkOperators(tampered, domain, domainKey.publicKey)).toThrow('not signed by the domain key');
  });

  it('allows at most seven homes', () => {
    const { domainKey } = setup();
    const many = Array.from({ length: 8 }, (_, i) => ({ url: `https://h${i}.example`, key: `k${i}` }));
    const statement = signOperators(domainKey, { domain, seq: 1, notAfter: farFuture, homes: many });
    expect(() => checkOperators(statement, domain, domainKey.publicKey)).toThrow('one to 7 homes');
  });
});

describe('a resolver holding policies to the DNS pin', () => {
  it('takes homes and server from the signed statement, not from the unsigned fields', async () => {
    const { policy, domainKey } = setup();
    const lying = { ...policy, server: 'https://evil.example', homes: ['https://evil.example'] };
    const { resolver } = resolverFor(lying, new Map([[domain, domainKey.publicKey]]));
    const accepted = await resolver.policy(domain);
    expect(accepted.replicas).toEqual(['https://home.alpha.example', 'https://home.beta.example']);
    expect(accepted.server).toBe('https://home.alpha.example');
  });

  it('refuses a policy whose domain key is not the pinned one, even with a statement signed by that key', async () => {
    const { policy } = setup();
    const attacker = generateSigningKey();
    const forged = { ...policy, domainKey: attacker.publicKey, operators: signOperators(attacker, { domain, seq: 9, notAfter: farFuture, homes: [{ url: 'https://evil.example', key: attacker.publicKey }] }) };
    const { resolver } = resolverFor(forged, new Map([[domain, policy.domainKey]]));
    await expect(resolver.policy(domain)).rejects.toBeInstanceOf(NotSignetDomainError);
  });

  it('refuses operators when DNS pins no key', async () => {
    const { policy } = setup();
    const { resolver } = resolverFor(policy, new Map());
    await expect(resolver.policy(domain)).rejects.toBeInstanceOf(NotSignetDomainError);
  });

  it('refuses a lower sequence number than one it has seen', async () => {
    const { policy, domainKey, homes } = setup();
    const newer = { ...policy, operators: signOperators(domainKey, { domain, seq: 5, notAfter: farFuture, homes }) };
    const { resolver, served } = resolverFor(newer, new Map([[domain, domainKey.publicKey]]));
    await resolver.policy(domain);
    served.policy = { ...policy, operators: signOperators(domainKey, { domain, seq: 4, notAfter: farFuture, homes: homes.slice(0, 1) }) };
    // The refresh fails, so the cached newer policy is kept (Section 6.5).
    expect((await resolver.policy(domain)).replicas).toHaveLength(2);
  });

  it('keeps a pin case-sensitive when reading the DNS record', () => {
    expect(parseSignetTxt([['v=signet0; host=a.example.net; dk=AbC_dEf-123']], domain)).toEqual({ hosts: ['a.example.net'], dk: 'AbC_dEf-123' });
  });
});

describe('calls signed by a home', () => {
  const call = (headers: Record<string, string>) => ({ sig: headers['signet-sig'], ts: headers['signet-ts'], nonce: headers['signet-nonce'], home: headers['signet-home'] });

  it('verify under the home key when the statement lists it, and under the domain key otherwise', () => {
    const { policy, alpha, domainKey } = setup();
    const home = homeAuthHeaders(domain, alpha, 'POST', '/v0/deliver', '{}');
    expect(verifyDomainCall(policy, call(home), 'POST', '/v0/deliver', '{}')).toBe(true);
    const owner = domainAuthHeaders(domain, domainKey, 'POST', '/v0/deliver', '{}');
    expect(verifyDomainCall(policy, call(owner), 'POST', '/v0/deliver', '{}')).toBe(true);
  });

  it('are refused from an unlisted key, for another path or body, or without operators', () => {
    const { policy, alpha } = setup();
    const stranger = homeAuthHeaders(domain, generateSigningKey(), 'POST', '/v0/deliver', '{}');
    expect(verifyDomainCall(policy, call(stranger), 'POST', '/v0/deliver', '{}')).toBe(false);
    const home = homeAuthHeaders(domain, alpha, 'POST', '/v0/deliver', '{}');
    expect(verifyDomainCall(policy, call(home), 'POST', '/v0/other', '{}')).toBe(false);
    expect(verifyDomainCall(policy, call(home), 'POST', '/v0/deliver', '{"x":1}')).toBe(false);
    expect(verifyDomainCall({ ...policy, operators: undefined }, call(home), 'POST', '/v0/deliver', '{}')).toBe(false);
    // A home can't pass itself off as the domain by leaving the header out.
    const { 'signet-home': _omitted, ...bare } = home;
    expect(verifyDomainCall(policy, call(bare), 'POST', '/v0/deliver', '{}')).toBe(false);
  });
});

describe('directory answers signed by a home', () => {
  it('verify under a listed home key, and not under an unlisted one', () => {
    const { policy, alpha } = setup();
    const vrfKey = generateVrfKey();
    const answerPolicy = { ...policy, vrfKey: vrfKey.public };
    const vrf = proveIndex(vrfKey, 'ghost@example.net');
    const entry = signNotEnrolled(alpha, 'ghost@example.net', vrf, new Date(), true);
    expect(entry.home).toBe(alpha.publicKey);
    expect(verifyNotEnrolled(entry, answerPolicy)).toBe(vrf.index);
    const forged = signNotEnrolled(generateSigningKey(), 'ghost@example.net', vrf, new Date(), true);
    expect(() => verifyNotEnrolled(forged, answerPolicy)).toThrow('unsigned not-enrolled');
  });
});

describe('delivery receipts', () => {
  const fields = { id: 'i_abcdef01', domain, to: ['bob@example.net'], held: [] as string[] };

  it('verify when the domain or one of its listed homes signed them for that delivery', () => {
    const { policy, alpha, domainKey } = setup();
    expect(verifyReceipt(signReceipt(alpha, fields, new Date(), true), policy, fields.id)).toBe(true);
    expect(verifyReceipt(signReceipt(domainKey, fields), policy, fields.id)).toBe(true);
  });

  it('are refused for another delivery or domain, from an unlisted key, or with the signer changed', () => {
    const { policy, alpha } = setup();
    const receipt = signReceipt(alpha, fields, new Date(), true);
    expect(verifyReceipt(receipt, policy, 'i_other0001')).toBe(false);
    expect(verifyReceipt(receipt, { ...policy, domain: 'other.net' }, fields.id)).toBe(false);
    expect(verifyReceipt(signReceipt(generateSigningKey(), fields, new Date(), true), policy, fields.id)).toBe(false);
    // Claiming to be the domain with a key that isn't its own.
    expect(verifyReceipt(signReceipt(generateSigningKey(), fields), policy, fields.id)).toBe(false);
    expect(verifyReceipt({ ...receipt, body: { ...receipt.body, to: ['mallory@example.net'] } }, policy, fields.id)).toBe(false);
  });
});
