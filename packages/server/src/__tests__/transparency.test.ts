import { Identity, TransparencyError, domainKeyIndex, generateSigningKey, serverUrlProblem, signRotation, signTreeHead } from '@signet/lib';
import { LogWitnessServer } from '../log-witness';
import { Testbed } from '../testbed';

async function world(witnesses = 0) {
  const bed = await Testbed.start(['alpha.test', 'beta.test'], { witnesses });
  const alice = Identity.create('alice@alpha.test');
  const bob = Identity.create('bob@beta.test');
  const device = (identity: Identity) => identity.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] });
  const aliceKeys = device(alice);
  const bobKeys = device(bob);
  await bed.publish(alice);
  await bed.publish(bob);
  return { bed, aliceKeys, bobKeys };
}

describe('the domain key in the transparency log (Sections 5.3.1 and 6.5)', () => {
  it('records each domain key before the domain logs anything else', async () => {
    const { bed } = await world();
    try {
      const { leaf } = bed.log.log.latest('beta.test', domainKeyIndex('beta.test'));
      expect(leaf).toMatchObject({ kind: 'domain-key', domain: 'beta.test', domainKey: bed.domainKey('beta.test').publicKey });
      // The test servers listen on localhost, outside their domain, so their policy carries the signed server URLs (Section 6.4).
      const policy = bed.server('beta.test').policy;
      expect(serverUrlProblem(policy, policy.domainKey, false)).toBeNull();
      expect(serverUrlProblem({ ...policy, server: 'http://elsewhere.example' }, policy.domainKey, false)).toContain('serverSig');
    } finally {
      await bed.close();
    }
  });

  it('makes a first-time client refuse a policy whose domain key the log does not record', async () => {
    const { bed, aliceKeys } = await world();
    try {
      const real = bed.resolver.policy.bind(bed.resolver);
      jest.spyOn(bed.resolver, 'policy').mockImplementation(async (domain) => {
        const policy = await real(domain);
        return domain === 'beta.test' ? { ...policy, domainKey: generateSigningKey().publicKey } : policy;
      });
      const stranger = bed.client(aliceKeys);
      await stranger.ready().catch(() => undefined);
      await expect(stranger.lookup('bob@beta.test')).rejects.toThrow('not the one its transparency log records');
    } finally {
      jest.restoreAllMocks();
      await bed.close();
    }
  });

  it('refuses a logged key change without the old key’s proof, and takes one with it', async () => {
    const { bed } = await world();
    try {
      const old = bed.domainKey('beta.test');
      const next = generateSigningKey();
      const leaf = (rotation?: { from: string; sig: string }) => ({ v: 0, index: domainKeyIndex('beta.test'), domain: 'beta.test', kind: 'domain-key', identityKey: null, cardHash: null, viewHash: null, domainKey: next.publicKey, ...(rotation ? { rotation } : {}), ts: new Date().toISOString() });
      const check = (candidate: ReturnType<typeof leaf>) => (bed.log as unknown as { checkDomainKeyLeaf: (leaf: unknown, domain: string) => void }).checkDomainKeyLeaf(candidate, 'beta.test');
      expect(() => check(leaf())).toThrow('without a proof');
      expect(() => check(leaf(signRotation(generateSigningKey(), 'beta.test', next.publicKey)))).toThrow('without a proof');
      expect(() => check(leaf(signRotation(old, 'beta.test', next.publicKey)))).not.toThrow();
    } finally {
      await bed.close();
    }
  });
});

describe('witnessed tree heads (Sections 5.5.1 and 5.5.2)', () => {
  it('serves heads cosigned by every witness, which a client holding them as trusted accepts', async () => {
    const { bed, aliceKeys } = await world(2);
    try {
      const keys = bed.witnesses.map((witness) => witness.publicKey);
      const head = (await (await fetch(`${bed.log.url}/v0/tree-head`)).json()) as { cosigs?: unknown[] };
      expect(head.cosigs).toHaveLength(2);
      const client = bed.client(aliceKeys, undefined, { witnesses: { keys, threshold: 2 } });
      await client.ready();
      expect(await client.lookup('bob@beta.test')).not.toBeNull();
    } finally {
      await bed.close();
    }
  });

  it('refuses a head with too few cosignatures from trusted witnesses', async () => {
    const { bed, aliceKeys } = await world(1);
    try {
      const keys = [bed.witnesses[0].publicKey, generateSigningKey().publicKey];
      const client = bed.client(aliceKeys, undefined, { witnesses: { keys, threshold: 2 } });
      await client.ready().catch(() => undefined);
      await expect(client.lookup('bob@beta.test')).rejects.toThrow(TransparencyError);
    } finally {
      await bed.close();
    }
  });

  it('has a witness refuse to cosign a head that forks or shrinks the log it saw', async () => {
    const { bed } = await world();
    try {
      const logKey = generateSigningKey();
      const witness = new LogWitnessServer(generateSigningKey(), { url: bed.log.url, key: logKey.publicKey });
      await witness.listen();
      const post = (head: unknown) => fetch(`${witness.url}/v0/cosign`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ head }) });
      const root = (byte: number) => Buffer.alloc(32, byte);
      expect((await post(signTreeHead(logKey, 1, root(1)))).status).toBe(200);
      // The same size with another root, though the log signed it, cannot be cosigned; nor can a smaller tree.
      expect((await post(signTreeHead(logKey, 1, root(2)))).status).toBe(409);
      expect((await post(signTreeHead(logKey, 0, root(3)))).status).toBe(409);
      // A head the log did not sign is refused outright.
      expect((await post(signTreeHead(generateSigningKey(), 2, root(4)))).status).toBe(400);
      await witness.close();
    } finally {
      await bed.close();
    }
  });

  it('refuses a tree head older than the client allows', async () => {
    const { bed, aliceKeys } = await world();
    try {
      const client = bed.client(aliceKeys, undefined, { maxHeadAgeMs: -1 });
      await client.ready().catch(() => undefined);
      await expect(client.lookup('bob@beta.test')).rejects.toThrow('too old');
    } finally {
      await bed.close();
    }
  });
});
