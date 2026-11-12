import { createPublicKey } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { LogLeaf } from '@signet/lib';
import { Identity, StaticResolver, b64u, clientAuthHeaders, exportIssuerKey, generateIssuerKey, generateSigningKey, importIssuerKey } from '@signet/lib';
import { TransparencyLogServer } from '../log-server';
import { Testbed } from '../testbed';

describe('surviving a restart', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'signet-data-'));
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('keeps accounts, mail, keys and the replay cache across a home server restart', async () => {
    const bed = await Testbed.start(['alpha.test', 'beta.test'], { dataDirs: { 'beta.test': dir }, openEnrollment: true });
    try {
      const alice = Identity.create('alice@alpha.test');
      const bob = Identity.create('bob@beta.test');
      const alicePhone = bed.client(alice.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] }));
      const bobKeys = bob.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] });
      const bobPhone = bed.client(bobKeys);
      await bed.publish(alice);
      await bed.publish(bob);
      await alicePhone.ready();
      await bobPhone.ready();
      await alicePhone.sendRequest('bob@beta.test', { subject: 'Before the restart' });
      const path = '/v0/mailbox?after=0';
      const captured = clientAuthHeaders('bob@beta.test', bobKeys.cert.clientId, bobKeys.signing, 'GET', path, '');
      expect((await fetch(`${bed.url('beta.test')}${path}`, { headers: captured })).status).toBe(200);

      await bed.restart('beta.test');

      // The request is still in Bob's mailbox, Bob is still enrolled, and Alice still verifies him.
      const [incoming] = await bobPhone.sync();
      if (incoming?.kind !== 'request') throw new Error('expected the request to survive');
      expect(incoming.request.body.subject).toBe('Before the restart');
      expect((await alicePhone.lookup('bob@beta.test'))?.identityKey).toBe(bob.identityKey);
      const thread = await bobPhone.accept(incoming.request);
      expect((await alicePhone.sync()).map((event) => event.kind)).toEqual(['joined']);
      expect(thread).toMatch(/^t_/);
      // A request captured before the restart still can't be replayed after it.
      expect((await fetch(`${bed.url('beta.test')}${path}`, { headers: captured })).status).toBe(401);
    } finally {
      await bed.close();
    }
  });

  it('retries a queued delivery after the sending server restarts', async () => {
    const bed = await Testbed.start(['alpha.test', 'beta.test'], { dataDirs: { 'alpha.test': dir }, retryDelaysMs: [200, 200, 200] });
    try {
      const alice = Identity.create('alice@alpha.test');
      const bob = Identity.create('bob@beta.test');
      const alicePhone = bed.client(alice.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] }));
      const bobPhone = bed.client(bob.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] }));
      await bed.publish(alice);
      await bed.publish(bob);
      await alicePhone.ready();
      await bobPhone.ready();

      bed.breakDelivery('beta.test');
      await alicePhone.sendRequest('bob@beta.test', { subject: 'Sent while beta was down' });
      expect(bed.server('alpha.test').store.outbound()).toHaveLength(1);
      await bed.restart('alpha.test');
      bed.repairDelivery('beta.test');

      let events: Awaited<ReturnType<typeof bobPhone.sync>> = [];
      for (let tries = 0; tries < 40 && events.length === 0; tries += 1) {
        await new Promise((resolve) => setTimeout(resolve, 100));
        events = await bobPhone.sync();
      }
      expect(events).toMatchObject([{ kind: 'request', request: { body: { subject: 'Sent while beta was down' } } }]);
      expect(bed.server('alpha.test').store.outbound()).toEqual([]);
    } finally {
      await bed.close();
    }
  });

  it('never lets enrollment replace an account that exists', async () => {
    const bed = await Testbed.start(['beta.test'], { openEnrollment: true });
    try {
      const bob = Identity.create('bob@beta.test');
      bob.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*'] });
      await bed.publish(bob);
      const impostor = Identity.create('bob@beta.test');
      impostor.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*'] });

      const response = await fetch(`${bed.url('beta.test')}/v0/enroll`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(impostor.publication()),
      });

      expect(response.status).toBe(409);
      expect(bed.server('beta.test').store.user('bob')?.binding.identityKey).toBe(bob.identityKey);
    } finally {
      await bed.close();
    }
  });

  it('restarts the transparency log from its file with the same tree', () => {
    const key = generateSigningKey();
    const file = join(dir, 'leaves.jsonl');
    const first = new TransparencyLogServer(key, new StaticResolver(new Map()), undefined, file);
    for (let i = 0; i < 5; i += 1) {
      const leaf: LogLeaf = { v: 0, index: `i${i}`, domain: 'beta.test', kind: 'bound', identityKey: 'k', cardHash: `c${i}`, viewHash: null, ts: new Date().toISOString() };
      first.record(leaf);
    }

    const second = new TransparencyLogServer(key, new StaticResolver(new Map()), undefined, file);

    expect(second.log.size).toBe(5);
    expect(second.log.treeHead().root).toBe(first.log.treeHead().root);
    expect(second.log.latest('beta.test', 'i3').leaf?.cardHash).toBe('c3');
  });

  it("keeps the issuer's key, so tokens it signed stay valid", () => {
    const key = generateIssuerKey('issuer.example.org');

    const restored = importIssuerKey(JSON.parse(JSON.stringify(exportIssuerKey(key))));

    expect(restored.publicKey).toBe(key.publicKey);
    expect(b64u(createPublicKey(restored.privateKey).export({ format: 'der', type: 'spki' }))).toBe(key.publicKey);
  });
});
