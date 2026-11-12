import type { LogLeaf } from '@signet/lib';
import { Identity, clientAuthHeaders, domainAuthHeaders, generateSigningKey, recoveryProof } from '@signet/lib';
import { Testbed } from '../testbed';

async function world() {
  const bed = await Testbed.start(['alpha.test', 'beta.test']);
  const alice = Identity.create('alice@alpha.test');
  const bob = Identity.create('bob@beta.test');
  const aliceKeys = alice.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] });
  const alicePhone = bed.client(aliceKeys);
  const bobPhone = bed.client(bob.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] }));
  await bed.publish(alice);
  await bed.publish(bob);
  await alicePhone.ready();
  await bobPhone.ready();
  return { bed, alice, bob, aliceKeys, alicePhone, bobPhone };
}

describe('hardening', () => {
  let w: Awaited<ReturnType<typeof world>>;

  beforeEach(async () => {
    w = await world();
  });

  afterEach(async () => {
    await w.bed.close();
  });

  it("refuses a captured client request replayed within the clock window", async () => {
    const path = '/v0/mailbox?after=0';
    const headers = clientAuthHeaders('alice@alpha.test', w.aliceKeys.cert.clientId, w.aliceKeys.signing, 'GET', path, '');

    expect((await fetch(`${w.bed.url('alpha.test')}${path}`, { headers })).status).toBe(200);
    const replayed = await fetch(`${w.bed.url('alpha.test')}${path}`, { headers });
    expect(replayed.status).toBe(401);
    expect(await replayed.text()).toContain('already used');
  });

  it("refuses a captured server-to-server request replayed within the window", async () => {
    const path = '/v0/directory/bob?requester=someone';
    const headers = domainAuthHeaders('alpha.test', w.bed.domainKey('alpha.test'), 'GET', path, '');

    expect((await fetch(`${w.bed.url('beta.test')}${path}`, { headers })).status).toBe(200);
    expect((await fetch(`${w.bed.url('beta.test')}${path}`, { headers })).status).toBe(401);
  });

  it("files log leaves by domain, so one domain can't overwrite another's address", async () => {
    const index = (await w.alicePhone.lookup('bob@beta.test'))?.index ?? '';
    const forged: LogLeaf = { v: 0, index, domain: 'alpha.test', kind: 'unbound', identityKey: null, cardHash: null, viewHash: null, ts: new Date().toISOString() };
    const body = JSON.stringify(forged);
    const appended = await fetch(`${w.bed.log.url}/v0/append`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...domainAuthHeaders('alpha.test', w.bed.domainKey('alpha.test'), 'POST', '/v0/append', body) },
      body,
    });
    expect(appended.ok).toBe(true);

    // Bob is still found, and Bob's own monitor sees nothing amiss.
    const fresh = w.bed.client(w.alice.enrollClient({ kind: 'device', label: 'Laptop', scopes: ['read:*'] }));
    await w.bed.publish(w.alice);
    await fresh.ready();
    expect((await fresh.lookup('bob@beta.test'))?.identityKey).toBe(w.bob.identityKey);
    expect((await w.bobPhone.monitor()).alerts).toEqual([]);
  });

  it('limits recovery attempts per address and accepts each proof once', async () => {
    const recovery = w.bob.setRecovery();
    await w.bed.publish(w.bob);
    const attempt = (proof: { ts: string; sig: string }) =>
      fetch(`${w.bed.url('beta.test')}/v0/recovery/bob`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(proof) });

    const proof = recoveryProof('bob@beta.test', recovery);
    expect((await attempt(proof)).status).toBe(200);
    expect((await attempt(proof)).status).toBe(404);

    const stranger = generateSigningKey();
    const statuses = [];
    for (let i = 0; i < 4; i += 1) statuses.push((await attempt(recoveryProof('bob@beta.test', stranger))).status);
    expect(statuses).toEqual([404, 404, 404, 429]);
    // The limit holds for the real key too, until tomorrow.
    expect((await attempt(recoveryProof('bob@beta.test', recovery))).status).toBe(429);
  });
});
