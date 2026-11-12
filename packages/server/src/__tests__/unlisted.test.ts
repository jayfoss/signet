import { Identity, UnlistedAddressError } from '@signet/lib';
import { Testbed } from '../testbed';

async function world() {
  // beta.test runs an intake; alpha.test doesn't.
  const bed = await Testbed.start(['alpha.test', 'beta.test'], { intake: ['beta.test'] });
  const alice = Identity.create('alice@alpha.test');
  const jerzy = Identity.create('jerzy@beta.test');
  const alicePhone = bed.client(alice.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] }));
  const jerzyPhone = bed.client(jerzy.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] }));
  const assistant = bed.client(jerzy.enrollClient({ kind: 'agent', label: 'Assistant', scopes: ['read:*', 'send', 'admit'] }));
  jerzy.setUnlisted(true);
  await bed.publish(alice);
  await bed.publish(jerzy);
  for (const client of [alicePhone, jerzyPhone, assistant]) await client.ready();
  return { bed, alice, jerzy, alicePhone, jerzyPhone, assistant };
}

/** What a stranger's server sees for an address, minus the fields that differ on every answer. */
async function strangerSees(bed: Testbed, local: string) {
  const response = await fetch(`${bed.url('beta.test')}/v0/directory/${local}`);
  const { principal, ts, sig, ...rest } = (await response.json()) as Record<string, unknown>;
  return { status: response.status, principal, fields: Object.keys({ principal, ts, sig, ...rest }).sort(), rest };
}

describe('unlisted addresses (opt-in)', () => {
  let w: Awaited<ReturnType<typeof world>>;

  beforeEach(async () => {
    w = await world();
  });

  afterEach(async () => {
    await w.bed.close();
  });

  it('gives strangers the same answer for an unlisted address and one that does not exist', async () => {
    const real = await strangerSees(w.bed, 'jerzy');
    const missing = await strangerSees(w.bed, 'nobody');

    expect(real).toEqual({ ...missing, principal: 'jerzy@beta.test' });
    expect(real.rest).toEqual({ status: 'unlisted' });
    await expect(w.alicePhone.lookup('jerzy@beta.test')).rejects.toBeInstanceOf(UnlistedAddressError);
    await expect(w.alicePhone.lookup('nobody@beta.test')).rejects.toBeInstanceOf(UnlistedAddressError);
  });

  it('delivers a request through the intake, then the thread runs end to end with a verified key', async () => {
    const { alicePhone, jerzyPhone } = w;
    await alicePhone.sendRequest('jerzy@beta.test', { subject: 'Intro from Pat', note: 'Pat said you could help' });

    const [incoming] = await jerzyPhone.sync();
    expect(incoming).toMatchObject({ kind: 'request', request: { body: { from: 'alice@alpha.test', note: 'Pat said you could help' } } });
    if (incoming?.kind !== 'request') throw new Error('expected a request');
    const thread = await jerzyPhone.accept(incoming.request);

    // Accepting released Jerzy's view to Alice, so she now verifies him against the log like anyone listed.
    expect((await alicePhone.sync()).map((event) => event.kind)).toEqual(['joined']);
    expect((await alicePhone.lookup('jerzy@beta.test'))?.identityKey).toBe(w.jerzy.identityKey);
    await alicePhone.send(thread, { subject: 'Thanks', text: 'End to end from here' });
    expect((await jerzyPhone.sync()).map((event) => event.kind === 'message' && event.message.body.text)).toContain('End to end from here');
  });

  it('drops a request to an address that does not exist, with the same answer to the sender', async () => {
    const { alicePhone } = w;

    await expect(alicePhone.sendRequest('nobody@beta.test', { subject: 'Hello?' })).resolves.toMatchObject({ to: 'nobody@beta.test' });
    await expect(alicePhone.sendRequest('jerzy@beta.test', { subject: 'Hello?' })).resolves.toMatchObject({ to: 'jerzy@beta.test' });
    // Signed in the clear rather than anonymously: still no difference.
    await expect(alicePhone.sendRequest('nobody@beta.test', { subject: 'Hello?' }, { anonymous: false })).resolves.toMatchObject({ from: 'alice@alpha.test' });
    expect((await w.jerzyPhone.sync()).map((event) => event.kind)).toEqual(['request']);
  });

  it("keeps a humans-only request through the intake to the owner's devices", async () => {
    const { alicePhone, jerzyPhone, assistant } = w;
    await alicePhone.sendRequest('jerzy@beta.test', { subject: 'Your code', note: '482 913' }, { humansOnly: true });

    expect(await assistant.sync()).toEqual([]);
    expect(await jerzyPhone.sync()).toMatchObject([{ kind: 'request', request: { body: { audience: 'humans' } } }]);
  });

  it('sends mail to an unlisted address over Signet, not plain email', async () => {
    await expect(w.alicePhone.mail('jerzy@beta.test', { subject: 'Hi', text: 'Through the intake' })).resolves.toEqual({ via: 'signet' });
    expect(w.bed.sent).toEqual([]);
    expect(await w.jerzyPhone.sync()).toMatchObject([{ kind: 'request', request: { body: { note: 'Through the intake' } } }]);
  });

  it("refuses to unlist an address on a domain that has no intake", async () => {
    w.alice.setUnlisted(true);

    await expect(w.bed.publish(w.alice)).rejects.toThrow('has no intake');
  });

  it('lets a colleague on the same domain see an unlisted address as usual', async () => {
    const bob = Identity.create('bob@beta.test');
    const bobPhone = w.bed.client(bob.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] }));
    await w.bed.publish(bob);
    await bobPhone.ready();

    expect((await bobPhone.lookup('jerzy@beta.test'))?.identityKey).toBe(w.jerzy.identityKey);
  });
});
