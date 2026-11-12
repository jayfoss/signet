import type { SignetEvent } from '@signet/lib';
import { Identity, MlsSession } from '@signet/lib';
import { Testbed } from '../testbed';

const kinds = (events: SignetEvent[]) => events.map((event) => event.kind);

async function world() {
  const bed = await Testbed.start(['alpha.test', 'beta.test']);
  const alice = Identity.create('alice@alpha.test');
  const jerzy = Identity.create('jerzy@beta.test');
  const alicePhone = bed.client(alice.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] }));
  const jerzyPhone = bed.client(jerzy.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] }));
  const clerkKeys = jerzy.enrollClient({ kind: 'agent', label: 'Clerk', scopes: ['read:*', 'send', 'admit', 'intent:schedule.*'] });
  const clerk = bed.client(clerkKeys);
  jerzy.setIntake({ clientId: clerkKeys.cert.clientId, intents: ['schedule.*'], exclusive: true });
  await bed.publish(alice);
  await bed.publish(jerzy);
  for (const client of [alicePhone, jerzyPhone, clerk]) await client.ready();
  const optClerkIn = async () => {
    jerzy.setAudiencePolicy([clerkKeys.cert.clientId]);
    await bed.publish(jerzy);
  };
  return { bed, alicePhone, jerzyPhone, clerk, clerkKeys, aliceKeys: alicePhone.keys, optClerkIn, jerzyIdentity: jerzy };
}

describe('humans-only: the sender asks, the recipient decides', () => {
  let w: Awaited<ReturnType<typeof world>>;

  beforeEach(async () => {
    w = await world();
  });

  afterEach(async () => {
    await w.bed.close();
  });

  it("keeps a humans-only request away from the recipient's agents by default, even an exclusive intake", async () => {
    const { alicePhone, jerzyPhone, clerk } = w;
    await alicePhone.sendRequest('jerzy@beta.test', { subject: 'Your sign-in code', note: '482 913' }, { humansOnly: true });

    expect(await clerk.sync()).toEqual([]);
    const [incoming] = await jerzyPhone.sync();
    expect(incoming).toMatchObject({ kind: 'request', request: { body: { audience: 'humans', note: '482 913' } } });
  });

  it('lets the recipient opt their agent in, so an over-cautious sender cannot keep it out', async () => {
    const { alicePhone, clerk, optClerkIn } = w;
    await optClerkIn();

    await alicePhone.sendRequest('jerzy@beta.test', { subject: 'Engagement letter' }, { humansOnly: true });

    expect(kinds(await clerk.sync())).toEqual(['request']);
  });

  it('moves a humans-only message to a sibling thread without agents, still inside MLS', async () => {
    const { alicePhone, jerzyPhone, clerk } = w;
    await alicePhone.sendRequest('jerzy@beta.test', { subject: 'Hello' });
    const [incoming] = await clerk.sync();
    if (incoming?.kind !== 'request') throw new Error('expected a request');
    const thread = await clerk.accept(incoming.request);
    await alicePhone.sync();
    await jerzyPhone.sync();

    const reset = await alicePhone.send(thread, { subject: 'Reset', text: 'Your reset link: https://example.test/r/abc', humansOnly: true });
    await alicePhone.send(thread, { subject: 'Hello', text: 'And an ordinary message' });
    expect(reset.thread).not.toBe(thread);
    expect(alicePhone.humansOnlySibling(thread)).toBe(reset.thread);

    // The sibling's first message waits at the server until the phone joins and registers its token.
    const atPhone = await jerzyPhone.sync();
    expect(atPhone.map((event) => event.kind).sort()).toEqual(['joined', 'message', 'message']);
    const joined = atPhone.find((event) => event.kind === 'joined');
    expect(joined).toMatchObject({ thread: reset.thread, humansOnly: true, linkedTo: thread });
    expect(joined?.kind === 'joined' && joined.members.map((m) => m.principal).sort()).toEqual(['alice@alpha.test', 'jerzy@beta.test']);
    expect(atPhone.find((event) => event.kind === 'message' && event.thread === reset.thread)).toMatchObject({
      message: { body: { audience: 'humans', text: 'Your reset link: https://example.test/r/abc' } },
    });
    expect(jerzyPhone.humansOnlySibling(thread)).toBe(reset.thread);

    const atClerk = await clerk.sync();
    expect(atClerk.map((event) => event.kind === 'message' && event.message.body.text)).toEqual(['And an ordinary message']);

    await alicePhone.send(thread, { subject: 'Reset', text: 'Second code', humansOnly: true });
    expect((await jerzyPhone.sync()).map((event) => event.kind === 'message' && event.thread === reset.thread)).toEqual([true]);
  });

  it('adds an agent to the humans-only thread once its owner opts it in, and only then', async () => {
    const { alicePhone, jerzyPhone, clerk, optClerkIn } = w;
    await alicePhone.sendRequest('jerzy@beta.test', { subject: 'Hello' });
    const [incoming] = await clerk.sync();
    if (incoming?.kind !== 'request') throw new Error('expected a request');
    const thread = await clerk.accept(incoming.request);
    await alicePhone.sync();
    await jerzyPhone.sync();
    const { thread: sibling } = await alicePhone.send(thread, { subject: 'Reset', text: 'One', humansOnly: true });
    await jerzyPhone.sync();
    expect(await alicePhone.rekey(sibling)).toEqual({ removed: [], added: [] });

    await optClerkIn();
    const { added } = await alicePhone.rekey(sibling);
    expect(added.map((joiner) => joiner.principal)).toEqual(['jerzy@beta.test']);
    expect(await clerk.sync()).toMatchObject([{ kind: 'joined', thread: sibling, humansOnly: true, linkedTo: thread }]);
    await alicePhone.send(thread, { subject: 'Reset', text: 'Two', humansOnly: true });
    expect((await clerk.sync()).map((event) => event.kind === 'message' && event.message.body.text)).toEqual(['Two']);
  });

  it("refuses a commit that slips an agent its owner hasn't allowed into a humans-only thread", async () => {
    const { bed, alicePhone, jerzyPhone, clerk, clerkKeys, aliceKeys } = w;
    await alicePhone.sendRequest('jerzy@beta.test', { subject: 'Hello' });
    const [incoming] = await clerk.sync();
    if (incoming?.kind !== 'request') throw new Error('expected a request');
    const thread = await clerk.accept(incoming.request);
    await alicePhone.sync();
    await jerzyPhone.sync();
    const { thread: sibling } = await alicePhone.send(thread, { subject: 'Reset', text: 'One', humansOnly: true });
    await jerzyPhone.sync();

    // A rogue client of Alice's skips the checks and commits Clerk into the humans-only thread.
    const rogue = new MlsSession(aliceKeys, alicePhone.snapshot().mls);
    const claimed = bed.server('beta.test').store.claimKeyPackage(clerkKeys.cert.clientId);
    if (!claimed) throw new Error('no key package');
    const { commit } = rogue.commit(sibling, [], [
      { cert: { principal: 'jerzy@beta.test', clientId: clerkKeys.cert.clientId, sigKey: clerkKeys.cert.sigKey }, claimed: { clientId: clerkKeys.cert.clientId, ...claimed } },
    ]);
    bed.server('beta.test').store.push('jerzy', { id: 'i_rogue', kind: 'commit', from: '', sealed: true, payload: { thread: sibling, mls: commit } });

    const [refused] = await jerzyPhone.sync();
    expect(refused).toMatchObject({ kind: 'error', error: expect.stringContaining('humans-only thread') });
    expect(jerzyPhone.members(sibling).map((m) => m.clientId)).not.toContain(clerkKeys.cert.clientId);
  });

  it('accepts a humans-only request into a humans-only thread', async () => {
    const { alicePhone, jerzyPhone, clerk } = w;
    await alicePhone.sendRequest('jerzy@beta.test', { subject: 'Your code' }, { humansOnly: true });
    const [incoming] = await jerzyPhone.sync();
    if (incoming?.kind !== 'request') throw new Error('expected a request');

    const thread = await jerzyPhone.accept(incoming.request);

    expect(jerzyPhone.isHumansOnly(thread)).toBe(true);
    expect(jerzyPhone.members(thread).map((m) => m.principal).sort()).toEqual(['alice@alpha.test', 'jerzy@beta.test']);
    expect(await clerk.sync()).toEqual([]);
  });

  it("honours Signet-Audience: humans on inbound plain email by the recipient's policy", async () => {
    const { bed, jerzyPhone, clerk, optClerkIn } = w;
    const reset = { from: 'no-reply@bank.test', to: 'jerzy@beta.test', subject: 'Password reset', text: 'Code 1234', headers: { 'Signet-Audience': 'humans' } };

    await bed.sendPlainEmail(reset);
    expect(await clerk.sync()).toEqual([]);
    expect(await jerzyPhone.sync()).toMatchObject([{ kind: 'legacy', mail: { subject: 'Password reset', humansOnly: true } }]);

    await optClerkIn();
    await bed.sendPlainEmail(reset);
    expect(await clerk.sync()).toMatchObject([{ kind: 'legacy', mail: { humansOnly: true } }]);
  });

  it('always gives the escrow client everything, whatever the sender or the owner prefers', async () => {
    const { bed, alicePhone, jerzyPhone, clerk } = w;
    const jerzy = Identity.restore(JSON.parse(JSON.stringify(w.jerzyIdentity.export())));
    const escrowKeys = jerzy.enrollClient({ kind: 'org-escrow', label: 'Firm escrow', scopes: ['read:*'] });
    jerzy.setAudiencePolicy([]);
    await bed.publish(jerzy);
    const escrow = bed.client(escrowKeys);
    await escrow.ready();
    const card = (await alicePhone.lookup('jerzy@beta.test'))?.card;
    expect(card?.humanKeys).toHaveLength(2);

    await alicePhone.sendRequest('jerzy@beta.test', { subject: 'Your sign-in code', note: '482 913' }, { humansOnly: true });
    expect(await escrow.sync()).toMatchObject([{ kind: 'request', request: { body: { audience: 'humans' } } }]);
    expect(await clerk.sync()).toEqual([]);

    const [incoming] = await jerzyPhone.sync();
    if (incoming?.kind !== 'request') throw new Error('expected a request');
    const thread = await jerzyPhone.accept(incoming.request);
    expect(jerzyPhone.isHumansOnly(thread)).toBe(true);
    expect(await escrow.sync()).toMatchObject([{ kind: 'joined', thread, humansOnly: true }]);
    const participants = await alicePhone.sync();
    expect(participants[0].kind === 'joined' && participants[0].participants.find((p) => p.principal === 'jerzy@beta.test')?.clients.map((c) => c.kind).sort()).toEqual(['device', 'escrow']);

    await bed.sendPlainEmail({ from: 'no-reply@bank.test', to: 'jerzy@beta.test', subject: 'Password reset', text: 'Code', headers: { 'Signet-Audience': 'humans' } });
    expect((await escrow.sync()).map((event) => event.kind)).toEqual(['legacy']);
  });
});
