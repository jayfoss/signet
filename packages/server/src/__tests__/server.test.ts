import type { SignetEvent } from '@signet/lib';
import {
  Identity,
  IdentityChangedError,
  SignetClient,
  TransparencyError,
  MlsSession,
  bindIdentity,
  entryHash,
  generateSigningKey,
  signJson,
  utf8,
} from '@signet/lib';
import { Testbed } from '../testbed';

const kinds = (events: SignetEvent[]) => events.map((event) => event.kind);
const SUBJECT = 'Intro from Sam: Series A docs';

async function world(options: { retryDelaysMs?: number[] } = {}) {
  const bed = await Testbed.start(['alpha.test', 'beta.test', 'gamma.test'], options);
  const alice = Identity.create('alice@alpha.test');
  const alicePhoneKeys = alice.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] });
  const jerzy = Identity.create('jerzy@beta.test');
  const jerzyPhoneKeys = jerzy.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] });
  const clerkKeys = jerzy.enrollClient({ kind: 'agent', label: 'Clerk', scopes: ['read:*', 'send', 'admit', 'intent:schedule.*'] });
  jerzy.setIntake({ clientId: clerkKeys.cert.clientId, intents: ['schedule.*'], exclusive: false });
  const sam = Identity.create('sam@gamma.test');
  const samPhoneKeys = sam.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] });
  for (const identity of [alice, jerzy, sam]) await bed.publish(identity);
  const alicePhone = bed.client(alicePhoneKeys);
  const jerzyPhone = bed.client(jerzyPhoneKeys);
  const clerk = bed.client(clerkKeys);
  for (const client of [alicePhone, jerzyPhone, clerk]) await client.ready();
  return { bed, alice, jerzy, sam, clerkKeys, samPhoneKeys, alicePhone, jerzyPhone, clerk };
}

describe('Signet across three domains', () => {
  let w: Awaited<ReturnType<typeof world>>;

  beforeEach(async () => {
    w = await world();
  });

  afterEach(async () => {
    await w.bed.close();
  });

  it('runs a request, an MLS thread with an attachment, and a revocation end to end', async () => {
    const { bed, jerzy, clerkKeys, alicePhone, jerzyPhone, clerk } = w;

    await alicePhone.sendRequest('jerzy@beta.test', { subject: SUBJECT, intent: { name: 'schedule.propose', args: { durationMin: 30 } } });
    const [incoming] = await clerk.sync();
    if (incoming?.kind !== 'request') throw new Error('expected a request');
    expect(incoming.admission).toEqual({ admit: false, reason: 'unknown sender' });

    const thread = await clerk.accept(incoming.request);
    expect(clerk.members(thread)).toHaveLength(3);
    await clerk.send(thread, {
      subject: SUBJECT,
      text: 'Agenda attached. Tuesday 3pm or Wednesday 10am?',
      intents: [{ name: 'schedule.propose', args: { slots: ['Tue 15:00', 'Wed 10:00'] } }],
      files: [{ name: 'agenda.txt', type: 'text/plain', data: utf8('1. Cap table\n2. Timeline\n') }],
    });

    const aliceEvents = await alicePhone.sync();
    expect(kinds(aliceEvents)).toEqual(['joined', 'message']);
    const proposal = aliceEvents[1];
    if (proposal.kind !== 'message') throw new Error('expected a message');
    expect(proposal.sender.label).toBe('Clerk');
    expect((await alicePhone.fetchAttachment(proposal.message.body.attachments[0])).toString()).toContain('Cap table');

    await alicePhone.send(thread, { subject: SUBJECT, text: 'Tuesday 3pm', intents: [{ name: 'schedule.confirm', args: { slot: 'Tue 15:00' } }] });
    expect(kinds(await jerzyPhone.sync())).toEqual(['request', 'joined', 'message', 'message']);

    jerzy.revoke(clerkKeys.cert.clientId);
    await bed.publish(jerzy);
    const { removed } = await jerzyPhone.rekey(thread);
    expect(removed.map((member) => member.clientId)).toEqual([clerkKeys.cert.clientId]);
    await jerzyPhone.send(thread, { subject: SUBJECT, text: 'Confirmed for Tuesday' });

    await expect(clerk.sync()).rejects.toThrow('401');
    const [latest] = bed.server('beta.test').store.mailbox('jerzy').slice(-1);
    const stale = new MlsSession(clerkKeys, clerk.snapshot().mls);
    expect(() => stale.decrypt(thread, (latest.payload as { mls: string }).mls)).toThrow();

    const after = await alicePhone.sync();
    expect(kinds(after)).toEqual(['rekeyed', 'message']);
    expect(after[1].kind === 'message' && after[1].message.body.text).toBe('Confirmed for Tuesday');
  });

  it('carries on after a client restarts from its snapshot', async () => {
    const { bed, alicePhone, clerk, clerkKeys } = w;
    await alicePhone.sendRequest('jerzy@beta.test', { subject: SUBJECT });
    const [incoming] = await clerk.sync();
    if (incoming?.kind !== 'request') throw new Error('expected a request');
    const thread = await clerk.accept(incoming.request);
    await alicePhone.sync();

    const restarted = bed.client(clerkKeys, JSON.parse(JSON.stringify(clerk.snapshot())));
    await alicePhone.send(thread, { subject: SUBJECT, text: 'Still there?' });
    const events = await restarted.sync();
    expect(events.at(-1)?.kind === 'message' && events.at(-1)).toMatchObject({ message: { body: { text: 'Still there?' } } });
  });

  it('admits a sender introduced by a contact', async () => {
    const { bed, alicePhone, clerk, samPhoneKeys } = w;
    await clerk.addContact('sam@gamma.test');
    const introduction = await bed.client(samPhoneKeys).introduce('alice@alpha.test', 'jerzy@beta.test', 'Series A docs');
    await alicePhone.sendRequest('jerzy@beta.test', { subject: SUBJECT, introduction });

    const [incoming] = await clerk.sync();
    expect(incoming?.kind === 'request' && incoming.admission).toEqual({ admit: true, reason: 'introduced by sam@gamma.test: Series A docs' });
  });

  it('rate-limits signed requests from one sender', async () => {
    const { bed, alicePhone } = w;
    for (let i = 0; i < 5; i += 1) await alicePhone.sendRequest('jerzy@beta.test', { subject: `Try ${i}` }, { anonymous: false });
    await alicePhone.sendRequest('jerzy@beta.test', { subject: 'One too many' }, { anonymous: false });

    expect(bed.server('beta.test').store.mailbox('jerzy').filter((item) => item.kind === 'request')).toHaveLength(5);
  });

  it('rejects a request key the server slipped onto the public card', async () => {
    const { bed, alicePhone } = w;
    const store = bed.server('beta.test').store;
    const user = store.user('jerzy');
    if (!user) throw new Error('jerzy is not enrolled');
    user.card = { ...user.card, card: { ...user.card.card, requestKeys: [...user.card.card.requestKeys, { keyId: 'k', agreeKey: generateSigningKey().publicKey }] } };
    store.putUser('jerzy', user);

    await expect(alicePhone.lookup('jerzy@beta.test')).rejects.toThrow('not signed by its identity key');
  });

  it('rejects a client the server slipped into the owner\'s log', async () => {
    const { bed, jerzy, jerzyPhone } = w;
    const store = bed.server('beta.test').store;
    const user = store.user('jerzy');
    if (!user) throw new Error('jerzy is not enrolled');
    const { cert } = Identity.create('jerzy@beta.test').enrollClient({ kind: 'device', label: 'Ghost', scopes: ['read:*'] });
    const unsigned = { seq: jerzy.entries.length, prev: entryHash(jerzy.entries[jerzy.entries.length - 1]), ts: new Date().toISOString(), body: { type: 'add-client' as const, cert } };
    user.log = [...user.log, { ...unsigned, sig: signJson(generateSigningKey(), unsigned) }];
    store.putUser('jerzy', user);

    await expect(jerzyPhone.lookup('jerzy@beta.test')).rejects.toThrow('not signed by the identity key');
  });

  it('shows strangers the card, contacts the view, and nobody but the owner the labels', async () => {
    const { bed, alicePhone, jerzyPhone, samPhoneKeys } = w;
    const stranger = await bed.client(samPhoneKeys).lookup('jerzy@beta.test');
    expect(stranger?.view).toBeUndefined();
    expect(stranger?.card.requestKeys).toHaveLength(2);
    expect(JSON.stringify(stranger)).not.toMatch(/Phone|Clerk|read:\*/);

    await alicePhone.sendRequest('jerzy@beta.test', { subject: SUBJECT });
    const [incoming] = await jerzyPhone.sync();
    if (incoming?.kind !== 'request') throw new Error('expected a request');
    await jerzyPhone.accept(incoming.request);
    const contact = await alicePhone.lookup('jerzy@beta.test');
    expect(contact?.view?.members.map((m) => m.kind).sort()).toEqual(['agent', 'device']);
    expect(JSON.stringify(contact)).not.toMatch(/Phone|Clerk|read:\*/);
    expect((await jerzyPhone.lookup('jerzy@beta.test'))?.log?.clients.size).toBe(2);
  });

  it('rejects a rebinding the server kept out of the transparency log', async () => {
    const { bed, alicePhone } = w;
    const impostor = Identity.create('jerzy@beta.test');
    const store = bed.server('beta.test').store;
    const forged = impostor.publication();
    store.putUser('jerzy', {
      log: forged.entries,
      card: forged.card,
      view: forged.view,
      binding: bindIdentity(bed.domainKey('beta.test'), 'jerzy@beta.test', impostor.identityKey),
    });

    await expect(alicePhone.lookup('jerzy@beta.test')).rejects.toBeInstanceOf(TransparencyError);
    await expect(bed.client(w.samPhoneKeys).lookup('jerzy@beta.test')).rejects.toBeInstanceOf(TransparencyError);
  });

  it('catches a logged rebinding: pinned senders refuse it and the owner is alerted', async () => {
    const { bed, alicePhone, jerzyPhone } = w;
    await alicePhone.lookup('jerzy@beta.test');
    expect((await jerzyPhone.monitor()).alerts).toEqual([]);

    // Enrollment never replaces an account, so a domain that rebinds has to release the address first: both steps are logged.
    await bed.server('beta.test').unenroll('jerzy');
    await bed.server('beta.test').enroll(Identity.create('jerzy@beta.test').publication());

    await expect(alicePhone.lookup('jerzy@beta.test')).rejects.toBeInstanceOf(IdentityChangedError);
    const report = await jerzyPhone.monitor();
    expect(report.alerts[0]).toBe('your home server no longer accepts this client');
    expect(report.alerts[1]).toBe("jerzy@beta.test is now bound to an identity key you don't hold");
    expect(report.alerts.slice(2)).toEqual([
      expect.stringMatching(/was unbound from its identity key$/),
      expect.stringMatching(/was bound to an identity key you don't hold$/),
    ]);
  });

  it('tells the owner when a new client appears on their account', async () => {
    const { bed, jerzy, jerzyPhone } = w;
    await jerzyPhone.monitor();
    jerzy.enrollClient({ kind: 'tool', label: 'Bookkeeping', scopes: [] });
    await bed.publish(jerzy);

    const report = await jerzyPhone.monitor();
    expect(report.alerts).toEqual([]);
    expect(report.newClients.map((cert) => cert.label)).toEqual(['Bookkeeping']);
  });

  it('refuses a domain whose transparency log the client does not trust', async () => {
    const { bed, alicePhone } = w;
    const untrusting = new SignetClient(alicePhone.keys, bed.resolver, {
      trustedLogs: [{ url: bed.trustedLog.url, key: generateSigningKey().publicKey }],
    });

    await expect(untrusting.lookup('jerzy@beta.test')).rejects.toBeInstanceOf(TransparencyError);
  });

  it('answers a signed not-enrolled for unknown addresses', async () => {
    await expect(w.alicePhone.lookup('nobody@beta.test')).resolves.toBeNull();
  });
});

describe('delivery failures', () => {
  it('retries a domain that is down, then bounces to the sender', async () => {
    const w = await world({ retryDelaysMs: [20, 20] });
    try {
      w.bed.breakDelivery('beta.test');
      await w.alicePhone.sendRequest('jerzy@beta.test', { subject: 'Hello?' });
      await new Promise((resolve) => setTimeout(resolve, 200));

      const [bounce] = await w.alicePhone.sync();
      expect(bounce).toMatchObject({ kind: 'bounce', to: ['jerzy@beta.test'] });
      expect(bounce.kind === 'bounce' && bounce.reason).toContain('gave up after 3 attempts');
    } finally {
      await w.bed.close();
    }
  });

  it('delivers once the domain recovers within the retry window', async () => {
    const w = await world({ retryDelaysMs: [50, 50] });
    try {
      w.bed.breakDelivery('beta.test');
      await w.alicePhone.sendRequest('jerzy@beta.test', { subject: 'Hello?' });
      w.bed.repairDelivery('beta.test');
      await new Promise((resolve) => setTimeout(resolve, 150));

      expect(kinds(await w.clerk.sync())).toEqual(['request']);
      expect(await w.alicePhone.sync()).toEqual([]);
    } finally {
      await w.bed.close();
    }
  });
});
