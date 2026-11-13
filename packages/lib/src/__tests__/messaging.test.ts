import type { Directory } from '../cards';
import { viewHash, viewMember } from '../cards';
import { open, seal } from '../crypto';
import { utf8 } from '../encoding';
import type { ClientKeys } from '../identity';
import { Identity } from '../identity';
import { IntentError, IntentLimitError } from '../intents';
import { composeMessage, verifyMessage } from '../message';
import type { Addition } from '../mls';
import { MlsError, MlsSession, checkKeyPackage } from '../mls';
import { MAX_REQUEST_BYTES, RequestError, createIntroduction, createRequest, openRequest } from '../request';
import { decideAdmission } from '../admission';

/** What a verified lookup would return for this identity, as a contact (with view) or a stranger. */
function directoryOf(identity: Identity, contact = true): Directory {
  const { card, view } = identity.publication();
  return {
    principal: identity.principal,
    identityKey: identity.identityKey,
    card: card.card,
    view: contact ? view.view : undefined,
    viewHash: viewHash(view),
    index: 'test',
  };
}

function people() {
  const alice = Identity.create('alice@alpha.test');
  const alicePhone = alice.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] });
  const jerzy = Identity.create('jerzy@beta.test');
  const jerzyPhone = jerzy.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] });
  const clerk = jerzy.enrollClient({ kind: 'agent', label: 'Clerk', scopes: ['read:*', 'send', 'admit', 'intent:schedule.*', 'intent:com.example.*'], limits: { commit_usd: 1000 } });
  const lookup = async (address: string) => directoryOf(address === alice.principal ? alice : jerzy, false);
  return { alice, alicePhone, jerzy, jerzyPhone, clerk, lookup };
}

const claim = (session: MlsSession, keys: ClientKeys, lastResort = false): Addition => ({
  cert: keys.cert,
  claimed: { clientId: keys.cert.clientId, kpId: 'kp', keyPackage: session.keyPackage(lastResort) },
});

describe('HPKE', () => {
  it('round-trips and refuses the wrong info string', async () => {
    const { clerk } = people();
    const sealed = await seal(clerk.cert.agreeKey, utf8('hello'), 'one');

    expect((await open(clerk.agreement, sealed, 'one')).toString()).toBe('hello');
    // Every sealed payload is padded to a multiple of 1024 bytes, so its size says little (Section 7.3).
    const sizes = await Promise.all(['a', 'a'.repeat(900), 'a'.repeat(1100)].map(async (text) => Buffer.from((await seal(clerk.cert.agreeKey, utf8(text), 'one')).ct, 'base64url').length));
    expect(sizes[0]).toBe(sizes[1]);
    expect(sizes[2]).toBeGreaterThan(sizes[1]);
    expect(sizes.map((size) => (size - 16) % 1024)).toEqual([0, 0, 0]);
    await expect(open(clerk.agreement, sealed, 'two')).rejects.toThrow();
  });
});

describe('requests', () => {
  it('seals one copy per public request key and verifies the sender against its presented view', async () => {
    const { alice, alicePhone, jerzy, clerk, lookup } = people();
    const request = await createRequest(alicePhone, alice.publication().view, directoryOf(jerzy, false), {
      subject: 'Intro from Sam',
      intent: { name: 'schedule.propose', args: { durationMin: 30 } },
    });

    expect(request.copies).toHaveLength(2);
    const opened = await openRequest(clerk, request, lookup);
    expect(opened.body.intent?.name).toBe('schedule.propose');
  });

  it('seals only to the intake agent when it is exclusive', async () => {
    const { alice, alicePhone, jerzy, jerzyPhone, clerk, lookup } = people();
    jerzy.setIntake({ clientId: clerk.cert.clientId, intents: ['schedule.*'], exclusive: true });
    const request = await createRequest(alicePhone, alice.publication().view, directoryOf(jerzy, false), { subject: 'Hi' });

    expect(request.copies).toHaveLength(1);
    await expect(openRequest(jerzyPhone, request, lookup)).rejects.toThrow('no copy');
    await expect(openRequest(clerk, request, lookup)).resolves.toMatchObject({ body: { subject: 'Hi' } });
  });

  it('refuses requests over the size limit and malformed intents', async () => {
    const { alice, alicePhone, jerzy } = people();
    const view = alice.publication().view;
    const recipient = directoryOf(jerzy, false);

    await expect(createRequest(alicePhone, view, recipient, { subject: 'x'.repeat(MAX_REQUEST_BYTES) })).rejects.toThrow(RequestError);
    await expect(createRequest(alicePhone, view, recipient, { subject: 'Hi', intent: { name: 'schedule.confirm', args: {} } })).rejects.toThrow(IntentError);
    await expect(createRequest(alicePhone, view, recipient, { subject: 'Hi', intent: { name: 'buy', args: {} } })).rejects.toThrow(IntentError);
  });

  it('rejects a request whose presented view is no longer current', async () => {
    const { alice, alicePhone, jerzy, clerk, lookup } = people();
    const staleView = alice.publication().view;
    const request = await createRequest(alicePhone, staleView, directoryOf(jerzy, false), { subject: 'Hi' });
    alice.revoke(alicePhone.cert.clientId);

    await expect(openRequest(clerk, request, lookup)).rejects.toThrow('not current');
  });

  it('admits a stranger introduced by a contact, and queues one introduced by a stranger', async () => {
    const { alice, alicePhone, jerzy, clerk } = people();
    const sam = Identity.create('sam@gamma.test');
    const samPhone = sam.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*'] });
    const lookup = async (address: string) => directoryOf(address === sam.principal ? sam : address === alice.principal ? alice : jerzy, false);
    const introduction = createIntroduction(samPhone, sam.publication().view, 'alice@alpha.test', 'jerzy@beta.test', 'Series A docs');
    const sealed = await createRequest(alicePhone, alice.publication().view, directoryOf(jerzy, false), { subject: 'Intro', introduction });
    const request = await openRequest(clerk, sealed, lookup);

    await expect(decideAdmission({ contacts: ['sam@gamma.test'], trustedDomains: [] }, 'jerzy@beta.test', request, lookup)).resolves.toEqual({
      admit: true,
      reason: 'introduced by sam@gamma.test: Series A docs',
    });
    await expect(decideAdmission({ contacts: [], trustedDomains: [] }, 'jerzy@beta.test', request, lookup)).resolves.toMatchObject({ admit: false });
  });
});

describe('MLS threads (OpenMLS)', () => {
  it('lets every member read, then shuts a removed member out of the next epoch', () => {
    const { alicePhone, jerzyPhone, clerk } = people();
    const alice = new MlsSession(alicePhone);
    const jerzy = new MlsSession(jerzyPhone);
    const agent = new MlsSession(clerk);
    const { thread, welcome } = jerzy.createGroup([claim(alice, alicePhone), claim(agent, clerk)]);
    if (!welcome) throw new Error('expected a welcome');

    expect(alice.peekWelcome(welcome).members.map((m) => m.clientId).sort()).toEqual([alicePhone, jerzyPhone, clerk].map((k) => k.cert.clientId).sort());
    alice.join(welcome);
    agent.join(welcome);
    expect(alice.exportSecret(thread, 'signet delivery v0')).toEqual(jerzy.exportSecret(thread, 'signet delivery v0'));

    const fromClerk = agent.encrypt(thread, utf8('Tuesday 3pm?'));
    const read = alice.decrypt(thread, fromClerk);
    expect(read.plaintext.toString()).toBe('Tuesday 3pm?');
    expect(read.sender).toMatchObject({ clientId: clerk.cert.clientId, signatureKey: clerk.cert.sigKey });

    const clerkLeaf = jerzy.members(thread).find((m) => m.clientId === clerk.cert.clientId)?.leafIndex ?? -1;
    const { commit } = jerzy.commit(thread, [clerkLeaf], []);
    expect(alice.previewCommit(thread, commit)).toMatchObject({ removed: [clerkLeaf], selfRemoved: false, sender: { clientId: jerzyPhone.cert.clientId } });
    expect(alice.epoch(thread)).toBe(1);
    alice.applyCommit(thread, commit);
    expect(alice.epoch(thread)).toBe(2);
    expect(agent.applyCommit(thread, commit).selfRemoved).toBe(true);
    expect(agent.isActive(thread)).toBe(false);

    const secret = jerzy.encrypt(thread, utf8('Confirmed'));
    expect(() => agent.decrypt(thread, secret)).toThrow();
    expect(alice.decrypt(thread, secret).plaintext.toString()).toBe('Confirmed');
  });

  it('keeps state unchanged when a commit is only previewed', () => {
    const { alicePhone, jerzyPhone, clerk } = people();
    const alice = new MlsSession(alicePhone);
    const jerzy = new MlsSession(jerzyPhone);
    const agent = new MlsSession(clerk);
    const { thread, welcome } = jerzy.createGroup([claim(alice, alicePhone)]);
    alice.join(welcome ?? '');
    const { commit, welcome: addClerk } = jerzy.commit(thread, [], [claim(agent, clerk)]);
    const before = alice.state;

    alice.previewCommit(thread, commit);
    expect(alice.state).toBe(before);
    expect(alice.applyCommit(thread, commit).added.map((m) => m.clientId)).toEqual([clerk.cert.clientId]);
    agent.join(addClerk ?? '');
    expect(alice.decrypt(thread, agent.encrypt(thread, utf8('hi'))).plaintext.toString()).toBe('hi');
  });

  it('lets a last-resort key package be used more than once', () => {
    const { alicePhone, jerzyPhone } = people();
    const alice = new MlsSession(alicePhone);
    const jerzy = new MlsSession(jerzyPhone);
    const fallback = claim(alice, alicePhone, true);

    const first = jerzy.createGroup([fallback]);
    const second = jerzy.createGroup([fallback]);
    alice.join(first.welcome ?? '');
    alice.join(second.welcome ?? '');
    expect(alice.decrypt(second.thread, jerzy.encrypt(second.thread, utf8('again'))).plaintext.toString()).toBe('again');
  });

  it("refuses a key package that isn't signed with its certified key", () => {
    const { alicePhone, clerk } = people();
    const alice = new MlsSession(alicePhone);

    expect(() => checkKeyPackage(clerk.cert, { clientId: clerk.cert.clientId, kpId: 'x', keyPackage: alice.keyPackage() })).toThrow(MlsError);
    expect(() => checkKeyPackage(clerk.cert, { clientId: clerk.cert.clientId, kpId: 'x', keyPackage: 'bm90IGEga2V5IHBhY2thZ2U' })).toThrow(MlsError);
  });

  it('survives a restart from its serialized state', () => {
    const { alicePhone, jerzyPhone } = people();
    const alice = new MlsSession(alicePhone);
    const jerzy = new MlsSession(jerzyPhone);
    const { thread, welcome } = jerzy.createGroup([claim(alice, alicePhone)]);
    alice.join(welcome ?? '');

    const restarted = new MlsSession(alicePhone, JSON.parse(JSON.stringify(alice.state)) as string);
    expect(restarted.decrypt(thread, jerzy.encrypt(thread, utf8('still here'))).plaintext.toString()).toBe('still here');
  });
});

describe('agent authority', () => {
  function proposal(clerk: ClientKeys, extra: Partial<Parameters<typeof composeMessage>[2]> = {}) {
    return composeMessage(clerk, 't', { subject: 'Times', text: 'Tuesday?', intents: [{ name: 'schedule.propose', args: { slots: ['Tue 15:00'] } }], ...extra });
  }

  it("stops an agent sending intents its private scopes don't cover", () => {
    const { clerk } = people();

    expect(() => composeMessage(clerk, 't', { subject: 'Docs', text: 'Here', intents: [{ name: 'file.request', args: { description: 'cap table' } }] })).toThrow(
      'not allowed to send file.request',
    );
  });

  it("refuses another person's agent unless it is their intake or holds a grant naming you", () => {
    const { jerzy, clerk } = people();
    const message = proposal(clerk);
    const member = viewMember(directoryOf(jerzy).view, clerk.cert.clientId);
    if (!member) throw new Error('clerk is not in the view');

    expect(() => verifyMessage(message, 't', directoryOf(jerzy), member, 'alice@alpha.test')).toThrow('has no grant');
    expect(() => verifyMessage(message, 't', directoryOf(jerzy), member, 'jerzy@beta.test')).not.toThrow();

    jerzy.setIntake({ clientId: clerk.cert.clientId, intents: ['schedule.*'], exclusive: false });
    expect(() => verifyMessage(message, 't', directoryOf(jerzy), member, 'alice@alpha.test')).not.toThrow();
  });

  it('honours a grant only for its counterparty, its limit, and until it is revoked', () => {
    const { jerzy, clerk } = people();
    const grant = jerzy.grant({ agent: clerk.cert.clientId, counterparty: 'alice@alpha.test', intents: ['schedule.*', 'com.example.payment.send'], limits: { commit_usd: 100 } });
    const member = viewMember(directoryOf(jerzy).view, clerk.cert.clientId);
    if (!member) throw new Error('clerk is not in the view');
    const withGrant = proposal(clerk, { grants: [grant] });

    expect(() => verifyMessage(withGrant, 't', directoryOf(jerzy), member, 'alice@alpha.test')).not.toThrow();
    expect(() => verifyMessage(withGrant, 't', directoryOf(jerzy), member, 'sam@gamma.test')).toThrow('has no grant');
    const payment = composeMessage(clerk, 't', { subject: 'Deposit', text: 'Paying', intents: [{ name: 'com.example.payment.send', args: { amountUsd: 500 } }], grants: [grant] });
    expect(() => verifyMessage(payment, 't', directoryOf(jerzy), member, 'alice@alpha.test')).toThrow(IntentLimitError);

    jerzy.revokeGrant(grant.id);
    expect(() => verifyMessage(withGrant, 't', directoryOf(jerzy), member, 'alice@alpha.test')).toThrow('has no grant');
  });

  it('rejects a grant signed by anyone but the owner', () => {
    const { jerzy, clerk } = people();
    const forged = Identity.create('jerzy@beta.test').grant({ agent: clerk.cert.clientId, counterparty: 'alice@alpha.test', intents: ['schedule.*'] });
    const member = viewMember(directoryOf(jerzy).view, clerk.cert.clientId);
    if (!member) throw new Error('clerk is not in the view');

    expect(() => verifyMessage(proposal(clerk, { grants: [forged] }), 't', directoryOf(jerzy), member, 'alice@alpha.test')).toThrow('has no grant');
  });

  it('rejects a message whose sender is not the client it claims', () => {
    const { jerzy, jerzyPhone, clerk } = people();
    const message = proposal(clerk);
    const phone = viewMember(directoryOf(jerzy).view, jerzyPhone.cert.clientId);
    if (!phone) throw new Error('phone is not in the view');

    expect(() => verifyMessage(message, 't', directoryOf(jerzy), phone, 'jerzy@beta.test')).toThrow('does not match');
  });
});

describe('padded plaintext (Section 7.3)', () => {
  const { padPlaintext, unpadPlaintext } = jest.requireActual('../crypto') as typeof import('../crypto');

  it('round-trips and refuses a length it cannot hold or padding that is not zero', () => {
    const padded = padPlaintext(Buffer.from('hello'));
    expect(padded.length).toBe(1024);
    expect(unpadPlaintext(padded).toString()).toBe('hello');
    const tooLong = Buffer.from(padded);
    tooLong.writeUInt32BE(5000, 0);
    expect(() => unpadPlaintext(tooLong)).toThrow('larger than itself');
    const dirty = Buffer.from(padded);
    dirty[1000] = 1;
    expect(() => unpadPlaintext(dirty)).toThrow('non-zero padding');
    expect(() => unpadPlaintext(padded.subarray(0, 1000))).toThrow('not padded');
  });
});
