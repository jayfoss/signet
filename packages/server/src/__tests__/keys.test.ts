import type { SignetEvent } from '@signet/lib';
import {
  IdentityChangedError,
  Identity,
  IntentError,
  IntentLimitError,
  checkIntentAuthority,
  cardKeyHistory,
  fetchRecoverableLog,
  findGrant,
  generateSigningKey,
  grantKeys,
  replayLog,
  signJson,
  validateIntent,
} from '@signet/lib';
import { Testbed } from '../testbed';

const keyChanges = (events: SignetEvent[]) => events.filter((event) => event.kind === 'key-changed');

async function world() {
  const bed = await Testbed.start(['alpha.test', 'beta.test']);
  const alice = Identity.create('alice@alpha.test');
  const jerzy = Identity.create('jerzy@beta.test');
  const alicePhoneKeys = alice.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] });
  const alicePhone = bed.client(alicePhoneKeys);
  const jerzyPhone = bed.client(jerzy.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] }));
  await bed.publish(alice);
  await bed.publish(jerzy);
  await alicePhone.ready();
  await jerzyPhone.ready();

  await alicePhone.sendRequest('jerzy@beta.test', { subject: 'Hello' });
  const [incoming] = await jerzyPhone.sync();
  if (incoming?.kind !== 'request') throw new Error('expected a request');
  const thread = await jerzyPhone.accept(incoming.request);
  await alicePhone.sync();
  return { bed, alice, alicePhone, alicePhoneKeys, jerzy, jerzyPhone, thread };
}

describe('identity keys: rotation and recovery', () => {
  let w: Awaited<ReturnType<typeof world>>;

  beforeEach(async () => {
    w = await world();
  });

  afterEach(async () => {
    await w.bed.close();
  });

  it('rotates the identity key without breaking contacts, threads or the owner\'s own monitor', async () => {
    const { bed, alice, alicePhone, jerzyPhone, thread } = w;
    const before = alice.identityKey;

    alice.rotateKey();
    await bed.publish(alice);

    const directory = await jerzyPhone.lookup('alice@alpha.test');
    expect(directory?.identityKey).toBe(alice.identityKey);
    expect(keyChanges(await jerzyPhone.sync())).toEqual([{ kind: 'key-changed', principal: 'alice@alpha.test', how: 'rotated', from: before, to: alice.identityKey }]);

    await alicePhone.send(thread, { subject: 'Still here', text: 'Same thread, new identity key' });
    expect((await jerzyPhone.sync()).map((event) => event.kind)).toEqual(['message']);
    expect((await alicePhone.monitor()).alerts).toEqual([]);
  });

  it('keeps grants signed before a rotation, but not before a recovery', async () => {
    const { alice } = w;
    const agent = alice.enrollClient({ kind: 'agent', label: 'Assistant', scopes: ['send'] });
    const grant = alice.grant({ agent: agent.cert.clientId, counterparty: 'jerzy@beta.test', intents: ['pay.*'] });
    const directoryOf = (identity: Identity) => {
      const { card } = identity.publication();
      return { principal: identity.principal, identityKey: identity.identityKey, card: card.card, viewHash: null, index: '' };
    };

    alice.rotateKey();
    expect(findGrant([grant], directoryOf(alice), agent.cert.clientId, 'jerzy@beta.test', 'pay.request')).toBeDefined();

    const recovery = alice.setRecovery();
    const recovered = Identity.recover({ principal: alice.principal, entries: alice.entries }, recovery);
    expect(grantKeys(cardKeyHistory(directoryOf(recovered).card))).toEqual([recovered.identityKey]);
    expect(findGrant([grant], directoryOf(recovered), agent.cert.clientId, 'jerzy@beta.test', 'pay.request')).toBeUndefined();
  });

  it('recovers a lost identity key with the recovery key, and tells contacts it was recovered', async () => {
    const { bed, alice, alicePhone, jerzyPhone, thread } = w;
    const recovery = alice.setRecovery();
    await bed.publish(alice);
    await jerzyPhone.lookup('alice@alpha.test');
    const pinned = alice.identityKey;

    // Every device that held the identity key is gone: only the recovery key is left.
    const entries = await fetchRecoverableLog(bed.url('alpha.test'), 'alice@alpha.test', recovery);
    const recovered = Identity.recover({ principal: 'alice@alpha.test', entries }, recovery);
    await bed.publish(recovered);

    await jerzyPhone.lookup('alice@alpha.test');
    expect(keyChanges(await jerzyPhone.sync())).toEqual([{ kind: 'key-changed', principal: 'alice@alpha.test', how: 'recovered', from: pinned, to: recovered.identityKey }]);
    await alicePhone.send(thread, { subject: 'Back', text: 'Recovered' });
    expect((await jerzyPhone.sync()).map((event) => event.kind)).toEqual(['message']);

    // The recovery key is used up.
    expect(() => Identity.recover({ principal: 'alice@alpha.test', entries: recovered.entries }, recovery)).toThrow('not the recovery key');
    await expect(fetchRecoverableLog(bed.url('alpha.test'), 'alice@alpha.test', recovery)).rejects.toThrow('404');
  });

  it("refuses the log to anyone without the recovery key, and a recovery signed by another key", async () => {
    const { bed, alice } = w;
    alice.setRecovery();
    await bed.publish(alice);
    const stranger = generateSigningKey();

    await expect(fetchRecoverableLog(bed.url('alpha.test'), 'alice@alpha.test', stranger)).rejects.toThrow('404');
    expect(() => Identity.recover({ principal: 'alice@alpha.test', entries: alice.entries }, stranger)).toThrow('not the recovery key');
  });

  it('rejects a rotation the old key did not sign', () => {
    const { alice } = w;
    const thief = generateSigningKey();
    const forged = Identity.restore(JSON.parse(JSON.stringify(alice.export())));
    const link = { type: 'rotate' as const, principal: alice.principal, from: alice.identityKey, to: thief.publicKey, ts: new Date().toISOString() };
    forged.append({ type: 'key-change', change: { link, sig: signJson(thief, link) } });

    expect(() => replayLog(forged.entries)).toThrow('rotation is not signed by the old key');
  });

  it('still treats a domain rebinding to an unrelated key as an identity change', async () => {
    const { bed, jerzyPhone } = w;
    await jerzyPhone.lookup('alice@alpha.test');

    await bed.server('alpha.test').unenroll('alice');
    await bed.publish(Identity.create('alice@alpha.test'));

    await expect(jerzyPhone.lookup('alice@alpha.test')).rejects.toBeInstanceOf(IdentityChangedError);
  });
});

describe('pay intents', () => {
  it('carry an ask and a receipt, never a payment', () => {
    expect(() => validateIntent({ name: 'pay.request', args: { amountUsd: 1200, description: 'Invoice 42', due: '2026-12-01', link: 'https://pay.example.com/i/42' } })).not.toThrow();
    expect(() => validateIntent({ name: 'pay.sent', args: { amountUsd: 1200, reference: 'ACH 9921' } })).not.toThrow();
    expect(() => validateIntent({ name: 'pay.request', args: { amountUsd: -5, description: 'Refund?' } })).toThrow(IntentError);
    expect(() => validateIntent({ name: 'pay.sent', args: { amountUsd: 10 } })).toThrow(IntentError);
  });

  it('need the scope but no spending limit, because asking to be paid commits nobody', () => {
    const owner = Identity.create('alice@alpha.test');
    const { cert } = owner.enrollClient({ kind: 'agent', label: 'Assistant', scopes: ['intent:pay.*', 'intent:com.example.quote.*'] });
    const { cert: noScope } = owner.enrollClient({ kind: 'agent', label: 'Other', scopes: [] });

    expect(() => checkIntentAuthority(cert, { name: 'pay.request', args: { amountUsd: 25_000, description: 'Retainer' } })).not.toThrow();
    expect(() => checkIntentAuthority(cert, { name: 'pay.sent', args: { amountUsd: 25_000, reference: 'Wire 77' } })).not.toThrow();
    expect(() => checkIntentAuthority(noScope, { name: 'pay.request', args: { amountUsd: 1, description: 'Coffee' } })).toThrow(IntentError);
    // Accepting a quote does commit money, so it still needs a limit.
    expect(() => checkIntentAuthority(cert, { name: 'com.example.quote.accept', args: { amountUsd: 500 } })).toThrow(IntentLimitError);
  });
});
