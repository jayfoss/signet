import { generateSigningKey, signJson } from '../crypto';
import { bindIdentity, verifyDirectoryEntry } from '../directory';
import type { DomainPolicy } from '../directory';
import { Identity, LogError, activeClient, activeClients, entryHash, hasScope, replayLog } from '../identity';
import { generateVrfKey, proveIndex, verifyIndex } from '../vrf';

describe('identity log', () => {
  it('replays enrolled clients and the intake agent', () => {
    const identity = Identity.create('jerzy@beta.test');
    const phone = identity.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] });
    const clerk = identity.enrollClient({ kind: 'agent', label: 'Clerk', scopes: ['read:*', 'intent:schedule.*'] });
    identity.setIntake({ clientId: clerk.cert.clientId, intents: ['schedule.*'], exclusive: false });

    const log = replayLog(identity.entries);

    expect(log.identityKey).toBe(identity.identityKey);
    expect(activeClients(log).map((cert) => cert.label)).toEqual(['Phone', 'Clerk']);
    expect(log.intake?.clientId).toBe(clerk.cert.clientId);
    expect(activeClient(log, phone.cert.clientId)).toBeDefined();
  });

  it('drops a revoked client and clears it as intake', () => {
    const identity = Identity.create('jerzy@beta.test');
    const clerk = identity.enrollClient({ kind: 'agent', label: 'Clerk', scopes: ['read:*'] });
    identity.setIntake({ clientId: clerk.cert.clientId, intents: [], exclusive: false });
    identity.revoke(clerk.cert.clientId);

    const log = replayLog(identity.entries);

    expect(activeClient(log, clerk.cert.clientId)).toBeUndefined();
    expect(log.intake).toBeNull();
  });

  it('refuses a device as the intake', () => {
    const identity = Identity.create('jerzy@beta.test');
    const phone = identity.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*'] });
    identity.setIntake({ clientId: phone.cert.clientId, intents: [], exclusive: false });

    expect(() => replayLog(identity.entries)).toThrow('not an active agent');
  });

  it('treats an expired certificate as inactive', () => {
    const identity = Identity.create('jerzy@beta.test');
    const tool = identity.enrollClient({ kind: 'tool', label: 'Books', scopes: ['read:*'], ttlDays: 1 });

    const log = replayLog(identity.entries);

    expect(activeClient(log, tool.cert.clientId, new Date(Date.now() + 2 * 86_400_000))).toBeUndefined();
  });

  it('rejects an entry the identity key did not sign (ghost client)', () => {
    const identity = Identity.create('jerzy@beta.test');
    identity.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*'] });
    const { cert } = Identity.create('jerzy@beta.test').enrollClient({ kind: 'device', label: 'Ghost', scopes: ['read:*'] });
    const unsigned = {
      seq: identity.entries.length,
      prev: entryHash(identity.entries[identity.entries.length - 1]),
      ts: new Date().toISOString(),
      body: { type: 'add-client' as const, cert },
    };
    const forged = { ...unsigned, sig: signJson(generateSigningKey(), unsigned) };

    expect(() => replayLog([...identity.entries, forged])).toThrow(LogError);
  });

  it('rejects a log with an entry removed', () => {
    const identity = Identity.create('jerzy@beta.test');
    const clerk = identity.enrollClient({ kind: 'agent', label: 'Clerk', scopes: ['read:*'] });
    identity.revoke(clerk.cert.clientId);
    identity.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*'] });

    const withoutRevocation = identity.entries.filter((entry) => entry.body.type !== 'revoke-client');

    expect(() => replayLog(withoutRevocation)).toThrow('out of order');
  });

  it('matches scopes with trailing wildcards', () => {
    const identity = Identity.create('jerzy@beta.test');
    const { cert } = identity.enrollClient({ kind: 'agent', label: 'Clerk', scopes: ['read:*', 'intent:schedule.*'] });

    expect(hasScope(cert, 'read:thread:t_1')).toBe(true);
    expect(hasScope(cert, 'intent:schedule.propose')).toBe(true);
    expect(hasScope(cert, 'intent:file.request')).toBe(false);
    expect(hasScope(cert, 'send')).toBe(false);
  });
});

describe('public card and contact view', () => {
  it('show strangers only unlabeled request keys and the intake, and contacts no labels or scopes', () => {
    const identity = Identity.create('jerzy@beta.test');
    identity.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] });
    identity.enrollClient({ kind: 'device', label: 'Laptop', scopes: ['read:*', 'send'] });
    const clerk = identity.enrollClient({ kind: 'agent', label: 'Clerk', scopes: ['read:*', 'send', 'admit', 'intent:schedule.*'] });
    identity.setIntake({ clientId: clerk.cert.clientId, intents: ['schedule.*'], exclusive: false });

    const { card, view } = identity.publication();
    const shown = JSON.stringify([card, view]);

    expect(card.card.requestKeys).toHaveLength(2);
    expect(card.card.intake).toEqual({ clientId: clerk.cert.clientId, agreeKey: clerk.cert.agreeKey, intents: ['schedule.*'] });
    expect(view.view.members.map((m) => m.kind)).toEqual(['device', 'device', 'agent']);
    for (const secret of ['Phone', 'Laptop', 'Clerk', 'read:*', 'admit', 'intent:']) expect(shown).not.toContain(secret);
  });

  it('seal requests to the intake alone when it is exclusive', () => {
    const identity = Identity.create('jerzy@beta.test');
    identity.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'admit'] });
    const clerk = identity.enrollClient({ kind: 'agent', label: 'Clerk', scopes: ['read:*', 'admit'] });
    identity.setIntake({ clientId: clerk.cert.clientId, intents: ['schedule.*'], exclusive: true });

    expect(identity.publication().card.card.requestKeys.map((key) => key.agreeKey)).toEqual([clerk.cert.agreeKey]);
  });
});

describe('humans-only audience', () => {
  it('routes humans-only mail to devices by default, and to agents only when the owner opts them in', () => {
    const identity = Identity.create('jerzy@beta.test');
    const phone = identity.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'admit'] });
    const clerk = identity.enrollClient({ kind: 'agent', label: 'Clerk', scopes: ['read:*', 'admit'] });

    const before = identity.publication();
    expect(before.card.card.humanKeys.map((key) => key.agreeKey)).toEqual([phone.cert.agreeKey]);
    expect(before.view.view.members.map((m) => m.humansOnly)).toEqual([true, false]);

    identity.setAudiencePolicy([clerk.cert.clientId]);
    const after = identity.publication();
    expect(after.card.card.humanKeys.map((key) => key.agreeKey)).toEqual([phone.cert.agreeKey, clerk.cert.agreeKey]);
    expect(after.view.view.members.map((m) => m.humansOnly)).toEqual([true, true]);
  });
});

describe('escrow', () => {
  it('gets every request and all humans-only mail, even past an exclusive intake and an empty audience policy', () => {
    const identity = Identity.create('jerzy@beta.test');
    const phone = identity.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'admit'] });
    const clerk = identity.enrollClient({ kind: 'agent', label: 'Clerk', scopes: ['read:*', 'admit'] });
    const escrow = identity.enrollClient({ kind: 'org-escrow', label: 'Firm escrow', scopes: ['read:*'] });
    identity.setIntake({ clientId: clerk.cert.clientId, intents: [], exclusive: true });
    identity.setAudiencePolicy([]);

    const { card, view } = identity.publication();
    expect(card.card.requestKeys.map((key) => key.agreeKey)).toEqual([clerk.cert.agreeKey, escrow.cert.agreeKey]);
    expect(card.card.humanKeys.map((key) => key.agreeKey)).toEqual([phone.cert.agreeKey, escrow.cert.agreeKey]);
    expect(view.view.members.find((m) => m.clientId === escrow.cert.clientId)).toMatchObject({ kind: 'escrow', reads: true, humansOnly: true });
  });

  it("refuses an escrow client that can't read everything", () => {
    const identity = Identity.create('jerzy@beta.test');
    identity.enrollClient({ kind: 'org-escrow', label: 'Firm escrow', scopes: [] });

    expect(() => replayLog(identity.entries)).toThrow("can't read everything");
  });
});

describe('VRF index', () => {
  it('is proven per address and fails for any other address or key', () => {
    const key = generateVrfKey();
    const proof = proveIndex(key, 'Jerzy@Beta.test');

    expect(verifyIndex(key.public, 'jerzy@beta.test', proof)).toBe(proof.index);
    expect(proveIndex(key, 'jerzy@beta.test').index).toBe(proof.index);
    expect(() => verifyIndex(key.public, 'alice@beta.test', proof)).toThrow();
    expect(() => verifyIndex(generateVrfKey().public, 'jerzy@beta.test', proof)).toThrow();
  });
});

describe('directory entry', () => {
  const domainKey = generateSigningKey();
  const vrfKey = generateVrfKey();
  const policy: DomainPolicy = {
    v: 'signet0',
    domain: 'beta.test',
    server: 'http://beta.test',
    mode: 'enforce',
    maxAge: 60,
    domainKey: domainKey.publicKey,
    vrfKey: vrfKey.public,
    log: { url: 'http://log.test', key: generateSigningKey().publicKey },
  };

  function entry(identity: Identity, overrides: Record<string, unknown> = {}) {
    const { card, view } = identity.publication();
    return {
      status: 'enrolled' as const,
      principal: identity.principal,
      binding: bindIdentity(domainKey, identity.principal, identity.identityKey),
      card,
      view,
      vrf: proveIndex(vrfKey, identity.principal),
      ...overrides,
    };
  }

  it('verifies a card and view bound by the domain key, with its VRF index', () => {
    const identity = Identity.create('jerzy@beta.test');

    const directory = verifyDirectoryEntry(entry(identity), policy);

    expect(directory.identityKey).toBe(identity.identityKey);
    expect(directory.index).toBe(proveIndex(vrfKey, 'jerzy@beta.test').index);
  });

  it('rejects a binding signed by another key', () => {
    const identity = Identity.create('jerzy@beta.test');

    expect(() =>
      verifyDirectoryEntry(entry(identity, { binding: bindIdentity(generateSigningKey(), identity.principal, identity.identityKey) }), policy),
    ).toThrow('binding is not signed by the domain key');
  });

  it("rejects a card the identity key didn't sign", () => {
    const identity = Identity.create('jerzy@beta.test');
    const impostor = Identity.create('jerzy@beta.test');

    expect(() => verifyDirectoryEntry(entry(identity, { card: impostor.publication().card }), policy)).toThrow('not signed by its identity key');
  });

  it("rejects another address's VRF proof", () => {
    const identity = Identity.create('jerzy@beta.test');

    expect(() => verifyDirectoryEntry(entry(identity, { vrf: proveIndex(vrfKey, 'alice@beta.test') }), policy)).toThrow();
  });
});
