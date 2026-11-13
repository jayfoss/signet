import type { DirectoryEntry } from '@signet/lib';
import { HiddenAddressError, Identity, attestedSignetHeader, hashBody, signUnlisted } from '@signet/lib';
import { Testbed } from '../testbed';

async function world() {
  // beta.test runs an intake. Bob is listed there; Jerzy chose to be unlisted.
  const bed = await Testbed.start(['alpha.test', 'beta.test'], { intake: ['beta.test'] });
  const alice = Identity.create('alice@alpha.test');
  const bob = Identity.create('bob@beta.test');
  const jerzy = Identity.create('jerzy@beta.test');
  const device = (identity: Identity) => bed.client(identity.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] }));
  const [alicePhone, bobPhone, jerzyPhone] = [device(alice), device(bob), device(jerzy)];
  jerzy.setUnlisted(true);
  for (const identity of [alice, bob, jerzy]) await bed.publish(identity);
  for (const client of [alicePhone, bobPhone, jerzyPhone]) await client.ready();
  const server = bed.server('beta.test');
  const intakeKeyId = server.policy.intake?.keyId;
  const unlistedAnswer = (local: string) => signUnlisted(bed.domainKey('beta.test'), `${local}@beta.test`);
  return { bed, jerzy, alicePhone, bobPhone, jerzyPhone, server, intakeKeyId, unlistedAnswer };
}

describe('catching a domain that hides a listed address to read first requests', () => {
  let w: Awaited<ReturnType<typeof world>>;

  beforeEach(async () => {
    w = await world();
  });

  afterEach(async () => {
    jest.restoreAllMocks();
    await w.bed.close();
  });

  /** The domain tells other servers Bob is unlisted, but answers anonymous lookups honestly. */
  const lieToServers = (local: string) => {
    const server = w.server as unknown as { remoteLookup: (request: unknown, who: string) => Promise<DirectoryEntry> };
    const honest = server.remoteLookup.bind(w.server);
    jest.spyOn(server, 'remoteLookup').mockImplementation(async (request, who) => (who === local ? w.unlistedAnswer(local) : honest(request, who)));
  };

  /** The domain tells everyone Bob is unlisted. */
  const lieToEveryone = (local: string) => {
    const honest = w.server.directory.bind(w.server);
    jest.spyOn(w.server, 'directory').mockImplementation((who, access) => (who === local && access === 'public' ? w.unlistedAnswer(local) : honest(who, access)));
  };

  it('cross-checks anonymously, then sends straight to the real keys and reports the lie', async () => {
    lieToServers('bob');

    const sent = await w.alicePhone.sendRequest('bob@beta.test', { subject: 'Hello' });

    expect(sent.copies.map((copy) => copy.clientId)).not.toContain(w.intakeKeyId);
    expect(await w.bobPhone.sync()).toMatchObject([{ kind: 'request' }]);
    expect(await w.alicePhone.sync()).toEqual(
      expect.arrayContaining([{ kind: 'directory-alert', principal: 'bob@beta.test', alert: expect.stringContaining('shows it to anonymous lookups') }]),
    );
  });

  it("alerts the owner when its domain tells strangers it's unlisted", async () => {
    expect((await w.bobPhone.monitor()).alerts).toEqual([]);

    lieToEveryone('bob');

    expect((await w.bobPhone.monitor()).alerts).toContain("beta.test tells strangers bob@beta.test is unlisted, so their first requests would go through its intake, which can read them");
  });

  it('alerts an unlisted owner whose domain shows it to strangers', async () => {
    const honest = w.server.directory.bind(w.server);
    jest.spyOn(w.server, 'directory').mockImplementation((who, access) => (who === 'jerzy' && access === 'public' ? honest(who, 'contact') : honest(who, access)));

    expect((await w.jerzyPhone.monitor()).alerts).toContain('beta.test shows jerzy@beta.test to strangers, though it is unlisted');
  });

  it('refuses the intake for an address the sender already pinned', async () => {
    await w.alicePhone.lookup('bob@beta.test');
    lieToEveryone('bob');

    await expect(w.alicePhone.sendRequest('bob@beta.test', { subject: 'Hello' })).rejects.toThrow(HiddenAddressError);
    await expect(w.alicePhone.sendRequest('bob@beta.test', { subject: 'Hello' })).rejects.toThrow('you have its key pinned');
  });

  it('refuses the intake for an address known from an authenticated Signet header', async () => {
    lieToEveryone('bob');
    const fields = { from: 'bob@beta.test', to: ['alice@alpha.test'], subject: 'Following up', bodyHash: hashBody('Hello') };
    const header = attestedSignetHeader(w.bed.domainKey('beta.test'), w.bed.url('beta.test'), (await w.bobPhone.lookup('bob@beta.test'))?.identityKey ?? '', fields);

    expect(await w.alicePhone.checkSignetHeader(fields, header)).toMatchObject({ onSignet: true, authenticated: true });
    await expect(w.alicePhone.sendRequest('bob@beta.test', { subject: 'Re: following up' })).rejects.toThrow('authenticated Signet header');
  });

  it("reaches an unlisted person directly with the contact card they handed out", async () => {
    const card = await w.jerzyPhone.contactCard();
    expect(card).toMatch(/^signet:card\?e=/);

    expect((await w.alicePhone.importContactCard(card)).identityKey).toBe(w.jerzy.identityKey);
    const sent = await w.alicePhone.sendRequest('jerzy@beta.test', { subject: 'Hello' });

    expect(sent.copies.map((copy) => copy.clientId)).not.toContain(w.intakeKeyId);
    expect(await w.jerzyPhone.sync()).toMatchObject([{ kind: 'request', request: { body: { from: 'alice@alpha.test' } } }]);
  });

  it('asks for a new card once the old one no longer matches the log', async () => {
    await w.alicePhone.importContactCard(await w.jerzyPhone.contactCard());
    w.jerzy.enrollClient({ kind: 'device', label: 'Laptop', scopes: ['read:*', 'send', 'admit'] });
    await w.bed.publish(w.jerzy);

    await expect(w.alicePhone.sendRequest('jerzy@beta.test', { subject: 'Hello' })).rejects.toThrow('your contact card for it is out of date');
  });
});
