import type { SignetClient } from '@signet/lib';
import { Identity } from '@signet/lib';
import { Testbed } from '../testbed';

const scopes = ['read:*', 'send', 'admit'];

async function world() {
  const bed = await Testbed.start(['alpha.test', 'beta.test']);
  const bob = Identity.create('bob@beta.test');
  const phone = bed.client(bob.enrollClient({ kind: 'device', label: 'Phone', scopes }));
  await bed.publish(bob);
  await phone.ready();
  const beta = bed.server('beta.test');
  const addDevice = async (label: string) => {
    const keys = bob.enrollClient({ kind: 'device', label, scopes });
    await bed.publish(bob);
    const client = bed.client(keys);
    await client.ready();
    return { client, keys };
  };
  return { bed, bob, phone, beta, addDevice };
}

type Raw = { request: (base: string, method: string, path: string, body?: unknown) => Promise<unknown> };
const raw = (client: SignetClient) => (client as unknown as Raw).request.bind(client);
const lists = (client: SignetClient) => client.snapshot().admission;

describe('encrypted shared contacts (Section 7.9)', () => {
  let w: Awaited<ReturnType<typeof world>>;
  beforeEach(async () => {
    w = await world();
  });
  afterEach(async () => {
    await w.bed.close();
  });

  it('keeps the contacts on the home server as ciphertext, one wrap for each client', async () => {
    await w.phone.addContact('alice@alpha.test');
    await w.phone.trustDomain('alpha.test');
    const doc = w.beta.store.contactsDoc('bob');
    expect(doc).toMatchObject({ epoch: 1, version: 2 });
    expect(Object.keys(doc.wraps)).toHaveLength(1);
    const stored = JSON.stringify(doc);
    expect(stored).not.toContain('alice');
    expect(stored).not.toContain('alpha.test');
    expect(lists(w.phone)).toEqual({ contacts: ['alice@alpha.test'], trustedDomains: ['alpha.test'] });
  });

  it('gives a new device the key at the next sync of one that has it, and the device then sees the contacts', async () => {
    await w.phone.addContact('alice@alpha.test');
    const laptop = await w.addDevice('Laptop');
    await laptop.client.sync();
    expect(lists(laptop.client).contacts).toEqual([]);
    // Nothing yet: no client that holds the key has seen the laptop.
    expect(w.beta.store.contactsDoc('bob').wraps[laptop.keys.cert.clientId]).toBeUndefined();
    await w.phone.sync();
    expect(w.beta.store.contactsDoc('bob').wraps[laptop.keys.cert.clientId]).toBeDefined();
    await laptop.client.sync();
    expect(lists(laptop.client).contacts).toEqual(['alice@alpha.test']);
  });

  it('carries removals to every client, and does not bring a removed entry back from a stale copy', async () => {
    const laptop = await w.addDevice('Laptop');
    await w.phone.addContact('alice@alpha.test');
    await w.phone.sync();
    await laptop.client.sync();
    expect(lists(laptop.client).contacts).toEqual(['alice@alpha.test']);
    await w.phone.removeContact('alice@alpha.test');
    await laptop.client.sync();
    expect(lists(laptop.client).contacts).toEqual([]);
    await w.phone.sync();
    expect(lists(w.phone).contacts).toEqual([]);
  });

  it('keeps both changes when two clients edit at once', async () => {
    const laptop = await w.addDevice('Laptop');
    await w.phone.sync();
    await laptop.client.sync();
    await Promise.all([w.phone.addContact('alice@alpha.test'), laptop.client.addContact('carol@alpha.test')]);
    await w.phone.sync();
    await laptop.client.sync();
    expect(lists(w.phone).contacts.sort()).toEqual(['alice@alpha.test', 'carol@alpha.test']);
    expect(lists(laptop.client).contacts.sort()).toEqual(['alice@alpha.test', 'carol@alpha.test']);
  });

  it('applies a change made before the client had the key once it has it', async () => {
    const laptop = await w.addDevice('Laptop');
    await w.phone.addContact('alice@alpha.test');
    await laptop.client.addContact('carol@alpha.test');
    expect(lists(laptop.client).contacts).toEqual(['carol@alpha.test']);
    await w.phone.sync();
    await laptop.client.sync();
    await w.phone.sync();
    expect(lists(w.phone).contacts.sort()).toEqual(['alice@alpha.test', 'carol@alpha.test']);
    expect(lists(laptop.client).contacts.sort()).toEqual(['alice@alpha.test', 'carol@alpha.test']);
  });

  it('makes a new key when a client that held the old one is revoked, so it cannot read what comes after', async () => {
    const laptop = await w.addDevice('Laptop');
    await w.phone.addContact('alice@alpha.test');
    await w.phone.sync();
    await laptop.client.sync();
    expect(Object.keys(w.beta.store.contactsDoc('bob').wraps)).toHaveLength(2);
    const oldKey = laptop.client.snapshot().contactKeys[w.bed.url('beta.test')];
    w.bob.revoke(laptop.keys.cert.clientId);
    await w.bed.publish(w.bob);
    await w.phone.addContact('dana@alpha.test');
    await w.phone.sync();
    const doc = w.beta.store.contactsDoc('bob');
    expect(doc.epoch).toBe(2);
    expect(Object.keys(doc.wraps)).toEqual([expect.any(String)]);
    expect(doc.wraps[laptop.keys.cert.clientId]).toBeUndefined();
    expect(lists(w.phone).contacts.sort()).toEqual(['alice@alpha.test', 'dana@alpha.test']);
    // The revoked client's key is the old epoch's: it opens nothing in the new document.
    expect(oldKey.epoch).toBe(1);
  });

  it('refuses an answer older than one it has seen', async () => {
    await w.phone.addContact('alice@alpha.test');
    const older = w.beta.store.contactsDoc('bob');
    await w.phone.addContact('carol@alpha.test');
    w.beta.store.putContactsDoc('bob', older);
    await expect(w.phone.sync()).rejects.toThrow('older contacts');
  });

  it('refuses a stale version, a wrap for a client that is not active, and a skipped epoch', async () => {
    await w.phone.addContact('alice@alpha.test');
    const doc = w.beta.store.contactsDoc('bob');
    const put = (body: object) => raw(w.phone)(w.bed.url('beta.test'), 'PUT', '/v0/contacts', body);
    const data = doc.data;
    await expect(put({ expectedVersion: doc.version - 1, epoch: doc.epoch, data })).rejects.toThrow('409');
    await expect(put({ expectedVersion: doc.version, epoch: doc.epoch, data, wraps: { c_stranger: { enc: 'a', ct: 'b' } } })).rejects.toThrow('400');
    await expect(put({ expectedVersion: doc.version, epoch: doc.epoch + 2, data, wraps: {} })).rejects.toThrow('400');
    await expect(put({ expectedVersion: doc.version, epoch: doc.epoch + 1, wraps: {} })).rejects.toThrow('400');
    expect(w.beta.store.contactsDoc('bob').version).toBe(doc.version);
  });
});
