import { Identity } from '@signet/lib';
import { Testbed } from '../testbed';

async function world() {
  const bed = await Testbed.start(['alpha.test', 'beta.test']);
  const alice = Identity.create('alice@alpha.test');
  const bob = Identity.create('bob@beta.test');
  const device = (identity: Identity) => bed.client(identity.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] }));
  const alicePhone = device(alice);
  const bobPhone = device(bob);
  await bed.publish(alice);
  await bed.publish(bob);
  await alicePhone.ready();
  await bobPhone.ready();
  return { bed, bob, alicePhone, bobPhone, beta: bed.server('beta.test') };
}

describe('mailbox acknowledgements and retention (Section 10.7)', () => {
  let w: Awaited<ReturnType<typeof world>>;
  let bed: Testbed;
  beforeEach(async () => {
    w = await world();
    bed = w.bed;
  });
  afterEach(async () => {
    await w.bed.close();
  });

  it('deletes an item once the reading client has acknowledged it, and never reuses a seq', async () => {
    await w.alicePhone.sendRequest('bob@beta.test', { subject: 'First' });
    expect(w.beta.store.mailbox('bob')).toHaveLength(1);
    const first = w.beta.store.mailbox('bob')[0].seq;
    await w.bobPhone.sync();
    expect(w.beta.store.mailbox('bob')).toHaveLength(0);
    await w.alicePhone.sendRequest('bob@beta.test', { subject: 'Second' });
    const [second] = w.beta.store.mailbox('bob');
    expect(second.seq).toBeGreaterThan(first);
    const events = await w.bobPhone.sync();
    expect(events.some((event) => event.kind === 'request')).toBe(true);
  });

  it('keeps an item until every reading client has acknowledged it', async () => {
    const phone = w.bobPhone;
    const laptop = bed.client(w.bob.enrollClient({ kind: 'device', label: 'Laptop', scopes: ['read:*', 'send', 'admit'] }));
    await bed.publish(w.bob);
    await laptop.ready();
    await w.alicePhone.sendRequest('bob@beta.test', { subject: 'Hello' });
    await phone.sync();
    // The laptop has not read it yet, so it stays.
    expect(w.beta.store.mailbox('bob')).toHaveLength(1);
    await laptop.sync();
    expect(w.beta.store.mailbox('bob')).toHaveLength(0);
  });

  it('refuses an acknowledgement for a store that has started over', async () => {
    const call = (w.bobPhone as unknown as { request: (base: string, method: string, path: string, body?: unknown) => Promise<unknown> }).request.bind(w.bobPhone);
    await expect(call(w.bed.url('beta.test'), 'POST', '/v0/mailbox/ack', { through: 1, epoch: 'e_old' })).rejects.toThrow('409');
  });

  it('deletes an item that has outlived the retention period, acknowledged or not', async () => {
    await w.alicePhone.sendRequest('bob@beta.test', { subject: 'Old' });
    expect(w.beta.store.mailbox('bob')).toHaveLength(1);
    await w.beta.sweep(Date.now() + 31 * 24 * 3_600_000);
    expect(w.beta.store.mailbox('bob')).toHaveLength(0);
  });

  it('publishes the retention in the policy only when it is not the default', async () => {
    expect(w.beta.policy.mailboxRetention).toBeUndefined();
  });
});

describe('attachments (Section 8.9)', () => {
  it('uses long ids, lets the uploader delete a blob, and expires the rest', async () => {
    const w = await world();
    try {
      const file = { name: 'a.txt', type: 'text/plain', data: new TextEncoder().encode('hello') };
      const upload = (w.alicePhone as unknown as { upload: (file: unknown) => Promise<{ url: string; name: string }> }).upload.bind(w.alicePhone);
      const ref = await upload(file);
      const id = new URL(ref.url).pathname.split('/').pop() as string;
      expect(id.length).toBeGreaterThanOrEqual('blob_'.length + 22);
      expect((await fetch(ref.url)).status).toBe(200);
      // Someone else cannot delete it.
      const other = (w.bobPhone as unknown as { request: (base: string, method: string, path: string) => Promise<unknown> }).request.bind(w.bobPhone);
      await expect(other(w.bed.url('alpha.test'), 'DELETE', `/v0/blobs/${id}`)).rejects.toThrow();
      await w.alicePhone.deleteAttachment(ref as never);
      expect((await fetch(ref.url)).status).toBe(404);
      const second = await upload(file);
      await w.bed.server('alpha.test').sweep(Date.now() + 31 * 24 * 3_600_000);
      expect((await fetch(second.url)).status).toBe(404);
    } finally {
      await w.bed.close();
    }
  });
});
