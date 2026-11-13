import { Identity } from '@signet/lib';
import { Testbed } from '../testbed';

const scopes = ['read:*', 'send', 'admit'];
const WINDOW = 400;
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe('batching across senders (Section 10.6.1)', () => {
  it('holds deliveries to another domain until the window ends and then sends senders together', async () => {
    const bed = await Testbed.start(['alpha.test', 'beta.test'], { batchMs: WINDOW });
    try {
      const alice = Identity.create('alice@alpha.test');
      const carol = Identity.create('carol@alpha.test');
      const jerzy = Identity.create('jerzy@beta.test');
      const phone = (who: Identity) => bed.client(who.enrollClient({ kind: 'device', label: 'Phone', scopes }));
      const [alicePhone, carolPhone, jerzyPhone] = [phone(alice), phone(carol), phone(jerzy)];
      for (const who of [alice, carol, jerzy]) await bed.publish(who);
      await Promise.all([alicePhone.ready(), carolPhone.ready(), jerzyPhone.ready()]);

      // When each delivery reaches beta's mailbox.
      const arrivals: { local: string; at: number }[] = [];
      const store = bed.server('beta.test').store;
      const push = store.push.bind(store);
      store.push = (local, item) => {
        arrivals.push({ local: item.kind === 'request' ? `${item.id}` : item.kind, at: Date.now() });
        return push(local, item);
      };

      // Start just after a window edge, so both sends fall in one window.
      await sleep(WINDOW - (Date.now() % WINDOW) + 10);
      const start = Date.now();
      const aliceSend = alicePhone.sendRequest('jerzy@beta.test', { subject: 'From Alice' }).then(() => Date.now());
      await sleep(180);
      const carolSend = carolPhone.sendRequest('jerzy@beta.test', { subject: 'From Carol' }).then(() => Date.now());
      const [aliceDone, carolDone] = await Promise.all([aliceSend, carolSend]);

      expect(arrivals).toHaveLength(2);
      const [first, second] = arrivals.map((arrival) => arrival.at - start).sort((a, b) => a - b);
      // Nothing left before the window ended, though the first was submitted at once.
      expect(first).toBeGreaterThanOrEqual(WINDOW - 60);
      // The two were sent 180 ms apart, and arrive close together.
      expect(second - first).toBeLessThan(150);
      // The senders were answered only after their deliveries were attempted.
      expect(aliceDone - start).toBeGreaterThanOrEqual(WINDOW - 60);
      expect(carolDone - start).toBeGreaterThanOrEqual(WINDOW - 60);
      expect((await jerzyPhone.sync()).filter((event) => event.kind === 'request')).toHaveLength(2);
    } finally {
      await bed.close();
    }
  }, 30_000);

  it('keeps one sender’s messages in order, and answers them all', async () => {
    const bed = await Testbed.start(['alpha.test', 'beta.test'], { batchMs: 150 });
    try {
      const alice = Identity.create('alice@alpha.test');
      const jerzy = Identity.create('jerzy@beta.test');
      const alicePhone = bed.client(alice.enrollClient({ kind: 'device', label: 'Phone', scopes }));
      const jerzyPhone = bed.client(jerzy.enrollClient({ kind: 'device', label: 'Phone', scopes }));
      await bed.publish(alice);
      await bed.publish(jerzy);
      await alicePhone.ready();
      await jerzyPhone.ready();
      await alicePhone.sendRequest('jerzy@beta.test', { subject: 'Hello' });
      const [incoming] = await jerzyPhone.sync();
      if (incoming?.kind !== 'request') throw new Error('expected a request');
      const thread = await jerzyPhone.accept(incoming.request);
      await alicePhone.sync();
      for (const text of ['one', 'two', 'three']) await alicePhone.send(thread, { subject: 'Order', text });
      const texts = (await jerzyPhone.sync()).flatMap((event) => (event.kind === 'message' ? [event.message.body.text] : []));
      expect(texts).toEqual(['one', 'two', 'three']);
    } finally {
      await bed.close();
    }
  }, 30_000);

  it('does nothing to deliveries inside one domain', async () => {
    const bed = await Testbed.start(['alpha.test'], { batchMs: 5_000 });
    try {
      const alice = Identity.create('alice@alpha.test');
      const carol = Identity.create('carol@alpha.test');
      const alicePhone = bed.client(alice.enrollClient({ kind: 'device', label: 'Phone', scopes }));
      const carolPhone = bed.client(carol.enrollClient({ kind: 'device', label: 'Phone', scopes }));
      await bed.publish(alice);
      await bed.publish(carol);
      await alicePhone.ready();
      await carolPhone.ready();
      const started = Date.now();
      await alicePhone.sendRequest('carol@alpha.test', { subject: 'Local' });
      expect(Date.now() - started).toBeLessThan(3_000);
      expect((await carolPhone.sync()).filter((event) => event.kind === 'request')).toHaveLength(1);
    } finally {
      await bed.close();
    }
  }, 30_000);
});
