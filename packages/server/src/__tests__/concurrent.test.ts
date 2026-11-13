import type { SignetClient, SignetEvent } from '@signet/lib';
import { Identity } from '@signet/lib';
import { Testbed } from '../testbed';

const scopes = ['read:*', 'send', 'admit'];
const epochOf = (client: SignetClient, thread: string): number => (client as unknown as { mls: { epoch: (thread: string) => number } }).mls.epoch(thread);

async function world() {
  const bed = await Testbed.start(['alpha.test', 'beta.test']);
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
  return { bed, alice, jerzy, alicePhone, jerzyPhone, thread };
}

describe('two members committing from the same epoch (Section 8.8)', () => {
  // Which of the two commits is first in the new devices' mailboxes is the other way round in the second run.
  it.each([['alice commits first'], ['jerzy commits first']])('settles on the commit with the smaller hash, however the commits arrive, and carries on (%s)', async (order) => {
    const w = await world();
    try {
      // Each account gets a new device, and both phones rekey before either has seen the other's commit.
      const tablet = w.bed.client(w.alice.enrollClient({ kind: 'device', label: 'Tablet', scopes }));
      const laptop = w.bed.client(w.jerzy.enrollClient({ kind: 'device', label: 'Laptop', scopes }));
      await w.bed.publish(w.alice);
      await w.bed.publish(w.jerzy);
      await tablet.ready();
      await laptop.ready();
      const before = epochOf(w.alicePhone, w.thread);

      const [first, second] = order === 'alice commits first' ? [w.alicePhone, w.jerzyPhone] : [w.jerzyPhone, w.alicePhone];
      await first.rekey(w.thread);
      await second.rekey(w.thread);
      expect(epochOf(w.alicePhone, w.thread)).toBe(before + 1);
      expect(epochOf(w.jerzyPhone, w.thread)).toBe(before + 1);

      const seen: SignetEvent[] = [];
      for (let round = 0; round < 3; round += 1) {
        for (const client of [tablet, laptop, w.alicePhone, w.jerzyPhone]) seen.push(...(await client.sync()));
      }
      // Everyone is in one epoch.
      const epochs = [tablet, laptop, w.alicePhone, w.jerzyPhone].map((client) => epochOf(client, w.thread));
      expect(new Set(epochs).size).toBe(1);
      expect(epochs[0]).toBe(before + 1);
      // Exactly one of the two phones had applied the commit that lost, and went back to before it.
      expect(seen.filter((event) => event.kind === 'fork-resolved')).toHaveLength(1);
      expect(seen.flatMap((event) => (event.kind === 'error' ? [event.error] : []))).toEqual([]);

      // And the group works: a message from each side reaches everyone else.
      await w.alicePhone.send(w.thread, { subject: 'Hi', text: 'from alice' });
      await w.jerzyPhone.send(w.thread, { subject: 'Hi', text: 'from jerzy' });
      const texts = async (client: SignetClient) => (await client.sync()).flatMap((event) => (event.kind === 'message' ? [event.message.body.text] : []));
      expect((await texts(tablet)).sort()).toEqual(['from alice', 'from jerzy']);
      expect((await texts(laptop)).sort()).toEqual(['from alice', 'from jerzy']);
      expect(await texts(w.alicePhone)).toEqual(['from jerzy']);
      expect(await texts(w.jerzyPhone)).toEqual(['from alice']);
    } finally {
      await w.bed.close();
    }
  });

  it('keeps a message it cannot read yet, reads it once the commit arrives, and reports one that never becomes readable', async () => {
    const w = await world();
    try {
      const laptop = w.bed.client(w.jerzy.enrollClient({ kind: 'device', label: 'Laptop', scopes }));
      await w.bed.publish(w.jerzy);
      await laptop.ready();
      // The server parks Alice's next message until Jerzy's phone has the new epoch's token, so catch it on the way.
      const parked: { id: string; kind: string; payload: unknown }[] = [];
      const store = w.bed.server('beta.test').store;
      const park = store.park.bind(store);
      store.park = (local, hash, item, ttl, cap) => {
        parked.push(item as never);
        return park(local, hash, item, ttl, cap);
      };
      await w.alicePhone.rekey(w.thread);
      await w.alicePhone.send(w.thread, { subject: 'Hi', text: 'after the rekey' });
      expect(parked).toHaveLength(1);

      // Hand it to Jerzy's phone before the commit it follows: it cannot read it yet, and keeps it.
      const hold = (client: SignetClient) => (client as unknown as { state: { held: { item: unknown; at: number }[] } }).state.held;
      hold(w.jerzyPhone).push({ item: { ...parked[0], seq: 0, receivedAt: new Date().toISOString() }, at: Date.now() });
      // The server's own copy never arrives, so the only way to read it is from what the client held.
      store.release = () => 0;
      const events = await w.jerzyPhone.sync();
      expect(events.map((event) => event.kind)).toEqual(expect.arrayContaining(['rekeyed', 'message']));
      expect(events.some((event) => event.kind === 'error')).toBe(false);
      expect(hold(w.jerzyPhone)).toHaveLength(0);

      // One that no commit ever makes readable is reported after the window, not before.
      hold(w.jerzyPhone).push({ item: { ...parked[0], id: 'i_unreadable', seq: 0, receivedAt: new Date().toISOString() }, at: Date.now() });
      expect((await w.jerzyPhone.sync()).some((event) => event.kind === 'error')).toBe(false);
      hold(w.jerzyPhone)[0].at = Date.now() - 6 * 60_000;
      const late = await w.jerzyPhone.sync();
      expect(late.some((event) => event.kind === 'error' && event.error.includes('could not be decrypted'))).toBe(true);
    } finally {
      await w.bed.close();
    }
  });
});
