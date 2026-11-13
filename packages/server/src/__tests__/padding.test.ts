import { Identity } from '@signet/lib';
import { Testbed } from '../testbed';

const scopes = ['read:*', 'send', 'admit'];

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
  return { bed, alicePhone, jerzyPhone };
}

describe('padded envelopes on the wire (Section 10.2)', () => {
  it('pads every submission and every delivery between servers, and the receiver is none the wiser', async () => {
    // Spy first: clients take the global fetch when they are made.
    const seen: { url: string; bytes: number }[] = [];
    const real = global.fetch;
    jest.spyOn(global, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      const body = init?.body;
      const size = typeof body === 'string' ? Buffer.byteLength(body) : body instanceof Uint8Array ? body.byteLength : undefined;
      if (size !== undefined && /\/v0\/(submit|deliver|deliver-sealed|deliver-anonymous|relay)(\?|$)/.test(url)) seen.push({ url, bytes: size });
      return real(input, init);
    });
    const w = await world();
    try {
      await w.alicePhone.sendRequest('jerzy@beta.test', { subject: 'Hello' });
      const [incoming] = await w.jerzyPhone.sync();
      if (incoming?.kind !== 'request') throw new Error('expected a request');
      const thread = await w.jerzyPhone.accept(incoming.request);
      await w.alicePhone.sync();
      await w.alicePhone.send(thread, { subject: 'Short', text: 'Hi' });
      await w.alicePhone.send(thread, { subject: 'Longer', text: 'A rather longer message, so the bodies differ in length.' });
      const events = await w.jerzyPhone.sync();
      expect(events.filter((event) => event.kind === 'message')).toHaveLength(2);

      expect(seen.some((entry) => entry.url.endsWith('/v0/submit'))).toBe(true);
      // What the relay sees is the padded delivery inside an encapsulation of fixed overhead, so its sizes agree too.
      const relayed = seen.filter((entry) => entry.url.includes('/v0/relay'));
      expect(relayed.length).toBeGreaterThanOrEqual(2);
      expect(seen.filter((entry) => !entry.url.includes('/v0/relay')).every((entry) => entry.bytes % 1024 === 0)).toBe(true);
      expect(relayed.slice(-2)[0].bytes).toBe(relayed.slice(-2)[1].bytes);
      // Two messages of different lengths leave in bodies of the same size.
      const submits = seen.filter((entry) => entry.url.endsWith('/v0/submit')).slice(-2);
      expect(submits[0].bytes).toBe(submits[1].bytes);
    } finally {
      jest.restoreAllMocks();
      await w.bed.close();
    }
  });

  it('does not keep or pass on the padding', async () => {
    const w = await world();
    try {
      await w.alicePhone.sendRequest('jerzy@beta.test', { subject: 'Hello' });
      const [item] = (w.bed.server('beta.test').store as unknown as { mailbox: (local: string) => object[] }).mailbox('jerzy');
      expect(JSON.stringify(item)).not.toContain('"pad"');
    } finally {
      await w.bed.close();
    }
  });
});

describe('the delay before deliveries nobody asked for just now (Section 7.3)', () => {
  it('waits a random time before a delivery a sync sends again, and not before one a person sends', async () => {
    const w = await world();
    try {
      const delays: number[] = [];
      const real = global.setTimeout;
      jest.spyOn(global, 'setTimeout').mockImplementation(((fn: () => void, ms?: number, ...args: unknown[]) => {
        if (typeof ms === 'number' && ms > 0 && ms < 2000 && ms !== 20) delays.push(ms);
        return real(fn, 0, ...args);
      }) as typeof setTimeout);
      const client = w.alicePhone as unknown as { backgroundDelay: () => Promise<void>; options: { submitDelayMs?: number } };
      client.options.submitDelayMs = 1500;
      await client.backgroundDelay();
      expect(delays).toHaveLength(1);
      expect(delays[0]).toBeLessThan(1500);
      client.options.submitDelayMs = 0;
      await client.backgroundDelay();
      expect(delays).toHaveLength(1);
    } finally {
      jest.restoreAllMocks();
      await w.bed.close();
    }
  });
});
