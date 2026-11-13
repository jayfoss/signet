import { OHTTP_REQUEST_TYPE, OHTTP_RESPONSE_TYPE, Identity, decapsulateResponse, decodeResponse, domainAuthHeaders, encapsulateRequest, encodeRequest, generateSigningKey } from '@signet/lib';
import { Testbed } from '../testbed';

const scopes = ['read:*', 'send', 'admit'];
const WINDOW = 200;
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
// A short window needs a big budget: at 200 ms a window it is 18000 an hour.
const COVER = { cover: { 'alpha.test': { domains: ['beta.test'] } }, acceptCover: { 'beta.test': { partners: ['alpha.test'], perHour: 100_000 } } };

async function world(options: Parameters<typeof Testbed.start>[1] = {}, domains = ['alpha.test', 'beta.test']) {
  const bed = await Testbed.start(domains, { batchMs: WINDOW, ...COVER, ...options });
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

describe('cover traffic (Section 10.6.2)', () => {
  it('sends at a steady rate to a covered domain when nobody is sending, and the gateway keeps none of it', async () => {
    const w = await world();
    try {
      await sleep(3 * WINDOW);
      const before = w.bed.relay.forwarded;
      await sleep(10 * WINDOW);
      const idle = w.bed.relay.forwarded - before;
      // One a window, give or take the edges.
      expect(idle).toBeGreaterThanOrEqual(8);
      expect(idle).toBeLessThanOrEqual(12);
      expect((w.bed.server('beta.test').store as unknown as { mailbox: (local: string) => unknown[] }).mailbox('jerzy')).toHaveLength(0);
    } finally {
      await w.bed.close();
    }
  }, 30_000);

  it('sends the same number a window when users are sending: real deliveries take the place of cover', async () => {
    const w = await world();
    try {
      await w.alicePhone.sendRequest('jerzy@beta.test', { subject: 'Hello' });
      const [incoming] = await w.jerzyPhone.sync();
      if (incoming?.kind !== 'request') throw new Error('expected a request');
      const thread = await w.jerzyPhone.accept(incoming.request);
      await w.alicePhone.sync();

      const measure = async (work: () => Promise<void>) => {
        await sleep(WINDOW - (Date.now() % WINDOW) + 5);
        const before = w.bed.relay.forwarded;
        const started = Date.now();
        await work();
        await sleep(Math.max(0, 12 * WINDOW - (Date.now() - started)));
        return w.bed.relay.forwarded - before;
      };
      const idle = await measure(async () => undefined);
      const busy = await measure(async () => {
        for (const text of ['one', 'two', 'three']) await w.alicePhone.send(thread, { subject: 'Busy', text });
      });
      expect(Math.abs(busy - idle)).toBeLessThanOrEqual(2);
      const texts = (await w.jerzyPhone.sync()).flatMap((event) => (event.kind === 'message' ? [event.message.body.text] : []));
      expect(texts).toEqual(['one', 'two', 'three']);
    } finally {
      await w.bed.close();
    }
  }, 60_000);

  it('makes cover and real deliveries the same size on the link to the relay', async () => {
    const sizes: number[] = [];
    const real = global.fetch;
    jest.spyOn(global, 'fetch').mockImplementation(async (input, init) => {
      const body = init?.body;
      if (String(input).includes('/v0/relay') && body instanceof Uint8Array) sizes.push(body.byteLength);
      return real(input, init);
    });
    const w = await world();
    try {
      await w.alicePhone.sendRequest('jerzy@beta.test', { subject: 'Hello' });
      const [incoming] = await w.jerzyPhone.sync();
      if (incoming?.kind !== 'request') throw new Error('expected a request');
      const thread = await w.jerzyPhone.accept(incoming.request);
      await w.alicePhone.sync();
      sizes.length = 0;
      await sleep(3 * WINDOW);
      await w.alicePhone.send(thread, { subject: 'Short', text: 'Hi' });
      await w.alicePhone.send(thread, { subject: 'Longer', text: 'A somewhat longer message than the one before it, to be sure.' });
      // An anonymous request goes by another path, with another token, and is the same size too.
      await w.alicePhone.sendRequest('jerzy@beta.test', { subject: 'Another' });
      await sleep(3 * WINDOW);
      expect(sizes.length).toBeGreaterThanOrEqual(10);
      expect(new Set(sizes).size).toBe(1);
    } finally {
      jest.restoreAllMocks();
      await w.bed.close();
    }
  }, 60_000);

  it('publishes what the gateway will take, and stops covering a domain that does not take it', async () => {
    const w = await world({ acceptCover: {} });
    try {
      expect(w.bed.server('beta.test').policy.ohttp?.cover).toBeUndefined();
      await sleep(3 * WINDOW);
      const pacer = (w.bed.server('alpha.test') as unknown as { pacer: { covers: (domain: string) => boolean } }).pacer;
      expect(pacer.covers('beta.test')).toBe(false);
      // What it carries still gets there.
      await w.alicePhone.sendRequest('jerzy@beta.test', { subject: 'Hello' });
      expect((await w.jerzyPhone.sync()).filter((event) => event.kind === 'request')).toHaveLength(1);
    } finally {
      await w.bed.close();
    }
    const covered = await world({ acceptCover: { 'beta.test': { partners: ['alpha.test'] } } });
    try {
      expect(covered.bed.server('beta.test').policy.ohttp?.cover).toEqual({ perHour: 3600 });
      // At this window that is more than the gateway takes, so the sender does not cover it.
      await sleep(3 * WINDOW);
      const pacer = (covered.bed.server('alpha.test') as unknown as { pacer: { covers: (domain: string) => boolean } }).pacer;
      expect(pacer.covers('beta.test')).toBe(false);
    } finally {
      await covered.bed.close();
    }
  }, 30_000);

  it('refuses new submissions for a domain whose backlog is full, and sends the rest in order', async () => {
    const w = await world({ batchMs: 600, cover: { 'alpha.test': { domains: ['beta.test'], backlog: 1 } } });
    try {
      const sends = await Promise.allSettled(['a', 'b', 'c', 'd'].map((subject) => w.alicePhone.sendRequest('jerzy@beta.test', { subject })));
      const refused = sends.filter((outcome) => outcome.status === 'rejected');
      expect(sends.some((outcome) => outcome.status === 'fulfilled')).toBe(true);
      expect(refused.length).toBeGreaterThanOrEqual(1);
      expect(refused.every((outcome) => String((outcome as PromiseRejectedResult).reason).includes('503'))).toBe(true);
    } finally {
      await w.bed.close();
    }
  }, 60_000);

  it('does not pace a domain it was not told to cover', async () => {
    const w = await world({}, ['alpha.test', 'beta.test', 'gamma.test']);
    try {
      const pacer = (w.bed.server('alpha.test') as unknown as { pacer: { covers: (domain: string) => boolean } }).pacer;
      expect(pacer.covers('gamma.test')).toBe(false);
      expect(pacer.covers('beta.test')).toBe(true);
    } finally {
      await w.bed.close();
    }
  }, 30_000);
});

describe('the gateway is not a way to flood it (Section 10.6.2)', () => {
  const signed = (key: ReturnType<typeof generateSigningKey>, domain: string, path = '/v0/cover') => {
    const body = JSON.stringify({ pad: '0'.repeat(100) });
    return { body, headers: { 'content-type': 'application/json', ...domainAuthHeaders(domain, key, 'POST', path, body) } };
  };
  const post = (url: string, request: { body: string; headers: Record<string, string> }) => fetch(`${url}/v0/cover`, { method: 'POST', headers: request.headers, body: request.body });

  it('refuses anyone who is not a named partner without looking them up', async () => {
    const w = await world({ cover: {} });
    try {
      const looked: string[] = [];
      const policy = w.bed.resolver.policy.bind(w.bed.resolver);
      jest.spyOn(w.bed.resolver, 'policy').mockImplementation(async (domain) => {
        looked.push(domain);
        return policy(domain);
      });
      const url = w.bed.url('beta.test');
      expect((await fetch(`${url}/v0/cover`, { method: 'POST', body: '{}' })).status).toBe(403);
      expect((await post(url, signed(generateSigningKey(), 'evil.test'))).status).toBe(403);
      expect((await post(url, signed(generateSigningKey(), 'EVIL.test'))).status).toBe(403);
      expect(looked).not.toContain('evil.test');
      expect(looked).not.toContain('EVIL.test');
    } finally {
      jest.restoreAllMocks();
      await w.bed.close();
    }
  }, 30_000);

  it('refuses a partner’s name with someone else’s signature, and a signature used twice', async () => {
    const w = await world({ cover: {} });
    try {
      const url = w.bed.url('beta.test');
      expect((await post(url, signed(generateSigningKey(), 'alpha.test'))).status).toBe(401);
      const genuine = signed(w.bed.domainKey('alpha.test'), 'alpha.test');
      expect((await post(url, genuine)).status).toBe(200);
      expect((await post(url, genuine)).status).toBe(401);
      // A signature for another path does not do for this one.
      const other = signed(w.bed.domainKey('alpha.test'), 'alpha.test', '/v0/deliver');
      expect((await post(url, other)).status).toBe(401);
    } finally {
      await w.bed.close();
    }
  }, 30_000);

  it('gives each partner a budget for the hour, and says what it is', async () => {
    const w = await world({ cover: {}, acceptCover: { 'beta.test': { partners: ['alpha.test'], perHour: 5 } } });
    try {
      const url = w.bed.url('beta.test');
      expect(w.bed.server('beta.test').policy.ohttp?.cover).toEqual({ perHour: 5 });
      const statuses: number[] = [];
      for (let i = 0; i < 7; i += 1) statuses.push((await post(url, signed(w.bed.domainKey('alpha.test'), 'alpha.test'))).status);
      expect(statuses).toEqual([200, 200, 200, 200, 200, 429, 429]);
    } finally {
      await w.bed.close();
    }
  }, 30_000);

  it('applies the same rules inside Oblivious HTTP, and pads every answer', async () => {
    const w = await world({ cover: {} });
    try {
      const policy = w.bed.server('beta.test').policy;
      const ask = async (request: { body: string; headers: Record<string, string> }) => {
        const inner = encodeRequest({ method: 'POST', scheme: 'https', authority: new URL(w.bed.url('beta.test')).host, path: '/v0/cover', headers: Object.entries(request.headers), body: Buffer.from(request.body) });
        const { message, pending } = await encapsulateRequest((policy.ohttp as { keys: string }).keys, inner);
        const response = await fetch(`${w.bed.url('beta.test')}/v0/ohttp`, { method: 'POST', headers: { 'content-type': OHTTP_REQUEST_TYPE }, body: message });
        expect(response.headers.get('content-type')).toBe(OHTTP_RESPONSE_TYPE);
        const decoded = decodeResponse(decapsulateResponse(pending, Buffer.from(await response.arrayBuffer())));
        return { status: decoded.status, size: decoded.body.length };
      };
      const good = await ask(signed(w.bed.domainKey('alpha.test'), 'alpha.test'));
      const evil = await ask(signed(generateSigningKey(), 'evil.test'));
      const forged = await ask(signed(generateSigningKey(), 'alpha.test'));
      expect([good.status, evil.status, forged.status]).toEqual([200, 403, 401]);
      // Whatever the answer, it is the same size.
      expect(new Set([good.size, evil.size, forged.size]).size).toBe(1);
      expect(good.size % 4096).toBe(0);
    } finally {
      await w.bed.close();
    }
  }, 30_000);

  it('takes no cover at all unless it was set up to', async () => {
    const w = await world({ cover: {}, acceptCover: {} });
    try {
      expect((await post(w.bed.url('beta.test'), signed(w.bed.domainKey('alpha.test'), 'alpha.test'))).status).toBe(404);
    } finally {
      await w.bed.close();
    }
  }, 30_000);
});
