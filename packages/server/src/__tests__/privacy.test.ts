import { Identity, randomToken } from '@signet/lib';
import { Testbed } from '../testbed';

async function world(limits = {}) {
  const bed = await Testbed.start(['alpha.test', 'beta.test'], { limits });
  const alice = Identity.create('alice@alpha.test');
  const jerzy = Identity.create('jerzy@beta.test');
  const alicePhone = bed.client(alice.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] }));
  const jerzyPhone = bed.client(jerzy.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] }));
  await bed.publish(alice);
  await bed.publish(jerzy);
  await alicePhone.ready();
  await jerzyPhone.ready();
  return { bed, alicePhone, jerzyPhone };
}

describe('sealed sender', () => {
  it("keeps thread traffic from naming its sender to the recipient's server", async () => {
    const { bed, alicePhone, jerzyPhone } = await world();
    try {
      await alicePhone.sendRequest('jerzy@beta.test', { subject: 'Hello' });
      const [incoming] = await jerzyPhone.sync();
      if (incoming?.kind !== 'request') throw new Error('expected a request');
      const thread = await jerzyPhone.accept(incoming.request);
      await jerzyPhone.send(thread, { subject: 'Hello', text: 'Welcome' });
      expect((await alicePhone.sync()).map((event) => event.kind)).toEqual(['joined', 'message']);
      await alicePhone.send(thread, { subject: 'Hello', text: 'Thanks' });
      expect((await jerzyPhone.sync()).map((event) => event.kind)).toEqual(['message']);

      const atBeta = bed.server('beta.test').store.mailbox('jerzy');
      const atAlpha = bed.server('alpha.test').store.mailbox('alice');
      const threadItems = [...atBeta, ...atAlpha].filter((item) => item.kind !== 'request');
      expect(threadItems.length).toBeGreaterThanOrEqual(3);
      expect(threadItems.every((item) => item.from === '' && item.sealed === true)).toBe(true);
      expect(new Set(threadItems.map((item) => item.kind))).toEqual(new Set(['welcome', 'message']));
      expect(JSON.stringify(atBeta.filter((item) => item.kind !== 'request'))).not.toContain('alice@alpha.test');
      expect(JSON.stringify(atAlpha)).not.toContain('jerzy@beta.test');
    } finally {
      await bed.close();
    }
  });

  it('holds a delivery with an unknown token instead of putting it in the mailbox', async () => {
    const { bed } = await world();
    try {
      const response = await fetch(`${bed.server('beta.test').url}/v0/deliver-sealed`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ id: 'i_x', to: ['jerzy@beta.test'], kind: 'message', payload: { thread: 't_x', mls: 'x' }, token: randomToken() }),
      });
      expect(response.ok).toBe(true);
      expect(bed.server('beta.test').store.mailbox('jerzy')).toEqual([]);

      const request = await fetch(`${bed.server('beta.test').url}/v0/deliver-sealed`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ id: 'i_y', to: ['jerzy@beta.test'], kind: 'request', payload: {}, token: randomToken() }),
      });
      expect(request.status).toBe(400);
    } finally {
      await bed.close();
    }
  });
});

describe('anonymous requests (Privacy Pass over Oblivious HTTP)', () => {
  it('reaches the recipient with no sender on the envelope, through the relay', async () => {
    const { bed, alicePhone, jerzyPhone } = await world();
    try {
      await alicePhone.sendRequest('jerzy@beta.test', { subject: 'Hello', note: 'Sam suggested we talk' });

      const [stored] = bed.server('beta.test').store.mailbox('jerzy');
      expect(stored).toMatchObject({ kind: 'request', from: '', sealed: true });
      expect(JSON.stringify(stored)).not.toContain('alice@alpha.test');
      expect(bed.relay.forwarded).toBe(1);
      expect(bed.server('beta.test').receivedViaOhttp).toBe(1);

      const [incoming] = await jerzyPhone.sync();
      expect(incoming).toMatchObject({ kind: 'request', request: { body: { from: 'alice@alpha.test', note: 'Sam suggested we talk' } } });
    } finally {
      await bed.close();
    }
  });

  it('lets the reply thread be sealed too, so neither request nor thread names Alice to beta.test', async () => {
    const { bed, alicePhone, jerzyPhone } = await world();
    try {
      await alicePhone.sendRequest('jerzy@beta.test', { subject: 'Hello' });
      const [incoming] = await jerzyPhone.sync();
      if (incoming?.kind !== 'request') throw new Error('expected a request');
      const thread = await jerzyPhone.accept(incoming.request);
      await jerzyPhone.send(thread, { subject: 'Hello', text: 'Welcome' });
      await alicePhone.sync();
      await alicePhone.send(thread, { subject: 'Hello', text: 'Thanks' });
      expect((await jerzyPhone.sync()).map((event) => event.kind)).toEqual(['message']);

      expect(JSON.stringify(bed.server('beta.test').store.mailbox('jerzy'))).not.toContain('alice@alpha.test');
      expect(bed.server('beta.test').receivedViaOhttp).toBeGreaterThanOrEqual(2);
    } finally {
      await bed.close();
    }
  });

  it('caps tokens per user and rejects forged tokens', async () => {
    const { bed, alicePhone } = await world({ tokensPerUserPerDay: 2 });
    try {
      await alicePhone.sendRequest('jerzy@beta.test', { subject: 'One' });
      await alicePhone.sendRequest('jerzy@beta.test', { subject: 'Two' });
      await expect(alicePhone.sendRequest('jerzy@beta.test', { subject: 'Three' })).rejects.toThrow('429');

      const [first] = bed.server('beta.test').store.mailbox('jerzy');
      const replay = await fetch(`${bed.server('beta.test').url}/v0/deliver-anonymous`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ id: 'i_replay', to: ['jerzy@beta.test'], kind: 'request', payload: first.payload, anonymousToken: 'AAI' + 'A'.repeat(400) }),
      });
      expect(replay.status).toBe(403);
    } finally {
      await bed.close();
    }
  });

  it("accepts a token once, and only for the recipient's own domain", async () => {
    const { bed } = await world();
    try {
      const { blindTokenRequest, blindSign, finalizeToken } = await import('@signet/lib');
      const pending = blindTokenRequest(bed.issuer.publicKey, 'alpha.test');
      const token = finalizeToken(pending, blindSign(bed.issuer.key, pending.blinded));
      const deliver = (anonymousToken: string, id: string) =>
        fetch(`${bed.server('beta.test').url}/v0/deliver-anonymous`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ id, to: ['jerzy@beta.test'], kind: 'request', payload: { to: 'jerzy@beta.test', copies: [] }, anonymousToken }),
        });

      expect((await deliver(token, 'i_1')).status).toBe(403);
      const forBeta = blindTokenRequest(bed.issuer.publicKey, 'beta.test');
      const good = finalizeToken(forBeta, blindSign(bed.issuer.key, forBeta.blinded));
      expect((await deliver(good, 'i_2')).status).toBe(200);
      expect((await deliver(good, 'i_3')).status).toBe(403);
    } finally {
      await bed.close();
    }
  });
});

describe('lookup and claim limits', () => {
  it('rate-limits lookups per requesting user, through their own server', async () => {
    const { bed, alicePhone } = await world({ lookupsPerRequesterPerDay: 3 });
    try {
      for (let i = 0; i < 3; i += 1) await alicePhone.lookup('jerzy@beta.test');
      await expect(alicePhone.lookup('jerzy@beta.test')).rejects.toThrow('429');
    } finally {
      await bed.close();
    }
  });

  it('charges a lookup that finds nobody ten times as much as one that finds someone', async () => {
    const { bed, alicePhone } = await world({ lookupsPerRequesterPerDay: 30 });
    try {
      for (const nobody of ['a', 'b', 'c']) await expect(alicePhone.lookup(`${nobody}@beta.test`)).resolves.toBeNull();
      await expect(alicePhone.lookup('jerzy@beta.test')).rejects.toThrow('429');
    } finally {
      await bed.close();
    }
  });

  it('cuts off a domain whose lookups mostly find nobody', async () => {
    const { bed, alicePhone } = await world({ missWeight: 1, missRatioAfter: 4 });
    try {
      for (const nobody of ['a', 'b', 'c']) await alicePhone.lookup(`${nobody}@beta.test`);
      await alicePhone.lookup('jerzy@beta.test');
      await expect(alicePhone.lookup('jerzy@beta.test')).rejects.toThrow('mostly find nobody');
    } finally {
      await bed.close();
    }
  });

  it('gives anonymous directory reads only a small per-IP budget', async () => {
    const { bed } = await world({ anonymousLookupsPerIpPerDay: 2 });
    try {
      const url = `${bed.server('beta.test').url}/v0/directory/jerzy`;
      expect((await fetch(url)).status).toBe(200);
      expect((await fetch(url)).status).toBe(200);
      expect((await fetch(url)).status).toBe(429);
    } finally {
      await bed.close();
    }
  });

  it('answers unknown and unenrolled addresses identically', async () => {
    const { bed } = await world();
    try {
      const nobody = (await (await fetch(`${bed.server('beta.test').url}/v0/directory/nobody`)).json()) as Record<string, unknown>;
      expect(Object.keys(nobody).sort()).toEqual(['principal', 'sig', 'status', 'ts', 'vrf']);
      expect(nobody.status).toBe('not-enrolled');
    } finally {
      await bed.close();
    }
  });

  it('only hands key packages to authenticated servers', async () => {
    const { bed } = await world();
    try {
      const response = await fetch(`${bed.server('beta.test').url}/v0/directory/jerzy/claim`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ clients: ['anything'] }),
      });
      expect(response.status).toBe(401);
    } finally {
      await bed.close();
    }
  });

  it('keeps working after the one-time key packages run out, using the last-resort package', async () => {
    const { bed, alicePhone, jerzyPhone } = await world();
    try {
      await alicePhone.sendRequest('jerzy@beta.test', { subject: 'Hello' });
      const [incoming] = await jerzyPhone.sync();
      if (incoming?.kind !== 'request') throw new Error('expected a request');
      await jerzyPhone.accept(incoming.request);
      await alicePhone.sync();
      const threads: string[] = [];
      for (let i = 0; i < 6; i += 1) threads.push(await alicePhone.startThread(['jerzy@beta.test']));
      const joined = (await jerzyPhone.sync()).filter((event) => event.kind === 'joined');
      expect(joined).toHaveLength(6);
      expect(new Set(threads).size).toBe(6);
    } finally {
      await bed.close();
    }
  });

  it('requires a Signet server or a small per-IP budget for per-address log queries', async () => {
    const { bed } = await world();
    try {
      const url = `${bed.trustedLog.url}/v0/latest?key=anything`;
      for (let i = 0; i < 20; i += 1) expect((await fetch(url)).status).toBe(200);
      expect((await fetch(url)).status).toBe(429);
      expect((await fetch(`${bed.trustedLog.url}/v0/tree-head`)).status).toBe(200);
    } finally {
      await bed.close();
    }
  });
});
