import { OHTTP_REQUEST_TYPE } from '@signet/lib';
import { RateLimiter } from '../rate-limit';
import { RelayServer } from '../relay-server';

describe('a token bucket by key', () => {
  it('lets a burst through, then the average rate, and says how long to wait', () => {
    let now = 0;
    const limiter = new RateLimiter({ perSecond: 2, burst: 3 }, 100, () => now);
    expect([1, 2, 3].map(() => limiter.take('a'))).toEqual([0, 0, 0]);
    expect(limiter.take('a')).toBe(1);
    expect(limiter.refused).toBe(1);
    now = 500;
    expect(limiter.take('a')).toBe(0);
    expect(limiter.take('a')).toBe(1);
    now = 10_000;
    expect([1, 2, 3, 4].map(() => limiter.take('a'))).toEqual([0, 0, 0, 1]);
  });

  it('keeps keys apart', () => {
    const limiter = new RateLimiter({ perSecond: 1, burst: 1 }, 100, () => 0);
    expect(limiter.take('a')).toBe(0);
    expect(limiter.take('a')).toBeGreaterThan(0);
    expect(limiter.take('b')).toBe(0);
  });

  it('remembers a bounded number of keys, whatever is thrown at it', () => {
    let now = 0;
    const limiter = new RateLimiter({ perSecond: 1, burst: 2 }, 50, () => now);
    for (let i = 0; i < 1000; i += 1) {
      limiter.take(`source-${i}`);
      now += 1;
    }
    expect(limiter.size).toBeLessThanOrEqual(50);
  });

  it('forgets a key that has been quiet long enough to be full again', () => {
    let now = 0;
    const limiter = new RateLimiter({ perSecond: 1, burst: 2 }, 3, () => now);
    limiter.take('old');
    now = 60_000;
    for (const key of ['b', 'c', 'd']) limiter.take(key);
    expect(limiter.size).toBeLessThanOrEqual(3);
  });
});

describe('the reference relay with limits set (Section 10.4.2)', () => {
  /** A relay in front of a gateway that answers anything, on a clock the test sets. */
  async function relay(limits?: ConstructorParameters<typeof RelayServer>[3], now: () => number = Date.now) {
    const forwardedTo: string[] = [];
    const resolver = {
      policy: async (domain: string) => ({ domain, server: `https://${domain}`, ohttp: { gateway: `https://gw.${domain}/v0/ohttp`, keys: '' } }),
    } as never;
    const gateway = async (input: string | URL | Request) => {
      forwardedTo.push(String(input));
      return new Response('ok', { status: 200 });
    };
    const server = new RelayServer(resolver, gateway as typeof fetch, 0, limits, now);
    await server.listen();
    const send = (domain: string) => fetch(`${server.url}/v0/relay?domain=${domain}`, { method: 'POST', headers: { 'content-type': OHTTP_REQUEST_TYPE }, body: 'x' });
    return { server, send, forwardedTo };
  }

  it('forwards without limit unless it was told to limit', async () => {
    const { server, send } = await relay();
    try {
      for (let i = 0; i < 50; i += 1) expect((await send('a.test')).status).toBe(200);
      expect(server.refused).toBe(0);
    } finally {
      await server.close();
    }
  });

  it('refuses a source that sends more than its burst, with 429 and when to come back', async () => {
    const { server, send, forwardedTo } = await relay({ perSource: { perSecond: 1, burst: 5 }, perTarget: { perSecond: 100, burst: 100 }, maxHeld: 100 }, () => 0);
    try {
      const statuses: number[] = [];
      for (let i = 0; i < 8; i += 1) statuses.push((await send('a.test')).status);
      expect(statuses).toEqual([200, 200, 200, 200, 200, 429, 429, 429]);
      const refused = await send('a.test');
      expect(refused.headers.get('retry-after')).toBe('1');
      // Nothing refused reached the gateway.
      expect(forwardedTo).toHaveLength(5);
    } finally {
      await server.close();
    }
  });

  it('refuses a source that sends too much to one domain, and lets it send to another', async () => {
    const { server, send } = await relay({ perSource: { perSecond: 1, burst: 100 }, perTarget: { perSecond: 1, burst: 3 }, maxHeld: 100 }, () => 0);
    try {
      const flood: number[] = [];
      for (let i = 0; i < 5; i += 1) flood.push((await send('victim.test')).status);
      expect(flood).toEqual([200, 200, 200, 429, 429]);
      expect((await send('other.test')).status).toBe(200);
    } finally {
      await server.close();
    }
  });

  it('lets the source back in as time passes', async () => {
    let now = 0;
    const { server, send } = await relay({ perSource: { perSecond: 2, burst: 2 }, perTarget: { perSecond: 100, burst: 100 }, maxHeld: 100 }, () => now);
    try {
      expect([(await send('a.test')).status, (await send('a.test')).status, (await send('a.test')).status]).toEqual([200, 200, 429]);
      now = 1000;
      expect((await send('a.test')).status).toBe(200);
    } finally {
      await server.close();
    }
  });

  it('refuses a request without a domain before it counts against anyone', async () => {
    const { server } = await relay({ perSource: { perSecond: 1, burst: 1 }, perTarget: { perSecond: 1, burst: 1 }, maxHeld: 10 }, () => 0);
    try {
      const response = await fetch(`${server.url}/v0/relay`, { method: 'POST', headers: { 'content-type': OHTTP_REQUEST_TYPE }, body: 'x' });
      expect(response.status).toBe(400);
      expect(server.refused).toBe(0);
    } finally {
      await server.close();
    }
  });
});
