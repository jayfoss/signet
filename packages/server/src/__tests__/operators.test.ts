import { createServer } from 'node:net';
import type { SignetEvent } from '@signet/lib';
import { Identity, SignetClient, StaticResolver, encodeKeyConfig, generateGatewayKey, generateSigningKey, generateVrfKey, homeAuthHeaders, signOperators } from '@signet/lib';
import { TransparencyLogServer } from '../log-server';
import { LocalRegistrar } from '../registrar';
import { RelayServer } from '../relay-server';
import { SignetServer } from '../server';

const DOMAIN = 'multi.test';
const kinds = (events: SignetEvent[]) => events.map((event) => event.kind);
const RETRY = Array.from({ length: 30 }, () => 150);

const freePort = (): Promise<number> =>
  new Promise((resolve) => {
    const probe = createServer();
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address() as { port: number };
      probe.close(() => resolve(port));
    });
  });

async function until(condition: () => boolean, ms = 8000): Promise<void> {
  const deadline = Date.now() + ms;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error('timed out');
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

/**
 * multi.test is run by three operators who each run an independent home. None of them holds the domain key;
 * the test plays the domain owner, who does and runs the registrar. beta.test is an ordinary single home.
 */
async function world() {
  const urls = new Map<string, string | string[]>();
  const owner = generateSigningKey();
  const resolver = new StaticResolver(urls, fetch, new Map([[DOMAIN, owner.publicKey]]));
  const logServer = new TransparencyLogServer(generateSigningKey(), resolver);
  await logServer.listen();
  const log = { url: logServer.url, key: logServer.publicKey };

  // Calls to a blocked origin get a 503, as if that operator were down; a delivery-blocked one refuses only deliveries.
  const blocked = new Set<string>();
  const deliveryBlocked = new Set<string>();
  const gate = ((input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    const down = blocked.has(url.origin) || (deliveryBlocked.has(url.origin) && url.pathname.startsWith('/v0/deliver'));
    return down ? Promise.resolve(new Response('down', { status: 503 })) : fetch(input, init);
  }) as typeof fetch;

  const vrfKey = generateVrfKey();
  const names = ['a', 'b', 'c'] as const;
  const ports = await Promise.all(names.map(() => freePort()));
  const homeKeys = names.map(() => generateSigningKey());
  const homeUrls = ports.map((port) => `http://127.0.0.1:${port}`);
  const gatewayKeys = names.map(() => generateGatewayKey());
  const relay = new RelayServer(resolver);
  await relay.listen();
  // Each home has its own gateway, and the owner's signature vouches for its key.
  const operators = signOperators(owner, {
    domain: DOMAIN,
    seq: 1,
    notAfter: '2099-01-01T00:00:00.000Z',
    homes: homeUrls.map((url, i) => ({ url, key: homeKeys[i].publicKey, ohttp: { gateway: `${url}/v0/ohttp`, keys: encodeKeyConfig(gatewayKeys[i]) } })),
  });
  const registrar = new LocalRegistrar({ domain: DOMAIN, domainKey: owner, log, vrfKey });
  const home = (i: number) =>
    new SignetServer({
      domain: DOMAIN,
      homeKey: homeKeys[i],
      operators,
      domainPublicKey: owner.publicKey,
      registrar,
      resolver,
      log,
      vrfKey,
      gatewayKey: gatewayKeys[i],
      ohttpRelay: relay.url,
      retryDelaysMs: RETRY,
      fetchImpl: gate,
    });
  const homes = names.map((_, i) => home(i));
  await Promise.all(homes.map((server, i) => server.listen(ports[i])));
  urls.set(DOMAIN, homeUrls);

  const beta = new SignetServer({ domain: 'beta.test', domainKey: generateSigningKey(), resolver, log, retryDelaysMs: RETRY, ohttpRelay: relay.url, fetchImpl: gate });
  urls.set('beta.test', await beta.listen());

  const alice = Identity.create(`alice@${DOMAIN}`);
  const aliceKeys = alice.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] });
  const bob = Identity.create(`bob@${DOMAIN}`);
  const bobKeys = bob.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] });
  const jerzy = Identity.create('jerzy@beta.test');
  const jerzyKeys = jerzy.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] });
  // The owner enrolls each address at every home.
  for (const server of homes) {
    await server.enroll(alice.publication());
    await server.enroll(bob.publication());
  }
  await beta.enroll(jerzy.publication());

  const trustedLogs = [log];
  const make = (keys: typeof aliceKeys) => new SignetClient(keys, resolver, { trustedLogs, keyPackageTarget: 3 });
  const clients = { alice: make(aliceKeys), bob: make(bobKeys), jerzy: make(jerzyKeys) };
  await Promise.all(Object.values(clients).map((client) => client.ready()));

  const has = (server: SignetServer, local: string) => server.store.mailbox(local).length;
  return {
    homes,
    homeUrls,
    homeKeys,
    beta,
    relay,
    blocked,
    deliveryBlocked,
    owner,
    log,
    registrar,
    operators,
    clients,
    has,
    close: async () => {
      await Promise.all([...homes, beta].map((server) => server.close().catch(() => undefined)));
      await relay.close();
      await logServer.close();
    },
  };
}

describe('a domain run by three operators who share nothing', () => {
  let w: Awaited<ReturnType<typeof world>>;
  beforeEach(async () => {
    w = await world();
  });
  afterEach(async () => {
    await w.close();
  });

  it('delivers one message to every home and shows the client it once', async () => {
    await w.clients.jerzy.sendRequest(`alice@${DOMAIN}`, { subject: 'Hello', intent: { name: 'schedule.propose', args: { durationMin: 30 } } });
    for (const server of w.homes) expect(w.has(server, 'alice')).toBe(1);
    const ids = new Set(w.homes.map((server) => server.store.mailbox('alice')[0].id));
    expect(ids.size).toBe(1);

    expect(kinds(await w.clients.alice.sync())).toEqual(['request']);
    expect(kinds(await w.clients.alice.sync())).toEqual([]);
  });

  it('keeps the other operators delivering while one is down, and catches the one that was down up', async () => {
    const [down, up1, up2] = w.homes;
    w.blocked.add(w.homeUrls[0]);
    await w.clients.jerzy.sendRequest(`alice@${DOMAIN}`, { subject: 'While A is down', intent: { name: 'schedule.propose', args: { durationMin: 30 } } });
    expect(w.has(up1, 'alice')).toBe(1);
    expect(w.has(up2, 'alice')).toBe(1);
    expect(w.has(down, 'alice')).toBe(0);
    // Alice reads from the two that answer, without waiting for the third.
    expect(kinds(await w.clients.alice.sync())).toEqual(['request']);

    w.blocked.delete(w.homeUrls[0]);
    await until(() => w.has(down, 'alice') === 1);
    // The late copy is the same delivery, so it isn't shown again.
    expect(kinds(await w.clients.alice.sync())).toEqual([]);
  });

  it('queues a delivery when every home is down and delivers it when one returns', async () => {
    for (const url of w.homeUrls) w.deliveryBlocked.add(url);
    await w.clients.jerzy.sendRequest(`alice@${DOMAIN}`, { subject: 'Nobody home', intent: { name: 'schedule.propose', args: { durationMin: 30 } } });
    expect(w.homes.map((server) => w.has(server, 'alice'))).toEqual([0, 0, 0]);
    w.deliveryBlocked.delete(w.homeUrls[2]);
    await until(() => w.has(w.homes[2], 'alice') === 1);
    expect(kinds(await w.clients.alice.sync())).toEqual(['request']);
    w.deliveryBlocked.clear();
    await until(() => w.homes.every((server) => w.has(server, 'alice') === 1));
    expect(kinds(await w.clients.alice.sync())).toEqual([]);
  });

  it('delivers mail between two addresses on the domain to every home, and sends when the first home is down', async () => {
    w.blocked.add(w.homeUrls[0]);
    await w.homes[0].close();
    await w.clients.alice.sendRequest(`bob@${DOMAIN}`, { subject: 'Same domain', intent: { name: 'schedule.propose', args: { durationMin: 15 } } });
    // Submitted through B, because A was down; B delivered to itself and to C.
    await until(() => w.has(w.homes[1], 'bob') === 1 && w.has(w.homes[2], 'bob') === 1);
    expect(kinds(await w.clients.bob.sync())).toEqual(['request']);
  });

  it('sends a sealed message to each home through that home\'s own gateway', async () => {
    await w.clients.jerzy.sendRequest(`alice@${DOMAIN}`, { subject: 'Sealed', intent: { name: 'schedule.propose', args: { durationMin: 30 } } });
    const [incoming] = await w.clients.alice.sync();
    if (incoming?.kind !== 'request') throw new Error('expected a request');
    const thread = await w.clients.alice.accept(incoming.request);
    await w.clients.jerzy.sync();

    const viaGateway = () => w.homes.map((server) => server.receivedViaOhttp);
    const before = viaGateway();
    const forwarded = w.relay.forwarded;
    await w.clients.jerzy.send(thread, { subject: 'Sealed', text: 'Is anyone home?' });
    // One copy to each operator, every one through the relay and that operator's own gateway.
    viaGateway().forEach((count, i) => expect(count).toBeGreaterThan(before[i]));
    expect(w.relay.forwarded - forwarded).toBeGreaterThanOrEqual(3);
    const events = await w.clients.alice.sync();
    expect(events.filter((event) => event.kind === 'message')).toHaveLength(1);
  });

  it('refuses what an operator is not allowed to do', async () => {
    // A key that the owner didn't list can't deliver as the domain.
    const intruder = generateSigningKey();
    const body = JSON.stringify({ id: 'i_forged0001', to: ['jerzy@beta.test'], kind: 'request', from: `alice@${DOMAIN}`, payload: {} });
    const forged = await fetch(`${w.beta.url}/v0/deliver`, { method: 'POST', headers: { 'content-type': 'application/json', ...homeAuthHeaders(DOMAIN, intruder, 'POST', '/v0/deliver', body) }, body });
    expect(forged.status).toBe(401);

    // A listed home is not the domain: the log takes appends signed by the domain key only.
    const leaf = JSON.stringify({ v: 0, index: 'x', domain: DOMAIN, kind: 'bound', identityKey: 'k', cardHash: null, viewHash: null, ts: new Date().toISOString() });
    const append = await fetch(`${w.log.url}/v0/append`, { method: 'POST', headers: { 'content-type': 'application/json', ...homeAuthHeaders(DOMAIN, w.homeKeys[0], 'POST', '/v0/append', leaf) }, body: leaf });
    expect(append.status).toBeGreaterThanOrEqual(400);

    // A home that isn't in the owner's statement won't start.
    expect(
      () =>
        new SignetServer({
          domain: DOMAIN,
          homeKey: generateSigningKey(),
          operators: w.operators,
          domainPublicKey: w.owner.publicKey,
          registrar: w.registrar,
          resolver: new StaticResolver(new Map()),
          log: w.log,
        }),
    ).toThrow('not in the operators statement');
  });
});
