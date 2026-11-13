import { createServer } from 'node:net';
import type { SignetEvent } from '@signet/lib';
import {
  Identity,
  SignetClient,
  StaticResolver,
  clientAuthHeaders,
  encodeKeyConfig,
  generateGatewayKey,
  generateSigningKey,
  generateVrfKey,
  homeAuthHeaders,
  parseSignetHeader,
  signOperators,
  signOrgClaim,
  verifyAttestation,
} from '@signet/lib';
import { TransparencyLogServer } from '../log-server';
import { HttpRegistrar, LocalRegistrar, RegistrarServer } from '../registrar';
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
  // A dropping home says it accepted a delivery and keeps nothing.
  const dropping = new Set<string>();
  const gate = ((input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    const delivery = url.pathname.startsWith('/v0/deliver');
    if (dropping.has(url.origin) && delivery) return Promise.resolve(new Response(JSON.stringify({ unknown: [], rejected: [], queued: [] }), { status: 200 }));
    const down = blocked.has(url.origin) || (deliveryBlocked.has(url.origin) && delivery);
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
  // The owner runs the registrar as its own service; the homes only call it.
  const registrarLogic = new LocalRegistrar({ domain: DOMAIN, domainKey: owner, log, vrfKey });
  const registrarServer = new RegistrarServer({ domain: DOMAIN, registrar: registrarLogic, operators, domainPublicKey: owner.publicKey });
  await registrarServer.listen();
  const registrarFor = (i: number) => new HttpRegistrar({ url: registrarServer.url, domain: DOMAIN, homeKey: homeKeys[i] });
  const home = (i: number) =>
    new SignetServer({
      domain: DOMAIN,
      homeKey: homeKeys[i],
      operators,
      domainPublicKey: owner.publicKey,
      registrar: registrarFor(i),
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
  // The owner approves each address and enrolls it at every home.
  registrarServer.approve(`alice@${DOMAIN}`);
  registrarServer.approve(`bob@${DOMAIN}`);
  for (const server of homes) {
    await server.enroll(alice.publication());
    await server.enroll(bob.publication());
  }
  await beta.enroll(jerzy.publication());

  const trustedLogs = [log];
  const make = (keys: typeof aliceKeys, extra: Partial<ConstructorParameters<typeof SignetClient>[2]> = {}) =>
    new SignetClient(keys, resolver, { trustedLogs, keyPackageTarget: 3, fetchImpl: gate, ...extra });
  const clients = { alice: make(aliceKeys), bob: make(bobKeys), jerzy: make(jerzyKeys) };
  await Promise.all(Object.values(clients).map((client) => client.ready()));

  const has = (server: SignetServer, local: string) => server.store.mailbox(local).length;
  return {
    homes,
    homeUrls,
    homeKeys,
    beta,
    relay,
    make,
    dropping,
    blocked,
    deliveryBlocked,
    owner,
    log,
    aliceKeys,
    registrarServer,
    registrarFor,
    registrar: registrarLogic,
    operators,
    clients,
    has,
    close: async () => {
      await Promise.all([...homes, beta].map((server) => server.close().catch(() => undefined)));
      await relay.close();
      await registrarServer.close();
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

  it('repeats a registration a home missed, so it takes sealed mail again', async () => {
    await w.clients.jerzy.sendRequest(`alice@${DOMAIN}`, { subject: 'Thread', intent: { name: 'schedule.propose', args: { durationMin: 30 } } });
    const [incoming] = await w.clients.alice.sync();
    if (incoming?.kind !== 'request') throw new Error('expected a request');
    // Alice joins a thread while the third operator is down: it never hears of her delivery token.
    w.blocked.add(w.homeUrls[2]);
    const thread = await w.clients.alice.accept(incoming.request);
    w.blocked.delete(w.homeUrls[2]);
    await w.clients.alice.sync();
    await w.clients.jerzy.sync();
    const before = w.has(w.homes[2], 'alice');
    await w.clients.jerzy.send(thread, { subject: 'Thread', text: 'Anyone there?' });
    // Without the repeat, the third home would park the message instead of keeping it in her mailbox.
    await until(() => w.has(w.homes[2], 'alice') === before + 1);
  });

  it('tells the client when one operator says it took mail but kept nothing', async () => {
    w.dropping.add(w.homeUrls[1]);
    await w.clients.jerzy.sendRequest(`alice@${DOMAIN}`, { subject: 'Dropped', intent: { name: 'schedule.propose', args: { durationMin: 30 } } });
    const watching = w.make(w.aliceKeys, { homeGraceMs: 50, snapshot: w.clients.alice.snapshot() });
    expect(kinds(await watching.sync())).toEqual(['request']);
    await new Promise((resolve) => setTimeout(resolve, 120));
    const events = await watching.sync();
    expect(events).toEqual([{ kind: 'home-missing', home: w.homeUrls[1], itemId: expect.any(String) }]);
    expect(await watching.sync()).toEqual([]);
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

  it('lets a home reach the registrar only as the owner allows', async () => {
    // A home can't create an account the owner didn't approve.
    const stranger = Identity.create(`stranger@${DOMAIN}`);
    stranger.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send'] });
    await expect(w.homes[0].enroll(stranger.publication())).rejects.toThrow('not been approved');

    // Nor swap in a different log for an address the registrar has bound.
    const impostor = Identity.create(`alice@${DOMAIN}`);
    impostor.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send'] });
    await expect(w.registrarFor(0).bind(impostor.publication())).rejects.toThrow('extend');

    // Nor release an address; only the owner does.
    await expect(w.registrarFor(0).unbind(`alice@${DOMAIN}`)).rejects.toThrow('only the domain owner');

    // And a key the owner didn't list isn't a home.
    const unlisted = new HttpRegistrar({ url: w.registrarServer.url, domain: DOMAIN, homeKey: generateSigningKey() });
    await expect(unlisted.unbind(`alice@${DOMAIN}`)).rejects.toThrow('signed by a home the owner listed');
  });

  it('serves only claims the owner signed, and attests mail only for a request the registrar can check', async () => {
    const principal = `alice@${DOMAIN}`;
    // A home without the domain key keeps claims the owner signed, and turns away anything else.
    const claim = signOrgClaim(w.owner, principal, 'team:corporate');
    await expect(w.homes[0].setClaims('alice', ['team:corporate'])).rejects.toThrow('does not hold the domain key');
    await expect(w.homes[0].setClaims('alice', [JSON.stringify(signOrgClaim(generateSigningKey(), principal, 'team:corporate'))])).rejects.toThrow('does not hold the domain key');
    await w.homes[0].setClaims('alice', [JSON.stringify(claim)]);
    const headers = clientAuthHeaders(principal, w.aliceKeys.cert.clientId, w.aliceKeys.signing, 'GET', '/v0/claims', '');
    const served = (await (await fetch(`${w.homes[0].url}/v0/claims`, { headers })).json()) as { claims: unknown[] };
    expect(served.claims).toEqual([claim]);

    // The registrar attests outgoing plain email for a request alice's client signed.
    const to = ['carol@example.com'];
    const header = await w.clients.alice.signetHeader({ to, subject: 'Hello' });
    expect(verifyAttestation(parseSignetHeader(header) as NonNullable<ReturnType<typeof parseSignetHeader>>, { from: principal, to, subject: 'Hello' }, w.owner.publicKey)).toBe(true);

    // A home can't use that proof for different mail, can't use it twice, and can't make one up.
    const proofFor = (subject: string, signer = w.aliceKeys.signing) => {
      const body = JSON.stringify({ to, subject });
      const signed = clientAuthHeaders(principal, w.aliceKeys.cert.clientId, signer, 'POST', '/v0/legacy/attest', body);
      return { method: 'POST', path: '/v0/legacy/attest', body, headers: signed };
    };
    const ask = (subject: string, proof: ReturnType<typeof proofFor>) => w.registrarFor(0).attest({ principal, to, subject, server: w.homeUrls[0], proof });
    await expect(ask('Two', proofFor('One'))).rejects.toThrow('different mail');
    const once = proofFor('Once');
    await ask('Once', once);
    await expect(ask('Once', once)).rejects.toThrow('already used');
    await expect(ask('Fake', proofFor('Fake', generateSigningKey()))).rejects.toThrow('signature');
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
