import { createServer } from 'node:net';
import type { KeyPair, SignetEvent } from '@signet/lib';
import { Identity, SignetClient, StaticResolver, domainAuthHeaders, generateGatewayKey, generateSigningKey, generateVrfKey } from '@signet/lib';
import type { ClusterMember } from '../cluster';
import { ClusterWitness } from '../witness';
import { TransparencyLogServer } from '../log-server';
import { SignetServer } from '../server';

const T = 300;
const kinds = (events: SignetEvent[]) => events.map((event) => event.kind);

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
    if (Date.now() > deadline) throw new Error('timed out waiting for the cluster');
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

/** alpha.test runs two homes and a witness; beta.test is an ordinary single home that talks to it. */
async function world() {
  const urls = new Map<string, string | string[]>();
  const resolver = new StaticResolver(urls);
  const logServer = new TransparencyLogServer(generateSigningKey(), resolver);
  await logServer.listen();
  const log = { url: logServer.url, key: logServer.publicKey };

  const ports = { h1: await freePort(), h2: await freePort(), w: await freePort() };
  const members: ClusterMember[] = [
    { id: 'h1', url: `http://127.0.0.1:${ports.h1}`, role: 'home' },
    { id: 'h2', url: `http://127.0.0.1:${ports.h2}`, role: 'home' },
    { id: 'w', url: `http://127.0.0.1:${ports.w}`, role: 'witness' },
  ];
  const alphaKey = generateSigningKey();
  const shared = { vrfKey: generateVrfKey(), gatewayKey: generateGatewayKey() };
  const home = (id: string) =>
    new SignetServer({
      domain: 'alpha.test',
      domainKey: alphaKey,
      resolver,
      log,
      openEnrollment: true,
      ...shared,
      cluster: { id, members, electionMs: T, volatileLog: true },
    });
  const homes = { h1: home('h1'), h2: home('h2') };
  const witness = new ClusterWitness({ domain: 'alpha.test', domainKey: alphaKey, id: 'w', members, electionMs: T, volatileLog: true });
  await homes.h1.listen(ports.h1);
  await homes.h2.listen(ports.h2);
  await witness.listen(ports.w);
  urls.set('alpha.test', [members[0].url, members[1].url]);

  const beta = new SignetServer({ domain: 'beta.test', domainKey: generateSigningKey(), resolver, log, retryDelaysMs: [150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150], openEnrollment: true });
  urls.set('beta.test', await beta.listen());

  const alice = Identity.create('alice@alpha.test');
  const aliceKeys = alice.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] });
  const jerzy = Identity.create('jerzy@beta.test');
  const jerzyKeys = jerzy.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] });

  const primary = (): SignetServer => Object.values(homes).find((server) => server.isPrimary()) as SignetServer;
  await until(() => primary() !== undefined);
  await primary().enroll(alice.publication());
  await beta.enroll(jerzy.publication());

  const trustedLogs = [log];
  const aliceClient = new SignetClient(aliceKeys, resolver, { trustedLogs, keyPackageTarget: 3 });
  const jerzyClient = new SignetClient(jerzyKeys, resolver, { trustedLogs, keyPackageTarget: 3 });
  await aliceClient.ready();
  await jerzyClient.ready();

  return {
    homes,
    members,
    witness,
    beta,
    alphaKey,
    primary,
    aliceClient,
    jerzyClient,
    standby: () => Object.values(homes).find((server) => !server.isPrimary()) as SignetServer,
    close: async () => {
      await Promise.all([homes.h1.close(), homes.h2.close(), witness.close(), beta.close(), logServer.close()].map((closing) => closing.catch(() => undefined)));
    },
  };
}

describe('a domain with two homes and a witness', () => {
  let w: Awaited<ReturnType<typeof world>>;
  beforeEach(async () => {
    w = await world();
  });
  afterEach(async () => {
    await w.close();
  });

  it('has one primary; the standby copies its state and sends callers to the primary', async () => {
    await until(() => w.standby().store.hasUser('alice'));
    const primary = w.primary();
    const standby = w.standby();
    const primaryMember = w.members.find((member) => member.id === (primary === w.homes.h1 ? 'h1' : 'h2')) as ClusterMember;

    const refused = await fetch(`${standby.url}/v0/mailbox?after=0`);
    expect(refused.status).toBe(421);
    expect(refused.headers.get('signet-primary')).toBe(primaryMember.url);

    const policy = (await (await fetch(`${standby.url}/.well-known/signet.json`)).json()) as { server: string; homes: string[] };
    expect(policy.homes).toEqual([w.members[0].url, w.members[1].url]);
    expect(policy.server).toBe(policy.homes[0]);

    const answered = await fetch(`${primary.url}/.well-known/signet.json`);
    expect(answered.status).toBe(200);
    expect(await fetch(`${w.witness.url}/.well-known/signet.json`).then((response) => response.status)).toBe(404);
  });

  it('answers a cluster call only when it is signed with the domain key by a member', async () => {
    const body = JSON.stringify({ term: 1, candidate: 'h2', lastIndex: 0, lastTerm: 0 });
    const call = (key: KeyPair, candidate = 'h2') => {
      const payload = JSON.stringify({ term: 1, candidate, lastIndex: 0, lastTerm: 0 });
      return fetch(`${w.witness.url}/v0/cluster/vote`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...domainAuthHeaders('alpha.test', key, 'POST', '/v0/cluster/vote', payload) },
        body: payload,
      });
    };
    expect(body).toContain('candidate');
    expect((await call(generateSigningKey())).status).toBe(401);
    expect((await call(w.alphaKey, 'intruder')).status).toBe(403);
    expect((await fetch(`${w.witness.url}/v0/cluster/vote`, { method: 'POST', body })).status).toBeGreaterThanOrEqual(400);
  });

  it('keeps delivering, with the same mailbox, after the primary dies', async () => {
    const { jerzyClient, aliceClient } = w;
    await jerzyClient.sendRequest('alice@alpha.test', { subject: 'First', intent: { name: 'schedule.propose', args: { durationMin: 30 } } });
    expect(kinds(await aliceClient.sync())).toEqual(['request']);
    await until(() => w.standby().store.mailbox('alice').length === 1);

    const dead = w.primary();
    const survivor = w.standby();
    await dead.close();
    await until(() => survivor.isPrimary());

    await jerzyClient.sendRequest('alice@alpha.test', { subject: 'Second', intent: { name: 'schedule.propose', args: { durationMin: 45 } } });
    // beta's first attempt may find no primary yet; its retries land the delivery.
    await until(() => survivor.store.mailbox('alice').length === 2);
    const events = await aliceClient.sync();
    expect(kinds(events)).toEqual(['request']);
    expect(events[0].kind === 'request' && events[0].request.body.subject).toBe('Second');
    expect(survivor.store.mailbox('alice').map((item) => item.seq)).toEqual([1, 2]);
  });

  it('does not acknowledge a change it could not commit, and forgets it', async () => {
    const primary = w.primary();
    const others = [w.standby(), w.witness];
    await Promise.all(others.map((other) => other.close()));
    const stranger = Identity.create('stranger@alpha.test');
    stranger.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send'] });
    const response = await fetch(`${primary.url}/v0/enroll`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(stranger.publication()) });
    expect(response.status).toBe(503);
    expect(primary.isPrimary()).toBe(false);
    expect(primary.store.hasUser('stranger')).toBe(false);
    expect(primary.store.hasUser('alice')).toBe(true);
  });
});
