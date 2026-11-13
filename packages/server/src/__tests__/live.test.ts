import type { SignetClient, SignetEvent, SignedMessage } from '@signet/lib';
import { Identity, LiveGateway, LiveSession } from '@signet/lib';
import { Testbed } from '../testbed';

const offerIn = (events: SignetEvent[]): SignedMessage => {
  const event = events.find((e) => e.kind === 'message' && e.message.body.intents.some((i) => i.name === 'session.offer'));
  if (event?.kind !== 'message') throw new Error(`expected a live-session offer, got ${events.map((e) => (e.kind === 'error' ? e.error : e.kind)).join(", ")}`);
  return event.message;
};

async function world() {
  const bed = await Testbed.start(['alpha.test', 'beta.test']);
  const alice = Identity.create('alice@alpha.test');
  const jerzy = Identity.create('jerzy@beta.test');
  const desk = bed.client(alice.enrollClient({ kind: 'agent', label: 'Desk', scopes: ['read:*', 'send', 'admit', 'intent:session.*'] }));
  const jerzyPhoneKeys = jerzy.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] });
  const jerzyPhone = bed.client(jerzyPhoneKeys);
  const jerzyLaptopKeys = jerzy.enrollClient({ kind: 'device', label: 'Laptop', scopes: ['read:*', 'send', 'admit'] });
  const jerzyLaptop = bed.client(jerzyLaptopKeys);
  const clerkKeys = jerzy.enrollClient({ kind: 'agent', label: 'Clerk', scopes: ['read:*', 'send', 'admit', 'intent:schedule.*'] });
  const clerk = bed.client(clerkKeys);
  jerzy.setIntake({ clientId: clerkKeys.cert.clientId, intents: ['schedule.*'], exclusive: true });
  await bed.publish(alice);
  await bed.publish(jerzy);
  for (const client of [desk, jerzyPhone, jerzyLaptop, clerk]) await client.ready();

  await desk.sendRequest('jerzy@beta.test', { subject: 'Scheduling' });
  const [incoming] = await clerk.sync();
  if (incoming?.kind !== 'request') throw new Error('expected a request');
  const thread = await clerk.accept(incoming.request);
  for (const client of [desk, jerzyPhone, jerzyLaptop]) await client.sync();

  const turns: string[] = [];
  const gateway = new LiveGateway(
    { name: 'Desk', description: "Alice's scheduling agent", version: '0.1.0', capabilities: {}, defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'], skills: [] },
    (sessionId, token) => desk.authorizeLive(sessionId, token),
    ({ thread: on, text }) => {
      turns.push(`${on}: ${text}`);
      return `Desk heard: ${text}`;
    },
  );
  await gateway.listen();
  return { bed, gateway, turns, thread, desk, jerzyPhone, jerzyLaptop, clerk, jerzy, jerzyLaptopKeys };
}

describe('escalating a thread to a live A2A session', () => {
  let w: Awaited<ReturnType<typeof world>>;

  beforeEach(async () => {
    w = await world();
  });

  afterEach(async () => {
    await w.gateway.close();
    await w.bed.close();
  });

  const join = async (guest: SignetClient) => {
    const { sessionId } = await w.desk.offerLiveSession(w.thread, w.gateway.card);
    const offer = offerIn(await guest.sync());
    return { sessionId, offer, live: await guest.joinLiveSession(w.thread, offer) };
  };

  it('offers the session inside the thread and authenticates with a token both sides derive', async () => {
    const { live } = await join(w.clerk);

    await expect(live.send('Tuesday 3pm?')).resolves.toBe('Desk heard: Tuesday 3pm?');
    expect(w.turns).toEqual([`${w.thread}: Tuesday 3pm?`]);
    expect(w.desk.liveToken(w.thread, live.sessionId)).toBe(w.clerk.liveToken(w.thread, live.sessionId));
  });

  it('refuses a caller without the thread-derived token', async () => {
    const { sessionId } = await join(w.clerk);

    const outsider = new LiveSession(w.gateway.url, sessionId, Buffer.alloc(32).toString('base64url'));
    await expect(outsider.send('hello')).rejects.toThrow('401');
    const wrongSession = new LiveSession(w.gateway.url, 's_unknown', w.clerk.liveToken(w.thread, sessionId));
    await expect(wrongSession.send('hello')).rejects.toThrow('401');
  });

  it("won't join when the agent card doesn't match the hash in the offer", async () => {
    await w.desk.offerLiveSession(w.thread, { ...w.gateway.card, name: 'Someone else' });

    await expect(w.clerk.joinLiveSession(w.thread, offerIn(await w.clerk.sync()))).rejects.toThrow('agent card does not match');
  });

  it('ends the session when the thread is rekeyed, and a fresh join works at the new epoch', async () => {
    const { offer, live } = await join(w.clerk);
    await live.send('first');

    w.jerzy.revoke(w.jerzyLaptopKeys.cert.clientId);
    await w.bed.publish(w.jerzy);
    expect((await w.desk.rekey(w.thread)).removed.map((m) => m.clientId)).toEqual([w.jerzyLaptopKeys.cert.clientId]);
    await w.clerk.sync();

    await expect(live.send('second')).rejects.toThrow('401');
    const again = await w.clerk.joinLiveSession(w.thread, offer);
    await expect(again.send('second')).resolves.toBe('Desk heard: second');
  });

  it('ends the session when the host says so in the thread', async () => {
    const { sessionId, live } = await join(w.clerk);

    await w.desk.endLiveSession(sessionId, 'done');

    await expect(live.send('still there?')).rejects.toThrow('401');
    expect((await w.clerk.sync()).some((e) => e.kind === 'message' && e.message.body.intents[0]?.name === 'session.end')).toBe(true);
  });

  it("routes handoff.human to the owner's devices, ends live sessions, and holds agents until a human replies", async () => {
    const { live } = await join(w.clerk);

    await w.clerk.send(w.thread, { subject: 'Over to Jerzy', text: 'This needs a decision', intents: [{ name: 'handoff.human', args: { reason: 'fee negotiation' } }] });

    await expect(w.clerk.send(w.thread, { subject: 'Hi', text: 'Me again' })).rejects.toThrow('handed to a human');
    expect(await w.jerzyPhone.sync()).toMatchObject(expect.arrayContaining([{ kind: 'handoff', thread: w.thread, by: 'jerzy@beta.test', reason: 'fee negotiation' }]));
    await w.desk.sync();
    await expect(live.send('anyone?')).rejects.toThrow('401');
    // The other side's agent isn't held: the handoff was to Jerzy, not to Alice.
    await expect(w.desk.send(w.thread, { subject: 'Noted', text: 'Waiting for Jerzy' })).resolves.toBeDefined();

    await w.jerzyPhone.send(w.thread, { subject: 'Re: fee', text: "I'll take it from here" });
    await w.clerk.sync();
    expect(w.clerk.needsHuman(w.thread)).toBeUndefined();
    await expect(w.clerk.send(w.thread, { subject: 'Hi', text: 'Booking the call' })).resolves.toBeDefined();
  });

  it("makes receivers reject an agent's message in a thread its account handed off, even when the agent ignores the hold", async () => {
    await w.clerk.send(w.thread, { subject: 'Over to Jerzy', text: 'This needs a decision', intents: [{ name: 'handoff.human', args: { reason: 'fee negotiation' } }] });
    expect((await w.desk.sync()).map((event) => event.kind)).toContain('message');
    // The clerk forgets the hold, as a misbehaving agent might; the other side still holds it.
    (w.clerk as unknown as { state: { needsHuman: Record<string, unknown> } }).state.needsHuman = {};
    await w.clerk.send(w.thread, { subject: 'Hi', text: 'Me again' });
    const events = await w.desk.sync();
    expect(events.map((event) => event.kind)).toEqual(['error']);
    expect(events[0].kind === 'error' && events[0].error).toContain('handed this thread to a human');
    // Handing off again is still allowed, and a human's message ends the hold.
    await w.clerk.send(w.thread, { subject: 'Still here', text: 'Still needs you', intents: [{ name: 'handoff.human', args: { reason: 'still waiting' } }] });
    expect((await w.desk.sync()).map((event) => event.kind)).toEqual(['message']);
  });
});
