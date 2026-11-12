import type { SignedMessage, SignetClient, SignetEvent } from '@signet/lib';
import { DisclosureError, Identity, generateSigningKey, signOrgClaim } from '@signet/lib';
import { Testbed } from '../testbed';

const FEE = 'Acme agreed a $40,000 fixed fee.';
const messages = (events: SignetEvent[]): SignedMessage[] => events.flatMap((event) => (event.kind === 'message' ? [event.message] : []));
const texts = (events: SignetEvent[]) => messages(events).map((message) => message.body.text);

async function world() {
  const bed = await Testbed.start(['firm.test']);
  const people = ['jerzy', 'mia'].map((local) => Identity.create(`${local}@firm.test`));
  const [jerzy, mia] = people;
  const phone = (identity: Identity) => bed.client(identity.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] }));
  const agent = (identity: Identity) => bed.client(identity.enrollClient({ kind: 'agent', label: 'Assistant', scopes: ['read:*', 'send', 'admit', 'intent:info.*'] }));
  const [jerzyPhone, jerzyAgent, miaPhone, miaAgent] = [phone(jerzy), agent(jerzy), phone(mia), agent(mia)];
  for (const identity of people) await bed.publish(identity);
  const clients = [jerzyPhone, jerzyAgent, miaPhone, miaAgent];
  for (const client of clients) await client.ready();
  // What the firm vouches for: Jerzy works in corporate, but isn't on the Acme matter.
  bed.server('firm.test').setClaims('jerzy', ['team:corporate']);

  const thread = await jerzyAgent.startThread(['mia@firm.test']);
  for (const client of [jerzyPhone, miaPhone, miaAgent]) await client.sync();

  /** Jerzy's agent asks; Mia's agent gets the request with what it can verify about it. */
  const ask = async () => {
    await jerzyAgent.requestInfo(thread, { question: 'What fee did Acme agree to?', purpose: 'Drafting the engagement letter' });
    const [request] = messages(await miaAgent.sync());
    return miaAgent.disclosureContext(thread, request);
  };
  /** Mia's agent escalates; Mia's phone gets the card. */
  const escalate = async () => {
    const context = await ask();
    await miaAgent.escalateInfo(context, FEE);
    const card = messages(await miaPhone.sync()).map((message) => miaPhone.approvalCard(message)).find(Boolean);
    if (!card) throw new Error('no approval card reached the phone');
    return card;
  };
  return { bed, jerzy, thread, jerzyPhone, jerzyAgent, miaPhone, miaAgent, ask, escalate };
}

describe("asking a colleague's agent for something it may not be free to share", () => {
  let w: Awaited<ReturnType<typeof world>>;

  beforeEach(async () => {
    w = await world();
  });

  afterEach(async () => {
    await w.bed.close();
  });

  it('gives the answering agent verified facts: who asks, from what, with which claims, and who would read the answer', async () => {
    const context = await w.ask();

    expect(context).toMatchObject({ requester: 'jerzy@firm.test', requesterKind: 'agent', claims: ['team:corporate'], purpose: 'Drafting the engagement letter' });
    expect(context.audience.map((member) => `${member.principal} ${member.kind}`).sort()).toEqual([
      'jerzy@firm.test agent',
      'jerzy@firm.test device',
      'mia@firm.test agent',
      'mia@firm.test device',
    ]);
  });

  it("escalates to the owner's devices only, who release it to the asker's devices and not their agent", async () => {
    const card = await w.escalate();
    expect(card).toMatchObject({ draft: FEE, requester: 'jerzy@firm.test', claims: ['team:corporate'] });
    // The card never leaves Mia's own clients.
    expect(texts([...(await w.jerzyPhone.sync()), ...(await w.jerzyAgent.sync())]).join(' ')).not.toContain('Approve');

    await w.miaPhone.decideApproval(card, { release: 'requester-only' });

    expect(texts(await w.jerzyAgent.sync())).not.toContain(FEE);
    const atPhone = messages(await w.jerzyPhone.sync()).find((message) => message.body.text === FEE);
    expect(atPhone?.body).toMatchObject({ audience: 'humans', inReplyTo: card.requestId, intents: [{ name: 'info.answer', args: { decision: 'answered' } }] });
  });

  it('refuses to release to the thread if anyone joined after the owner saw the audience', async () => {
    const card = await w.escalate();
    const intern = w.bed.client(w.jerzy.enrollClient({ kind: 'agent', label: 'Intern bot', scopes: ['read:*'] }));
    await w.bed.publish(w.jerzy);
    await intern.ready();
    expect((await w.jerzyPhone.rekey(w.thread)).added).toHaveLength(1);
    await w.miaPhone.sync();

    await expect(w.miaPhone.decideApproval(card, { release: 'thread' })).rejects.toThrow("jerzy@firm.test (agent) joined. Approve again");
  });

  it('releases a narrower answer to the whole thread, bound to the audience the owner approved', async () => {
    const card = await w.escalate();

    const sent = await w.miaPhone.decideApproval(card, { release: 'thread', text: 'Yes, the fee is fixed.' });

    expect(sent.body.intents[0].args).toEqual({ requestId: card.requestId, decision: 'narrowed', approvedFor: card.audienceHash });
    expect(texts(await w.jerzyAgent.sync())).toEqual(['Yes, the fee is fixed.']);
  });

  it("answers directly when the firm's signed claims already allow it, and drops forged ones", async () => {
    w.bed.server('firm.test').setClaims('jerzy', ['team:corporate', 'matter:acme']);
    const allowed = await w.ask();
    expect(allowed.claims).toContain('matter:acme');
    await w.miaAgent.answerInfo(allowed, FEE);
    expect(texts(await w.jerzyAgent.sync())).toContain(FEE);

    const forged = signOrgClaim(generateSigningKey(), 'jerzy@firm.test', 'matter:everything');
    await w.jerzyAgent.send(w.thread, { subject: 'Request', text: 'And the board minutes?', intents: [{ name: 'info.request', args: { question: 'And the board minutes?', claims: [forged] } }] });
    const [request] = messages(await w.miaAgent.sync());
    expect((await w.miaAgent.disclosureContext(w.thread, request)).claims).toEqual([]);
  });

  it('lets the owner refuse, and only a device can decide', async () => {
    const card = await w.escalate();
    await expect(w.miaAgent.decideApproval(card, { release: 'thread' })).rejects.toThrow(DisclosureError);

    await w.miaPhone.decideApproval(card, { release: 'refuse', reason: 'Not something I can share outside the Acme team.' });

    const [answer] = messages(await w.jerzyAgent.sync());
    expect(answer.body.intents[0].args).toMatchObject({ decision: 'refused', reason: 'Not something I can share outside the Acme team.' });
  });
});

export type { SignetClient };
