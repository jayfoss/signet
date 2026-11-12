/* eslint-disable no-console */
/**
 * Jerzy's agent needs a fact only his colleague Mia has. Her agent can't tell whether Jerzy may see it,
 * so it asks Mia, on her phone, showing exactly who would read the answer. Mia releases it to Jerzy's
 * phone only; his agent never sees it. A second time, someone joins the thread before Mia decides, and
 * her phone refuses to send until she looks again.
 *
 *   pnpm disclosure-demo
 */
import type { ApprovalCard, SignedMessage, SignetClient, SignetEvent } from '@signet/lib';
import { Identity } from '@signet/lib';
import { Testbed } from '../src/testbed';

const step = (title: string) => console.log(`\n== ${title}`);
const note = (text: string) => console.log(`   ${text}`);
const messages = (events: SignetEvent[]): SignedMessage[] => events.flatMap((event) => (event.kind === 'message' ? [event.message] : []));

async function main(): Promise<void> {
  const bed = await Testbed.start(['firm.test']);
  try {
    const jerzy = Identity.create('jerzy@firm.test');
    const mia = Identity.create('mia@firm.test');
    const phone = (identity: Identity) => bed.client(identity.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] }));
    const agent = (identity: Identity) => bed.client(identity.enrollClient({ kind: 'agent', label: 'Assistant', scopes: ['read:*', 'send', 'admit', 'intent:info.*'] }));
    const jerzyPhone = phone(jerzy);
    const jerzyAgent = agent(jerzy);
    const miaPhone = phone(mia);
    const miaAgent = agent(mia);
    await bed.publish(jerzy);
    await bed.publish(mia);
    for (const client of [jerzyPhone, jerzyAgent, miaPhone, miaAgent]) await client.ready();
    bed.server('firm.test').setClaims('jerzy', ['team:corporate']);

    step('Jerzy and Mia work at the same firm. The firm vouches that Jerzy is in corporate; he is not on the Acme matter.');
    const thread = await jerzyAgent.startThread(['mia@firm.test']);
    for (const client of [jerzyPhone, miaPhone, miaAgent]) await client.sync();

    step("Jerzy's agent asks Mia's agent");
    await jerzyAgent.requestInfo(thread, { question: 'What fee did Acme agree to?', purpose: 'Drafting the engagement letter' });
    note('info.request: "What fee did Acme agree to?" (purpose: drafting the engagement letter)');

    step("Mia's agent checks what it can verify, not what the email says");
    const [request] = messages(await miaAgent.sync());
    const context = await miaAgent.disclosureContext(thread, request);
    note(`asked by: ${context.requester}, from an ${context.requesterKind} certified by Jerzy`);
    note(`firm-signed claims: ${context.claims.join(', ')}`);
    note(`an answer here would be read by: ${context.audience.map((m) => `${m.principal.split('@')[0]}'s ${m.kind}`).join(', ')}`);
    note("Mia's rule: Acme fees go only to people the firm says are on the Acme matter. Not satisfied, so ask Mia.");
    await miaAgent.escalateInfo(context, 'Acme agreed a $40,000 fixed fee.');

    step("Mia's phone shows the approval card. Nobody else got it.");
    const card = cardFrom(miaPhone, await miaPhone.sync());
    note(`"${card.requester} asks: ${card.question}"`);
    note(`draft: "${card.draft}"`);
    note(`would go to: ${card.audience.map((m) => `${m.principal.split('@')[0]}'s ${m.kind}`).join(', ')}`);
    const leaked = messages([...(await jerzyPhone.sync()), ...(await jerzyAgent.sync())]).some((m) => m.body.intents.some((i) => i.name === 'info.approval'));
    note(`did Jerzy's phone or agent get the card? ${leaked ? 'yes' : 'no'}`);

    step('Mia releases it to Jerzy himself, not his agent');
    await miaPhone.decideApproval(card, { release: 'requester-only' });
    const atAgent = messages(await jerzyAgent.sync()).map((m) => m.body.text);
    const atPhone = messages(await jerzyPhone.sync()).map((m) => m.body.text);
    note(`Jerzy's agent received: ${atAgent.length ? atAgent.join(' | ') : 'nothing it can read'}`);
    note(`Jerzy's phone received: "${atPhone.join(' | ')}" (humans-only, end to end)`);

    step('Again, but someone joins the thread before Mia decides');
    await jerzyAgent.requestInfo(thread, { question: 'And the payment schedule?' });
    const second = await miaAgent.disclosureContext(thread, messages(await miaAgent.sync())[0]);
    await miaAgent.escalateInfo(second, 'Half on signing, half on completion.');
    const secondCard = cardFrom(miaPhone, await miaPhone.sync());
    const intern = bed.client(jerzy.enrollClient({ kind: 'agent', label: 'Intern bot', scopes: ['read:*'] }));
    await bed.publish(jerzy);
    await intern.ready();
    await jerzyPhone.rekey(thread);
    await miaPhone.sync();
    note('Jerzy adds an "Intern bot" agent; the thread rekeys.');
    try {
      await miaPhone.decideApproval(secondCard, { release: 'thread' });
      note('released (this should not happen)');
    } catch (error) {
      note(`Mia taps release: refused. ${error instanceof Error ? error.message : String(error)}`);
    }
    note('Her approval covered the four clients she saw, not whoever is there now.');
  } finally {
    await bed.close();
  }
}

function cardFrom(client: SignetClient, events: SignetEvent[]): ApprovalCard {
  const card = messages(events).map((message) => client.approvalCard(message)).find(Boolean);
  if (!card) throw new Error('no approval card arrived');
  return card;
}

main().catch((error: unknown) => {
  console.error(error);
  process.exit(1);
});
