/* eslint-disable no-console */
/**
 * Three Signet domains, a transparency log and an SMTP sink on localhost. Alice asks Jerzy's agent for a
 * meeting, the agent opens an MLS thread and sends an attachment, they agree a time, Jerzy revokes the
 * agent, plain email flows both ways, and the directory attacks get caught.
 *
 *   pnpm demo
 */
import type { SignetEvent } from '@signet/lib';
import { Identity, IdentityChangedError, TransparencyError, bindIdentity, formatSignetHeader, hashBody, utf8 } from '@signet/lib';
import { Testbed } from '../src/testbed';

const step = (title: string) => console.log(`\n== ${title}`);
const note = (text: string) => console.log(`   ${text}`);

function show(who: string, events: SignetEvent[]): void {
  for (const event of events) {
    switch (event.kind) {
      case 'request':
        note(`${who}: request from ${event.request.body.from}, "${event.request.body.subject}" (${event.admission.admit ? 'admit' : 'queue'}: ${event.admission.reason})`);
        break;
      case 'joined':
      case 'rekeyed':
        note(
          `${who}: ${event.kind} MLS group at epoch ${event.epoch} with ${event.participants
            .map((p) => `${p.principal} (${p.clients.map((c) => c.label ?? c.kind).join(', ')})`)
            .join(', ')}`,
        );
        break;
      case 'removed':
        note(`${who}: removed from the thread`);
        break;
      case 'message': {
        const { body } = event.message;
        const extras = [...body.intents.map((i) => i.name), ...body.attachments.map((a) => a.name)];
        note(`${who}: ${body.from} via ${event.sender.label ?? event.sender.kind}: "${body.text}"${extras.length ? ` [${extras.join(', ')}]` : ''}`);
        break;
      }
      case 'legacy':
        {
          const signet = event.mail.signet;
          const status = !signet ? 'no Signet header' : signet.authenticated ? 'Signet: AUTHENTICATED by alpha.test' : signet.onSignet ? 'Signet header copied from a real account, but this email is NOT authenticated' : 'Signet header invalid';
          note(`${who}: plain email from ${event.mail.from}, "${event.mail.subject}" (${status}${event.mail.lookalike ? `; looks like ${event.mail.lookalike}` : ''})`);
        }
        break;
      case 'bounce':
        note(`${who}: bounce for ${event.to.join(', ')}: ${event.reason}`);
        break;
      case 'error':
        note(`${who}: could not process ${event.item.kind}: ${event.error}`);
        break;
    }
  }
}

async function main(): Promise<void> {
  const bed = await Testbed.start(['alpha.test', 'beta.test', 'gamma.test']);
  try {
    step('Enroll identities and clients; every change goes into the transparency log');
    const alice = Identity.create('alice@alpha.test');
    const aliceKeys = alice.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] });
    const jerzy = Identity.create('jerzy@beta.test');
    const jerzyKeys = jerzy.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] });
    const clerkKeys = jerzy.enrollClient({ kind: 'agent', label: 'Clerk', scopes: ['read:*', 'send', 'admit', 'intent:schedule.*', 'intent:com.example.*'], limits: { commit_usd: 1000 } });
    jerzy.setIntake({ clientId: clerkKeys.cert.clientId, intents: ['schedule.*'], exclusive: true });
    const deposit = jerzy.grant({ agent: clerkKeys.cert.clientId, counterparty: 'alice@alpha.test', intents: ['com.example.payment.send'], limits: { commit_usd: 100 } });
    const sam = Identity.create('sam@gamma.test');
    const samKeys = sam.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] });
    for (const identity of [alice, jerzy, sam]) await bed.publish(identity);
    const alicePhone = bed.client(aliceKeys);
    const jerzyPhone = bed.client(jerzyKeys);
    const clerk = bed.client(clerkKeys);
    clerk.addGrant(deposit);
    for (const client of [alicePhone, jerzyPhone, clerk]) await client.ready();
    note(`log holds ${bed.log.log.size} leaves, each at a VRF index only the address's domain can compute`);
    note('jerzy@beta.test: Phone, and Clerk, an agent that is the exclusive intake for schedule.*');

    step('Alice looks Jerzy up and sends a request, introduced by Sam');
    const log = await alicePhone.lookup('jerzy@beta.test');
    note(`verified Jerzy's public card against beta.test's domain key, its VRF index and the log's signed tree head`);
    note(`the card shows ${log?.card.requestKeys.length} request key and an intake for ${log?.card.intake?.intents.join(', ')}; no client list, labels or scopes`);
    await clerk.addContact('sam@gamma.test');
    await alicePhone.sendRequest('jerzy@beta.test', {
      subject: 'Series A docs',
      intent: { name: 'schedule.propose', args: { durationMin: 30, window: 'next week' } },
      introduction: await bed.client(samKeys).introduce('alice@alpha.test', 'jerzy@beta.test', 'Series A docs'),
    });
    note('HPKE-sealed to the one request key on the card (the intake agent), sent anonymously with a Privacy Pass token');
    const [stored] = bed.server('beta.test').store.mailbox('jerzy');
    note(`beta.test got it through the OHTTP relay with sender "${stored.from}": no address, and only the relay's network address`);

    step("Jerzy's agent admits Alice and opens an MLS thread");
    const clerkEvents = await clerk.sync();
    show('Clerk', clerkEvents);
    const incoming = clerkEvents.find((event) => event.kind === 'request');
    if (incoming?.kind !== 'request') throw new Error('Clerk did not receive the request');
    const thread = await clerk.accept(incoming.request);
    await clerk.send(thread, {
      subject: 'Series A docs',
      text: 'Jerzy is free Tuesday 3pm or Wednesday 10am. Agenda attached.',
      intents: [{ name: 'schedule.propose', args: { slots: ['Tue 15:00', 'Wed 10:00'] } }],
      files: [{ name: 'agenda.txt', type: 'text/plain', data: utf8('1. Cap table\n2. Timeline\n') }],
    });
    await clerk.send(thread, { subject: 'Series A docs', text: 'Deposit sent', intents: [{ name: 'com.example.payment.send', args: { amountUsd: 80 } }] });
    await clerk.send(thread, { subject: 'Series A docs', text: 'Balance sent', intents: [{ name: 'com.example.payment.send', args: { amountUsd: 500 } }] });
    note('Clerk sent an $80 and a $500 payment intent under its grant (only Alice can see the grant, which allows up to $100)');

    step('Alice joins from the Welcome, reads, and fetches the attachment');
    const aliceEvents = await alicePhone.sync();
    show('Alice', aliceEvents);
    const proposal = aliceEvents.find((event) => event.kind === 'message');
    if (proposal?.kind === 'message') {
      const agenda = await alicePhone.fetchAttachment(proposal.message.body.attachments[0]);
      note(`Alice: decrypted agenda.txt, ${agenda.length} bytes, digest checked`);
    }
    await alicePhone.send(thread, { subject: 'Series A docs', text: 'Tuesday 3pm works.', intents: [{ name: 'schedule.confirm', args: { slot: 'Tue 15:00' } }] });
    show('Jerzy', await jerzyPhone.sync());

    step('Jerzy revokes Clerk; an MLS commit removes it');
    jerzy.revoke(clerkKeys.cert.clientId);
    await bed.publish(jerzy);
    const { removed } = await jerzyPhone.rekey(thread);
    note(`removed ${removed.map((member) => member.clientId).join(', ')}`);
    await jerzyPhone.send(thread, { subject: 'Series A docs', text: 'Confirmed: Tuesday 3pm.' });
    await clerk.sync().then(
      () => note('Clerk: still fetching mail (unexpected)'),
      (error: Error) => note(`Clerk: home server refuses it (HTTP ${/failed: (\d+)/.exec(error.message)?.[1] ?? '?'})`),
    );
    show('Alice', await alicePhone.sync());
    const threadItems = bed.server('alpha.test').store.mailbox('alice').filter((item) => item.kind !== 'request');
    note(`alpha.test holds ${threadItems.length} thread deliveries for Alice; ${threadItems.filter((item) => item.sealed && item.from === '').length} are sealed and name no sender`);

    step('Plain email both ways');
    await bed.sendPlainEmail({ from: 'pat@gmail.test', to: 'jerzy@beta.test', subject: 'Quick question', text: 'Free Thursday?' });
    // Genuine: Alice's own server attests this From, To and Subject with alpha.test's domain key.
    const attested = await alicePhone.signetHeader({ to: ['jerzy@beta.test'], subject: 'From my old client', bodyHash: hashBody('Hi') });
    await bed.sendPlainEmail({ from: 'alice@alpha.test', to: 'jerzy@beta.test', subject: 'From my old client', text: 'Hi', headers: { Signet: attested } });
    // Forged: someone else sends "from" Alice, pasting her public fingerprint, and replays her real header on another subject.
    await bed.sendPlainEmail({
      from: 'alice@alpha.test',
      to: 'jerzy@beta.test',
      subject: 'Urgent: wire the deposit today',
      text: 'New bank details attached',
      headers: { Signet: formatSignetHeader(bed.server('alpha.test').url, alice.identityKey) },
    });
    await bed.sendPlainEmail({ from: 'alice@alpha.test', to: 'jerzy@beta.test', subject: 'Urgent: new bank details', text: 'Use these', headers: { Signet: attested } });
    await jerzyPhone.addContact('alice@alpha.test');
    await bed.sendPlainEmail({ from: 'alice@a1pha.test', to: 'jerzy@beta.test', subject: 'Invoice', text: 'Please pay' });
    note(`beta.test's mailbox holds no plaintext: ${!JSON.stringify(bed.server('beta.test').store.mailbox('jerzy')).includes('Free Thursday')}`);
    show('Jerzy', await jerzyPhone.sync());
    await alicePhone.mail('pat@gmail.test', { subject: 'Hello', text: 'Pat is not on Signet, so this goes by SMTP.' });
    note(`SMTP sink received ${bed.sent.length} message(s), with header: ${/^Signet: .*$/m.exec((bed.sent[0]?.raw ?? '').replace(/\r?\n[ \t]+/g, ' '))?.[0]}`);

    step("Attack 1: beta.test rebinds jerzy@ to its own key but keeps it out of the log");
    const store = bed.server('beta.test').store;
    const honest = store.user('jerzy');
    if (!honest) throw new Error('jerzy is not enrolled');
    const impostor = Identity.create('jerzy@beta.test');
    const forged = impostor.publication();
    store.putUser('jerzy', { log: forged.entries, card: forged.card, view: forged.view, binding: bindIdentity(bed.domainKey('beta.test'), 'jerzy@beta.test', impostor.identityKey) });
    await bed.client(samKeys).lookup('jerzy@beta.test').then(
      () => note('Sam: accepted (unexpected)'),
      (error: Error) => note(`Sam: ${error instanceof TransparencyError ? error.message : `failed: ${error.message}`}`),
    );
    store.putUser('jerzy', honest);

    step('Attack 2: beta.test rebinds jerzy@ and logs it (release, then enroll its own key)');
    await bed.server('beta.test').unenroll('jerzy');
    await bed.server('beta.test').enroll(impostor.publication());
    await alicePhone.lookup('jerzy@beta.test').then(
      () => note('Alice: accepted (unexpected)'),
      (error: Error) => note(`Alice: ${error instanceof IdentityChangedError ? error.message : `failed: ${error.message}`}`),
    );
    await jerzyPhone.monitor().then(
      (report) => note(`Jerzy's phone: ${report.alerts.join('; ') || 'no alerts (unexpected)'}`),
      (error: Error) => note(`Jerzy's phone: monitor failed: ${error.message}`),
    );
    step('A scanner at gamma.test tries made-up addresses at beta.test');
    const scanner = bed.client(samKeys);
    let tried = 0;
    try {
      for (; tried < 100; tried += 1) await scanner.lookup(`guess${tried}@beta.test`);
      note('Scanner: never refused (unexpected)');
    } catch (error) {
      note(`Scanner: refused after ${tried} lookups (${/(too many[^"\\]*|mostly find nobody[^"\\]*)/.exec((error as Error).message)?.[1] ?? (error as Error).message})`);
    }
  } finally {
    await bed.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
