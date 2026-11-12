import { Identity, formatSignetHeader } from '@signet/lib';
import { Testbed } from '../testbed';

describe('plain email alongside Signet', () => {
  let bed: Testbed;
  let jerzy: Identity;
  let alice: Identity;

  beforeEach(async () => {
    bed = await Testbed.start(['alpha.test', 'beta.test']);
    jerzy = Identity.create('jerzy@beta.test');
    alice = Identity.create('alice@alpha.test');
  });

  afterEach(async () => {
    await bed.close();
  });

  async function phones() {
    const jerzyPhone = bed.client(jerzy.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] }));
    const alicePhone = bed.client(alice.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] }));
    await bed.publish(jerzy);
    await bed.publish(alice);
    return { jerzyPhone, alicePhone };
  }

  it('encrypts inbound plain email to the recipient on arrival and keeps no plaintext', async () => {
    const { jerzyPhone } = await phones();

    await bed.sendPlainEmail({ from: 'pat@gmail.test', to: 'jerzy@beta.test', subject: 'Quick question', text: 'Are you free Thursday?' });

    const stored = JSON.stringify(bed.server('beta.test').store.mailbox('jerzy'));
    expect(stored).not.toContain('Thursday');
    const [event] = await jerzyPhone.sync();
    expect(event).toMatchObject({
      kind: 'legacy',
      mail: { from: 'pat@gmail.test', subject: 'Quick question', tier: 'request', signet: null, auth: { dmarc: 'none' } },
    });
    expect(event.kind === 'legacy' && event.mail.text.trim()).toBe('Are you free Thursday?');
  });

  it('rejects plain email for addresses that are not enrolled', async () => {
    await phones();

    await expect(bed.sendPlainEmail({ from: 'pat@gmail.test', to: 'nobody@beta.test', subject: 'Hi', text: 'Hi' })).rejects.toThrow(/550/);
  });

  it('authenticates a Signet header only when the sender\'s domain attested this exact email', async () => {
    const { jerzyPhone, alicePhone } = await phones();
    const attested = await alicePhone.signetHeader({ to: ['jerzy@beta.test'], subject: 'Hello' });
    const copied = formatSignetHeader(bed.server('alpha.test').url, alice.identityKey);

    await bed.sendPlainEmail({ from: 'alice@alpha.test', to: 'jerzy@beta.test', subject: 'Hello', text: 'Hi', headers: { Signet: attested } });
    await bed.sendPlainEmail({ from: 'alice@alpha.test', to: 'jerzy@beta.test', subject: 'Wire the deposit', text: 'Hi', headers: { Signet: copied } });
    await bed.sendPlainEmail({ from: 'alice@alpha.test', to: 'jerzy@beta.test', subject: 'New bank details', text: 'Hi', headers: { Signet: attested } });

    const [genuine, fingerprintOnly, replayed] = await jerzyPhone.sync();
    expect(genuine.kind === 'legacy' && genuine.mail.signet).toEqual({ address: 'alice@alpha.test', onSignet: true, authenticated: true });
    expect(fingerprintOnly.kind === 'legacy' && fingerprintOnly.mail.signet).toEqual({ address: 'alice@alpha.test', onSignet: true, authenticated: false });
    expect(replayed.kind === 'legacy' && replayed.mail.signet).toEqual({ address: 'alice@alpha.test', onSignet: true, authenticated: false });
  });

  it('flags plain email from a domain that looks like a contact\'s', async () => {
    const { jerzyPhone } = await phones();
    await jerzyPhone.addContact('alice@alpha.test');

    await bed.sendPlainEmail({ from: 'alice@a1pha.test', to: 'jerzy@beta.test', subject: 'Invoice', text: 'Please pay' });

    const [event] = await jerzyPhone.sync();
    expect(event).toMatchObject({ kind: 'legacy', mail: { lookalike: 'alpha.test', tier: 'request' } });
  });

  it("shares contacts across an account's devices, so every device warns about the same lookalikes", async () => {
    const { jerzyPhone } = await phones();
    const laptop = bed.client(jerzy.enrollClient({ kind: 'device', label: 'Laptop', scopes: ['read:*', 'send', 'admit'] }));
    await bed.publish(jerzy);
    await jerzyPhone.addContact('alice@alpha.test');

    await bed.sendPlainEmail({ from: 'alice@a1pha.test', to: 'jerzy@beta.test', subject: 'Invoice', text: 'Please pay' });

    expect(await laptop.sync()).toMatchObject([{ kind: 'legacy', mail: { lookalike: 'alpha.test' } }]);
    expect(laptop.admission.contacts).toContain('alice@alpha.test');
  });

  it('sends plain email to non-Signet recipients with the Signet header and attachments', async () => {
    const { alicePhone } = await phones();

    const result = await alicePhone.mail('pat@gmail.test', {
      subject: 'Docs',
      text: 'See attached.',
      files: [{ name: 'notes.txt', type: 'text/plain', data: Buffer.from('hello') }],
    });

    expect(result).toEqual({ via: 'smtp' });
    expect(bed.sent).toHaveLength(1);
    expect(bed.sent[0].to).toEqual(['pat@gmail.test']);
    expect(bed.sent[0].raw.replace(/\r?\n[ \t]+/g, ' ')).toMatch(/Signet: v=signet0; server=\S+; fp=\S+; ts=\S+; nonce=\S+; sig=\S+/);
    expect(bed.sent[0].raw).toContain('notes.txt');
  });

  it('routes mail to an enrolled address over Signet instead of SMTP', async () => {
    const { alicePhone } = await phones();

    await expect(alicePhone.mail('jerzy@beta.test', { subject: 'Hi', text: 'Hello over Signet' })).resolves.toEqual({ via: 'signet' });
    expect(bed.sent).toHaveLength(0);
  });
});
