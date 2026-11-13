import type { AddressInfo } from 'node:net';
import { createServer } from 'node:http';
import type { Server } from 'node:http';
import { GmailMailbox, Identity } from '@signet/lib';
import { simpleParser } from 'mailparser';
import { Testbed } from '../testbed';

/**
 * Just enough of the Gmail API for Signet's Gmail mode: send, profile, history and metadata reads.
 * Each access token is one mailbox; sent mail is delivered to the mailbox of each To address.
 */
async function fakeGmail(accounts: Record<string, string>) {
  const mailboxes = new Map<string, { id: string; threadId: string; headers: { name: string; value: string }[]; text: string }[]>();
  const tokenFor = Object.fromEntries(Object.entries(accounts).map(([token, address]) => [address, token]));
  let next = 0;
  const server: Server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      void (async () => {
        const token = (request.headers.authorization ?? '').replace('Bearer ', '');
        if (!accounts[token]) return response.writeHead(401).end();
        const url = new URL(request.url ?? '/', 'http://gmail');
        const reply = (body: unknown) => response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(body));
        const own = mailboxes.get(token) ?? [];
        if (url.pathname === '/gmail/v1/users/me/messages/send') {
          const { raw } = JSON.parse(Buffer.concat(chunks).toString()) as { raw: string };
          const parsed = await simpleParser(Buffer.from(raw, 'base64url'));
          const headers = [...parsed.headerLines].map((line) => ({ name: line.line.split(':')[0], value: line.line.slice(line.line.indexOf(':') + 1).trim() }));
          const id = `msg${(next += 1)}`;
          for (const to of parsed.to && !Array.isArray(parsed.to) ? parsed.to.value : []) {
            const box = tokenFor[to.address ?? ''];
            if (box) mailboxes.set(box, [...(mailboxes.get(box) ?? []), { id, threadId: id, headers, text: parsed.text ?? '' }]);
          }
          return reply({ id, threadId: id });
        }
        if (url.pathname === '/gmail/v1/users/me/profile') return reply({ historyId: String(own.length) });
        if (url.pathname === '/gmail/v1/users/me/history') {
          const start = Number(url.searchParams.get('startHistoryId'));
          return reply({ historyId: String(own.length), history: own.slice(start).map((message) => ({ messagesAdded: [{ message: { id: message.id } }] })) });
        }
        const message = own.find((candidate) => url.pathname === `/gmail/v1/users/me/messages/${candidate.id}`);
        if (message) {
          if (url.searchParams.get('format') === 'full') {
            return reply({ id: message.id, threadId: message.threadId, payload: { mimeType: 'multipart/alternative', parts: [{ mimeType: 'text/plain', body: { data: Buffer.from(message.text).toString('base64url') } }] } });
          }
          const wanted = url.searchParams.getAll('metadataHeaders').map((name) => name.toLowerCase());
          return reply({ id: message.id, threadId: message.threadId, payload: { headers: message.headers.filter((h) => wanted.includes(h.name.toLowerCase())) } });
        }
        response.writeHead(404).end();
      })();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { baseUrl, close: () => new Promise<void>((resolve) => server.close(() => resolve())) };
}

describe('Gmail mode', () => {
  it('sends plain mail through Gmail with an attested header, and spots it on the other side', async () => {
    const bed = await Testbed.start(['alpha.test', 'beta.test']);
    const gmail = await fakeGmail({ 'alice-token': 'alice@alpha.test', 'jerzy-token': 'jerzy@beta.test' });
    try {
      const alice = Identity.create('alice@alpha.test');
      const jerzy = Identity.create('jerzy@beta.test');
      const alicePhone = bed.client(alice.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] }));
      const jerzyPhone = bed.client(jerzy.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] }));
      await bed.publish(alice);
      await bed.publish(jerzy);
      const aliceGmail = new GmailMailbox({ accessToken: 'alice-token', baseUrl: gmail.baseUrl });
      const jerzyGmail = new GmailMailbox({ accessToken: async () => 'jerzy-token', baseUrl: gmail.baseUrl });
      const start = await jerzyGmail.historyId();

      await alicePhone.sendViaGmail(aliceGmail, ['jerzy@beta.test'], { subject: 'Lunch?', text: 'Thursday?' });
      const { offers, historyId } = await jerzyPhone.scanGmail(jerzyGmail, start);

      expect(offers).toEqual([
        { gmailId: expect.any(String), from: 'alice@alpha.test', subject: 'Lunch?', signet: { address: 'alice@alpha.test', onSignet: true, authenticated: true }, humansOnly: false },
      ]);
      expect((await jerzyPhone.scanGmail(jerzyGmail, historyId)).offers).toEqual([]);
    } finally {
      await gmail.close();
      await bed.close();
    }
  });
});
