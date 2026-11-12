/**
 * Gmail mode: for a domain whose mail stays on Google Workspace (or a user on consumer Gmail). Plain
 * email goes out through the Gmail API with the Signet header, and new mail is scanned for Signet
 * headers so a conversation can be upgraded. Signet itself still runs on the domain's Signet host.
 *
 * Scopes: `gmail.send` (sensitive) to send; `gmail.metadata` (restricted) to scan headers. Restricted
 * scopes need Google verification and a yearly CASA assessment for public apps; an Internal app inside
 * a customer's own Workspace is exempt.
 */
import MailComposer from 'nodemailer/lib/mail-composer';
import type { FileInput } from './attachments';
import { AUDIENCE_HEADER, SIGNET_HEADER } from './legacy';

export interface GmailOptions {
  /** OAuth access token, or a function returning a fresh one. */
  accessToken: string | (() => Promise<string>);
  /** Defaults to Google's API host; tests point it at a fake. */
  baseUrl?: string;
  fetchImpl?: typeof fetch;
}

export interface GmailHeaders {
  id: string;
  threadId: string;
  from: string;
  to: string[];
  subject: string;
  messageId: string;
  signet?: string;
  humansOnly: boolean;
}

const HEADERS = ['From', 'To', 'Subject', 'Message-ID', SIGNET_HEADER, AUDIENCE_HEADER];

/** "Alice <alice@x.com>, bob@y.com" → ["alice@x.com", "bob@y.com"]. */
const addresses = (value: string | undefined): string[] =>
  (value ?? '')
    .split(',')
    .map((part) => /<([^>]+)>/.exec(part)?.[1] ?? part.trim())
    .filter((address) => address.includes('@'));

export class GmailMailbox {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly options: GmailOptions) {
    this.baseUrl = (options.baseUrl ?? 'https://gmail.googleapis.com').replace(/\/$/, '');
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  /** Send plain email from the account, with the Signet header (and attachments) in the raw MIME. */
  async send(mail: {
    from: string;
    to: string[];
    subject: string;
    text: string;
    signetHeader?: string;
    humansOnly?: boolean;
    files?: FileInput[];
  }): Promise<{ id: string; threadId: string }> {
    const raw = await new MailComposer({
      from: mail.from,
      to: mail.to,
      subject: mail.subject,
      text: mail.text,
      headers: {
        ...(mail.signetHeader ? { [SIGNET_HEADER]: mail.signetHeader } : {}),
        ...(mail.humansOnly ? { [AUDIENCE_HEADER]: 'humans' } : {}),
      },
      attachments: (mail.files ?? []).map((file) => ({ filename: file.name, contentType: file.type, content: Buffer.from(file.data) })),
    })
      .compile()
      .build();
    return (await this.api('POST', '/gmail/v1/users/me/messages/send', { raw: raw.toString('base64url') })) as { id: string; threadId: string };
  }

  /** Where to start scanning from: the mailbox's current history id. */
  async historyId(): Promise<string> {
    return ((await this.api('GET', '/gmail/v1/users/me/profile')) as { historyId: string }).historyId;
  }

  /** Messages added since `historyId`, with just the headers Signet needs, and the id to resume from. */
  async newMessages(historyId: string): Promise<{ historyId: string; messages: GmailHeaders[] }> {
    const ids: string[] = [];
    let latest = historyId;
    let pageToken: string | undefined;
    do {
      const query = new URLSearchParams({ startHistoryId: historyId, historyTypes: 'messageAdded', ...(pageToken ? { pageToken } : {}) });
      const page = (await this.api('GET', `/gmail/v1/users/me/history?${query.toString()}`)) as {
        history?: { messagesAdded?: { message: { id: string } }[] }[];
        historyId: string;
        nextPageToken?: string;
      };
      for (const entry of page.history ?? []) for (const added of entry.messagesAdded ?? []) ids.push(added.message.id);
      latest = page.historyId;
      pageToken = page.nextPageToken;
    } while (pageToken);
    const messages = await Promise.all([...new Set(ids)].map((id) => this.headers(id)));
    return { historyId: latest, messages };
  }

  private async headers(id: string): Promise<GmailHeaders> {
    const query = new URLSearchParams([['format', 'metadata'], ...HEADERS.map((name) => ['metadataHeaders', name])]);
    const message = (await this.api('GET', `/gmail/v1/users/me/messages/${encodeURIComponent(id)}?${query.toString()}`)) as {
      id: string;
      threadId: string;
      payload?: { headers?: { name: string; value: string }[] };
    };
    const header = (name: string) => message.payload?.headers?.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value;
    const from = header('From') ?? '';
    return {
      id: message.id,
      threadId: message.threadId,
      from: /<([^>]+)>/.exec(from)?.[1] ?? from.trim(),
      to: addresses(header('To')),
      subject: header('Subject') ?? '',
      messageId: header('Message-ID') ?? '',
      ...(header(SIGNET_HEADER) ? { signet: header(SIGNET_HEADER) } : {}),
      humansOnly: header(AUDIENCE_HEADER)?.trim().toLowerCase() === 'humans',
    };
  }

  private async api(method: 'GET' | 'POST', path: string, body?: unknown): Promise<unknown> {
    const token = typeof this.options.accessToken === 'string' ? this.options.accessToken : await this.options.accessToken();
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers: { authorization: `Bearer ${token}`, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) throw new Error(`Gmail API ${method} ${path.split('?')[0]} failed: ${response.status} ${await response.text()}`);
    return response.json();
  }
}
