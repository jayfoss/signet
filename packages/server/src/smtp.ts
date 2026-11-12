import { resolveMx } from 'node:dns/promises';
import type { AddressInfo } from 'node:net';
import type { LegacyAuth } from '@signet/lib';
import { splitAddress } from '@signet/lib';
import type { DNSResolver } from 'mailauth/dist/cjs/types';
import { authenticate } from 'mailauth';
import type { Transporter } from 'nodemailer';
import { createTransport } from 'nodemailer';
import type { SMTPServerDataStream, SMTPServerSession } from 'smtp-server';
import { SMTPServer } from 'smtp-server';

const MAX_MESSAGE_BYTES = 40 * 1024 * 1024;

/** Where inbound mail goes once it has been checked: the home server encrypts it and forgets the plaintext. */
export interface LegacyInbox {
  domain: string;
  accepts(local: string): boolean;
  storeLegacy(local: string, raw: Buffer, envelopeFrom: string, auth: LegacyAuth): Promise<void>;
}

export interface InboundSmtpOptions {
  /** DNS resolver for SPF, DKIM and DMARC lookups; the system resolver by default. */
  dnsResolver?: DNSResolver;
  /** Certificate for STARTTLS. Without one, STARTTLS isn't offered. */
  tls?: { key: string | Buffer; cert: string | Buffer };
}

const smtpError = (code: number, message: string) => Object.assign(new Error(message), { responseCode: code });

function summarise(result: Awaited<ReturnType<typeof authenticate>>): LegacyAuth {
  const dkimResults = (result.dkim?.results ?? []) as { status?: { result?: string } }[];
  const dkim = dkimResults.some((r) => r.status?.result === 'pass') ? 'pass' : (dkimResults[0]?.status?.result ?? 'none');
  const spf = result.spf ? ((result.spf as { status?: { result?: string } }).status?.result ?? 'none') : 'none';
  const dmarc = result.dmarc ? ((result.dmarc as { status?: { result?: string } }).status?.result ?? 'none') : 'none';
  return { spf, dkim, dmarc };
}

/** Receives plain email for a Signet domain, checks SPF, DKIM and DMARC, then hands it to the inbox to encrypt. */
export class InboundSmtp {
  private readonly smtp: SMTPServer;

  constructor(
    private readonly inbox: LegacyInbox,
    private readonly options: InboundSmtpOptions = {},
  ) {
    this.smtp = new SMTPServer({
      name: inbox.domain,
      size: MAX_MESSAGE_BYTES,
      authOptional: true,
      disabledCommands: options.tls ? ['AUTH'] : ['AUTH', 'STARTTLS'],
      ...options.tls,
      onRcptTo: (address, _session, callback) => {
        try {
          const { local, domain } = splitAddress(address.address);
          if (domain !== inbox.domain || !inbox.accepts(local)) return callback(smtpError(550, `no such user: ${address.address}`));
          callback();
        } catch {
          callback(smtpError(550, `bad address: ${address.address}`));
        }
      },
      onData: (stream, session, callback) => {
        this.receive(stream, session).then(
          () => callback(),
          (error: Error) => callback(smtpError(451, `could not accept message: ${error.message}`)),
        );
      },
    });
  }

  async listen(port = 0, host = '127.0.0.1'): Promise<number> {
    await new Promise<void>((resolve) => this.smtp.listen(port, host, resolve));
    return (this.smtp.server.address() as AddressInfo).port;
  }

  close(): Promise<void> {
    return new Promise((resolve) => this.smtp.close(() => resolve()));
  }

  private async receive(stream: SMTPServerDataStream, session: SMTPServerSession): Promise<void> {
    const chunks: Buffer[] = [];
    for await (const chunk of stream) chunks.push(chunk as Buffer);
    if (stream.sizeExceeded) throw new Error('message too large');
    const raw = Buffer.concat(chunks);
    const envelopeFrom = session.envelope.mailFrom ? session.envelope.mailFrom.address : '';
    const result = await authenticate(raw, {
      ip: session.remoteAddress,
      helo: session.hostNameAppearsAs,
      sender: envelopeFrom,
      mta: this.inbox.domain,
      resolver: this.options.dnsResolver,
    });
    const auth = summarise(result);
    for (const recipient of session.envelope.rcptTo) {
      await this.inbox.storeLegacy(splitAddress(recipient.address).local, raw, envelopeFrom, auth);
    }
  }
}

export interface OutboundSmtpOptions {
  /** Send everything through this relay; otherwise deliver straight to each domain's MX. */
  relay?: { host: string; port: number; secure?: boolean; auth?: { user: string; pass: string } };
  /** DKIM-sign outgoing mail with the domain's key. */
  dkim?: { selector: string; privateKey: string };
}

export interface OutgoingMail {
  from: string;
  to: string[];
  subject: string;
  text: string;
  headers: Record<string, string>;
  attachments: { filename: string; contentType: string; content: string }[];
}

/** Sends plain email for clients whose recipients aren't on Signet. */
export class OutboundSmtp {
  constructor(
    private readonly domain: string,
    private readonly options: OutboundSmtpOptions = {},
  ) {}

  async send(mail: OutgoingMail): Promise<string> {
    const message = {
      from: mail.from,
      subject: mail.subject,
      text: mail.text,
      headers: mail.headers,
      attachments: mail.attachments.map((a) => ({ filename: a.filename, contentType: a.contentType, content: Buffer.from(a.content, 'base64') })),
    };
    if (this.options.relay) {
      const info = await this.transport(this.options.relay).sendMail({ ...message, to: mail.to });
      return info.messageId;
    }
    const byDomain = new Map<string, string[]>();
    for (const address of mail.to) {
      const { domain } = splitAddress(address);
      byDomain.set(domain, [...(byDomain.get(domain) ?? []), address]);
    }
    let messageId = '';
    for (const [domain, to] of byDomain) {
      const [mx] = (await resolveMx(domain)).sort((a, b) => a.priority - b.priority);
      if (!mx) throw new Error(`${domain} has no MX record`);
      const info = await this.transport({ host: mx.exchange, port: 25 }).sendMail({ ...message, to });
      messageId = info.messageId;
    }
    return messageId;
  }

  private transport(target: NonNullable<OutboundSmtpOptions['relay']>): Transporter {
    const dkim = this.options.dkim;
    return createTransport({
      host: target.host,
      port: target.port,
      secure: target.secure ?? false,
      auth: target.auth,
      name: this.domain,
      ...(dkim ? { dkim: { domainName: this.domain, keySelector: dkim.selector, privateKey: dkim.privateKey } } : {}),
    });
  }
}
