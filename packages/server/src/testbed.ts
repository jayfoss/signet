import type { AddressInfo } from 'node:net';
import type { ClientKeys, ClientSnapshot, Identity, KeyPair, SignetClientOptions, TrustedLog } from '@signet/lib';
import { SignetClient, StaticResolver, generateSigningKey, splitAddress } from '@signet/lib';
import { createTransport } from 'nodemailer';
import { SMTPServer } from 'smtp-server';
import { IssuerServer } from './issuer-server';
import { TransparencyLogServer } from './log-server';
import { LogWitnessServer } from './log-witness';
import { RelayServer } from './relay-server';
import type { Limits } from './server';
import { SignetServer } from './server';
import { InboundSmtp, OutboundSmtp } from './smtp';

/** SPF, DKIM and DMARC lookups all come back empty, so tests never touch real DNS. */
const noDns = async (): Promise<string[]> => {
  throw Object.assign(new Error('not found'), { code: 'ENOTFOUND' });
};

export interface SentMail {
  from: string;
  to: string[];
  raw: string;
}

/**
 * Several Signet domains, one transparency log and an SMTP sink on localhost, found through a static
 * resolver instead of DNS. Plain email out of any domain lands in `sent`.
 */
export class Testbed {
  readonly resolver: StaticResolver;
  readonly sent: SentMail[] = [];
  private readonly urls = new Map<string, string>();
  private readonly servers = new Map<string, SignetServer>();
  private readonly inbound = new Map<string, { smtp: InboundSmtp; port: number }>();
  private readonly broken = new Set<string>();
  private readonly domainKeys = new Map<string, KeyPair>();
  private logServer!: TransparencyLogServer;
  /** Independent witnesses that cosign the log's tree heads (Section 5.5.1). */
  readonly witnesses: LogWitnessServer[] = [];
  /** Privacy Pass issuer shared by every domain in the bed. */
  issuer!: IssuerServer;
  /** OHTTP relay every domain sends sealed and anonymous deliveries through. */
  relay!: RelayServer;
  private sink!: SMTPServer;

  private readonly makeServer = new Map<string, () => SignetServer>();

  /** Stop a domain's home server and start it again on the same port, from its data folder if it has one. */
  async restart(domain: string): Promise<SignetServer> {
    const old = this.server(domain);
    const port = Number(new URL(this.url(domain)).port);
    await old.close();
    const server = this.makeServer.get(domain)?.() as SignetServer;
    await server.listen(port);
    this.servers.set(domain, server);
    return server;
  }

  private constructor() {
    this.resolver = new StaticResolver(this.urls);
  }

  static async start(
    domains: string[],
    options: { retryDelaysMs?: number[]; openEnrollment?: boolean; limits?: Partial<Limits>; intake?: string[]; dataDirs?: Record<string, string>; witnesses?: number } = {},
  ): Promise<Testbed> {
    const bed = new Testbed();
    // Witnesses need the log's address and key, and the log needs theirs, so they join the list once running.
    const witnessUrls: string[] = [];
    bed.logServer = new TransparencyLogServer(generateSigningKey(), bed.resolver, undefined, undefined, witnessUrls);
    await bed.logServer.listen();
    for (let i = 0; i < (options.witnesses ?? 0); i += 1) {
      const witness = new LogWitnessServer(generateSigningKey(), bed.trustedLog);
      await witness.listen();
      bed.witnesses.push(witness);
      witnessUrls.push(witness.url);
    }
    bed.issuer = new IssuerServer('issuer.signet.test', bed.resolver);
    await bed.issuer.listen();
    bed.relay = new RelayServer(bed.resolver);
    await bed.relay.listen();
    const sinkPort = await bed.startSink();
    for (const domain of domains) {
      const domainKey = generateSigningKey();
      bed.domainKeys.set(domain, domainKey);
      bed.makeServer.set(domain, () =>
        new SignetServer({
          domain,
          domainKey,
          resolver: bed.resolver,
          log: bed.trustedLog,
          outbound: new OutboundSmtp(domain, { relay: { host: '127.0.0.1', port: sinkPort } }),
          retryDelaysMs: options.retryDelaysMs,
          openEnrollment: options.openEnrollment,
          intake: options.intake?.includes(domain),
          limits: options.limits,
          dataDir: options.dataDirs?.[domain],
          issuer: { url: bed.issuer.url, key: bed.issuer.publicKey },
          ohttpRelay: bed.relay.url,
          fetchImpl: (input, init) => bed.fetchBetweenServers(input, init),
        }),
      );
      const server = bed.makeServer.get(domain)?.() as SignetServer;
      bed.urls.set(domain, await server.listen());
      bed.servers.set(domain, server);
      const smtp = new InboundSmtp(server, { dnsResolver: noDns });
      bed.inbound.set(domain, { smtp, port: await smtp.listen() });
    }
    return bed;
  }

  get trustedLog(): TrustedLog {
    return { url: this.logServer.url, key: this.logServer.publicKey };
  }

  get log(): TransparencyLogServer {
    return this.logServer;
  }

  /** The domain's private key, for tests that play a malicious server. */
  url(domain: string): string {
    const url = this.urls.get(domain);
    if (!url) throw new Error(`no server for ${domain}`);
    return url;
  }

  domainKey(domain: string): KeyPair {
    const key = this.domainKeys.get(domain);
    if (!key) throw new Error(`no key for ${domain}`);
    return key;
  }

  server(domain: string): SignetServer {
    const server = this.servers.get(domain);
    if (!server) throw new Error(`no server for ${domain}`);
    return server;
  }

  /** A client that shares its label in threads, so test output reads "via Clerk". */
  client(keys: ClientKeys, snapshot?: Partial<ClientSnapshot>, extra: Partial<SignetClientOptions> = {}): SignetClient {
    return new SignetClient(keys, this.resolver, { trustedLogs: [this.trustedLog], snapshot, keyPackageTarget: 3, shareLabel: true, ohttpRelay: this.relay.url, ...extra });
  }

  /** Make server-to-server delivery into this domain fail with a 503 until `repairDelivery`. */
  breakDelivery(domain: string): void {
    this.broken.add(domain);
  }

  repairDelivery(domain: string): void {
    this.broken.delete(domain);
  }

  private fetchBetweenServers(input: string | URL | Request, init?: RequestInit): Promise<Response> {
    const url = String(input);
    for (const domain of this.broken) {
      const direct = url.startsWith(`${this.urls.get(domain)}/v0/deliver`);
      // The relay URL may carry more parameters, such as the home a delivery is for.
      const relayed = url.startsWith(`${this.relay.url}/v0/relay?domain=${encodeURIComponent(domain)}`);
      if (direct || relayed) return Promise.resolve(new Response('down for maintenance', { status: 503 }));
    }
    return fetch(input, init);
  }

  /** Enroll the identity on first publish (as the org admin would), then push log updates over HTTP. */
  async publish(identity: Identity): Promise<void> {
    const { local, domain } = splitAddress(identity.principal);
    const server = this.server(domain);
    if (!server.store.hasUser(local)) {
      await server.enroll(identity.publication());
      return;
    }
    const response = await fetch(`${this.urls.get(domain)}/v0/log/${encodeURIComponent(local)}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(identity.publication()),
    });
    if (!response.ok) throw new Error(`log update failed: ${await response.text()}`);
  }

  /** Send plain email into a Signet domain over SMTP, the way Gmail would. */
  async sendPlainEmail(mail: { from: string; to: string; subject: string; text: string; headers?: Record<string, string> }): Promise<void> {
    const inbound = this.inbound.get(splitAddress(mail.to).domain);
    if (!inbound) throw new Error(`no SMTP listener for ${mail.to}`);
    await createTransport({ host: '127.0.0.1', port: inbound.port, secure: false, ignoreTLS: true }).sendMail(mail);
  }

  async close(): Promise<void> {
    await Promise.all([...this.servers.values()].map((server) => server.close()));
    await Promise.all([...this.inbound.values()].map(({ smtp }) => smtp.close()));
    await Promise.all(this.witnesses.map((witness) => witness.close()));
    await this.logServer.close();
    await this.issuer.close();
    await this.relay.close();
    await new Promise<void>((resolve) => this.sink.close(() => resolve()));
  }

  private async startSink(): Promise<number> {
    this.sink = new SMTPServer({
      authOptional: true,
      disabledCommands: ['AUTH', 'STARTTLS'],
      onData: (stream, session, callback) => {
        const chunks: Buffer[] = [];
        stream.on('data', (chunk: Buffer) => chunks.push(chunk));
        stream.on('end', () => {
          this.sent.push({
            from: session.envelope.mailFrom ? session.envelope.mailFrom.address : '',
            to: session.envelope.rcptTo.map((rcpt) => rcpt.address),
            raw: Buffer.concat(chunks).toString('utf8'),
          });
          callback();
        });
      },
    });
    await new Promise<void>((resolve) => this.sink.listen(0, '127.0.0.1', resolve));
    return (this.sink.server.address() as AddressInfo).port;
  }
}
