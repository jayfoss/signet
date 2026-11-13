import { readFile, writeFile } from 'node:fs/promises';
import { basename, extname } from 'node:path';
import { parseArgs } from 'node:util';
import type { ClientCert, ClientKind, EnrollmentRequest, FileInput, Intent, KeyPair, Participant, PendingClient, Resolver, SignetCheck, SignetEvent } from '@signet/lib';
import {
  DnsResolver,
  GmailMailbox,
  Identity,
  UnlistedAddressError,
  enrollmentFingerprint,
  enrollmentLink,
  fetchApprovedCert,
  fetchRecoverableLog,
  joinPairing,
  pairAsOwner,
  parseEnrollmentLink,
  requestEnrollment, NotSignetDomainError, SignetClient, StaticResolver, activeClients, splitAddress } from '@signet/lib';
import type { Grant } from '@signet/lib';
import type { Config } from './home';
import { Home } from './home';

export interface CliContext {
  home: string;
  out: (line: string) => void;
  /** Tests pass their own resolver; otherwise config.json's servers map, or DNS. */
  resolver?: Resolver;
  /** Ask the person a yes/no question. Without it, anything that needs a yes is refused unless --approve. */
  confirm?: (question: string) => Promise<boolean>;
}

const USAGE = `signet <command> [options]

  init --address A --log-url=U --log-key=K [--servers JSON] [--relay URL] [--label Phone]
                                     (use = for keys: base64url can start with '-')
                                     create an identity and this device, and enroll
  Adding a client (its keys are made on the new device and never leave it):
  pair [--scopes a,b] [--limit-usd N] [--intake x,y [--intake-only]] [--approve]
                                     show a pairing code and approve the client that joins with it
                                     (primary device only); --scopes overrides what it asks for
  join CODE --address A --log-url=U --log-key=K [--kind device|agent|tool] [--label L] [--scopes a,b]
                                     on the new device: pair with the code the primary device shows
  enroll-request --address A --log-url=U --log-key=K [--kind ...] [--label L] [--scopes a,b]
                                     on the new device: print a link (or QR) for the primary device
  approve LINK [--scopes a,b] [--limit-usd N] [--intake x,y [--intake-only]]
                                     approve that link (primary device only)
  enroll-finish                      on the new device, once approved: fetch its certificate
  add-client --kind agent|tool|device --label L --scopes a,b --out DIR [--limit-usd N] [--intake x,y [--intake-only]]
                                     demo shortcut: make a client's keys here and write them to DIR
  grant AGENT_HOME COUNTERPARTY --intents a,b [--limit-usd N] [--days N]
                                     let that agent act with one counterparty (primary device only)
  audience --agents ID,ID            let these agents read mail senders mark humans-only (primary device
                                     only; empty to honour every such request)
  revoke CLIENT_ID                   revoke a client (primary device only)
  unlisted on|off                     hide this address from strangers (they reach it through the domain's intake),
                                     or list it again (primary device only; the domain must run an intake)
  rotate                             replace the identity key; contacts follow the change (primary device only)
  recovery-key --out FILE            name a recovery key and write it to FILE; keep it offline (primary device only)
  recover --address A --log-url=U --log-key=K --recovery-key FILE [--servers JSON] [--label Phone]
                                     every device is lost: take the account back with the recovery key
  clients                            list this account's clients
  lookup ADDRESS                     verify an address against its domain and the log
  request ADDRESS --subject S [--note N] [--intent NAME --args JSON] [--humans-only]
  sync [--auto-accept]               fetch new mail; --auto-accept admits trusted senders
  requests                           list waiting requests
  accept REQUEST_ID                  admit a request and start a thread
  threads                            list threads
  send THREAD --text T [--subject S] [--intent NAME --args JSON] [--attach FILE ...] [--humans-only]
                                     --humans-only sends in the thread's humans-only sibling (opened on first use)
  rekey THREAD                       drop revoked clients from a thread, add new ones
  handoff THREAD --reason R          hand a thread to your own devices; your agents stop sending in it until you reply
  mail ADDRESS --subject S --text T [--attach FILE ...] [--humans-only]
                                     Signet if they're enrolled, plain email otherwise
  attachment MESSAGE_ID INDEX --out FILE
  contact ADDRESS | trust DOMAIN     admit this person or domain without a request
  monitor                            check this address's history in the transparency log, and what strangers see
  card                               print this address's contact card: a link others can use to reach you
                                     directly, whatever your domain tells strangers
  import-card LINK                   keep someone's contact card (checked against the log)

  Gmail mode (mail stays on Google; set SIGNET_GMAIL_TOKEN to an OAuth access token):
  mail ADDRESS --via gmail ...       send plain email through the Gmail API with an attested Signet header
  gmail-scan                         check new Gmail for Signet headers (authenticated or not)`;

const OPTIONS = {
  address: { type: 'string' },
  'log-url': { type: 'string' },
  'log-key': { type: 'string' },
  servers: { type: 'string' },
  label: { type: 'string' },
  kind: { type: 'string' },
  scopes: { type: 'string' },
  intake: { type: 'string' },
  'intake-only': { type: 'boolean' },
  intents: { type: 'string' },
  'limit-usd': { type: 'string' },
  days: { type: 'string' },
  via: { type: 'string' },
  'humans-only': { type: 'boolean' },
  agents: { type: 'string' },
  out: { type: 'string' },
  'recovery-key': { type: 'string' },
  approve: { type: 'boolean' },
  relay: { type: 'string' },
  subject: { type: 'string' },
  reason: { type: 'string' },
  text: { type: 'string' },
  note: { type: 'string' },
  intent: { type: 'string' },
  args: { type: 'string' },
  attach: { type: 'string', multiple: true },
  'auto-accept': { type: 'boolean' },
  help: { type: 'boolean', short: 'h' },
} as const;

const TYPES: Record<string, string> = { '.pdf': 'application/pdf', '.txt': 'text/plain', '.png': 'image/png', '.jpg': 'image/jpeg', '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' };

const list = (value: string | undefined): string[] => (value ? value.split(',').map((part) => part.trim()).filter(Boolean) : []);

function required(value: string | undefined, name: string): string {
  if (!value) throw new Error(`--${name} is required`);
  return value;
}

function intentFrom(name: string | undefined, args: string | undefined): Intent | undefined {
  return name ? { name, args: args ? (JSON.parse(args) as Record<string, unknown>) : {} } : undefined;
}

async function filesFrom(paths: string[] | undefined): Promise<FileInput[]> {
  return Promise.all(
    (paths ?? []).map(async (path) => ({ name: basename(path), type: TYPES[extname(path).toLowerCase()] ?? 'application/octet-stream', data: await readFile(path) })),
  );
}

const resolverFor = (ctx: CliContext, config: Config): Resolver =>
  ctx.resolver ?? (config.servers ? new StaticResolver(new Map(Object.entries(config.servers))) : new DnsResolver());

async function serverFor(resolver: Resolver, address: string): Promise<string> {
  return (await resolver.policy(splitAddress(address).domain)).server;
}

async function post(url: string, body: unknown): Promise<Response> {
  return fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
}

async function publishLog(resolver: Resolver, identity: Identity): Promise<void> {
  const { local } = splitAddress(identity.principal);
  const response = await post(`${await serverFor(resolver, identity.principal)}/v0/log/${encodeURIComponent(local)}`, identity.publication());
  if (!response.ok) throw new Error(`could not publish the log: ${response.status} ${await response.text()}`);
}

/** "jerzy@beta.test (Phone, Clerk agent)": one entry per person, their clients in brackets. */
/** "Phone", "Clerk agent", or just "device"/"agent" when the client didn't share a label. */
const name = (client: { label?: string; kind: string }): string =>
  client.label ? (client.kind === 'device' ? client.label : `${client.label} ${client.kind}`) : client.kind;

const people = (participants: Participant[]): string =>
  participants
    .map(({ principal, clients }) => `${principal} (${clients.map(name).join(', ')})`)
    .join(', ');

function signetNote(signet: SignetCheck | null): string {
  if (!signet) return '';
  if (signet.authenticated) return `, Signet authenticated (${signet.address})`;
  return signet.onSignet ? `, Signet header NOT authenticated: ${signet.address} is on Signet but its domain didn't vouch for this email` : ', Signet header invalid';
}

function describe(event: SignetEvent): string {
  switch (event.kind) {
    case 'request': {
      const { body } = event.request;
      const intent = body.intent ? ` [${body.intent.name}]` : '';
      return `request ${body.id} from ${body.from}: "${body.subject}"${intent}${body.note ? ` - ${body.note}` : ''} (${event.admission.admit ? 'admitted' : 'waiting'}: ${event.admission.reason})`;
    }
    case 'joined':
    case 'rekeyed':
    case 'fork-resolved':
      return `${event.kind === 'fork-resolved' ? 'two commits competed; settled on the one with the smaller hash:' : event.kind} ${event.thread}${event.humansOnly ? ' [humans only]' : ''}${event.linkedTo ? ` beside ${event.linkedTo}` : ''} at epoch ${event.epoch} with ${people(event.participants)}`;
    case 'removed':
      return `removed from ${event.thread}`;
    case 'message': {
      const { body } = event.message;
      const extras = [...body.intents.map((i) => i.name), ...body.attachments.map((a) => `attachment ${a.name}`)];
      return `message ${body.id} in ${event.thread} from ${body.from} (${name(event.sender)})${body.audience === 'humans' ? ' [humans only]' : ''}: ${body.text}${extras.length ? ` [${extras.join(', ')}]` : ''}`;
    }
    case 'legacy': {
      const { mail } = event;
      return `plain email from ${mail.from}: "${mail.subject}"${mail.humansOnly ? ' [humans only]' : ''} (${mail.tier}, DMARC ${mail.auth.dmarc}${signetNote(mail.signet)}${mail.lookalike ? `; WARNING: looks like ${mail.lookalike}` : ''})`;
    }
    case 'directory-alert':
      return `WARNING ${event.alert}`;
    case 'key-changed':
      return event.how === 'rotated'
        ? `${event.principal} rotated their identity key`
        : `${event.principal}'s identity key was RECOVERED (their old key was lost); check with them if this is unexpected`;
    case 'bounce':
      return `bounced ${event.id} to ${event.to.join(', ')}: ${event.reason}`;
    case 'handoff':
      return `handed to you in ${event.thread}: ${event.reason}`;
    case 'delivery-unconfirmed':
      return `WARNING no recipient home has confirmed receiving ${event.id} for ${event.to.join(', ')}, even after sending it again through another home`;
    case 'home-missing':
      return `WARNING ${event.home} has not delivered ${event.itemId}, which your other homes have; it may be withholding mail`;
    case 'error':
      return `could not process ${event.item.kind} ${event.item.id}: ${event.error}`;
  }
}

/** Run one command against the client directory in ctx.home. */
export async function run(argv: string[], ctx: CliContext): Promise<void> {
  const { values: opts, positionals } = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true });
  const [command, ...rest] = positionals;
  if (!command || opts.help) {
    ctx.out(USAGE);
    return;
  }
  const home = await Home.create(ctx.home);

  if (command === 'init' || command === 'recover' || command === 'join' || command === 'enroll-request') {
    if (home.exists('client.json')) throw new Error(`${ctx.home} already holds a client`);
    const address = required(opts.address, 'address');
    const config: Config = {
      address,
      trustedLogs: [{ url: required(opts['log-url'], 'log-url'), key: required(opts['log-key'], 'log-key') }],
      servers: opts.servers ? (JSON.parse(opts.servers) as Record<string, string>) : undefined,
      ohttpRelay: opts.relay,
    };
    const resolver = resolverFor(ctx, config);
    const asked = {
      kind: (opts.kind ?? 'device') as ClientKind,
      label: opts.label ?? 'Device',
      scopes: opts.scopes ? list(opts.scopes) : ['read:*', 'send', 'admit'],
      limits: opts['limit-usd'] ? { commit_usd: Number(opts['limit-usd']) } : undefined,
    };
    if (command === 'join') {
      const keys = await joinPairing(resolver, address, required(rest[0], 'CODE'), asked, (fingerprint) =>
        ctx.out(`sent the request; check the other screen shows ${fingerprint}`),
      );
      await home.write('config.json', config);
      await home.write('client.json', keys);
      const client = new SignetClient(keys, resolver, { trustedLogs: config.trustedLogs });
      await client.ready();
      await home.write('snapshot.json', client.snapshot());
      ctx.out(`enrolled this ${keys.cert.kind} as ${keys.cert.clientId} with scopes ${keys.cert.scopes.join(', ') || '(none)'}`);
      return;
    }
    if (command === 'enroll-request') {
      const pending = requestEnrollment(address, asked);
      await home.write('config.json', config);
      await home.write('pending.json', pending);
      ctx.out(enrollmentLink(pending.request));
      ctx.out(`fingerprint ${enrollmentFingerprint(pending.request)}; once the primary device approves it, run \`signet enroll-finish\``);
      return;
    }
    if (command === 'recover') {
      const recovery = JSON.parse(await readFile(required(opts['recovery-key'], 'recovery-key'), 'utf8')) as KeyPair;
      const entries = await fetchRecoverableLog(await serverFor(resolver, address), address, recovery);
      const identity = Identity.recover({ principal: address, entries }, recovery);
      const keys = identity.enrollClient({ kind: 'device', label: opts.label ?? 'Device', scopes: ['read:*', 'send', 'admit'] });
      await publishLog(resolver, identity);
      await home.write('config.json', config);
      await home.saveIdentity(identity);
      await home.write('client.json', keys);
      const client = new SignetClient(keys, resolver, { trustedLogs: config.trustedLogs });
      await client.ready();
      await home.write('snapshot.json', client.snapshot());
      ctx.out(`recovered ${address} with a new identity key; this device is ${keys.cert.clientId}`);
      ctx.out('contacts are told the key was recovered. Revoke the lost devices (`signet clients`, `signet revoke`) and make a new recovery key');
      return;
    }
    const identity = Identity.create(address);
    const keys = identity.enrollClient({ kind: 'device', label: opts.label ?? 'Device', scopes: ['read:*', 'send', 'admit'] });
    await home.write('config.json', config);
    await home.saveIdentity(identity);
    await home.write('client.json', keys);
    const response = await post(`${await serverFor(resolver, address)}/v0/enroll`, identity.publication());
    if (!response.ok) {
      ctx.out(`created ${address}, but the server did not enroll it (${response.status}). Ask your admin to enroll ${ctx.home}/identity.json's log.`);
      return;
    }
    const client = new SignetClient(keys, resolver, { trustedLogs: config.trustedLogs });
    await client.ready();
    await home.write('snapshot.json', client.snapshot());
    ctx.out(`enrolled ${address} with this device as ${keys.cert.clientId}`);
    return;
  }

  const config = await home.config();
  const resolver = resolverFor(ctx, config);

  if (command === 'enroll-finish') {
    const pending = await home.need<PendingClient>('pending.json', 'run `signet enroll-request` first');
    const keys = await fetchApprovedCert(resolver, pending);
    await home.write('client.json', keys);
    const client = new SignetClient(keys, resolver, { trustedLogs: config.trustedLogs });
    await client.ready();
    await home.write('snapshot.json', client.snapshot());
    ctx.out(`enrolled this ${keys.cert.kind} as ${keys.cert.clientId} with scopes ${keys.cert.scopes.join(', ') || '(none)'}`);
    return;
  }

  if (['add-client', 'revoke', 'grant', 'audience', 'rotate', 'recovery-key', 'unlisted', 'pair', 'approve'].includes(command)) {
    const identity = await home.identity();
    /** Certify a client from its own request, with this device's choice of scopes, and publish. */
    const certify = async (request: EnrollmentRequest): Promise<ClientCert> => {
      const cert = identity.approveClient(request, {
        scopes: opts.scopes ? list(opts.scopes) : undefined,
        limits: opts['limit-usd'] ? { commit_usd: Number(opts['limit-usd']) } : undefined,
      });
      if (opts.intake !== undefined) {
        if (cert.kind !== 'agent') throw new Error('only an agent can be the intake');
        identity.setIntake({ clientId: cert.clientId, intents: list(opts.intake), exclusive: opts['intake-only'] === true });
      }
      await publishLog(resolver, identity);
      await home.saveIdentity(identity);
      // This device approved it, so its own monitor shouldn't ask "was this you?".
      const self = new SignetClient(await home.keys(), resolver, { trustedLogs: config.trustedLogs, snapshot: await home.snapshot() });
      self.acknowledgeClient(cert.clientId);
      await home.write('snapshot.json', self.snapshot());
      return cert;
    };
    const describeRequest = (request: EnrollmentRequest, fingerprint: string) =>
      `a new ${request.body.kind} "${request.body.label}" asks for ${request.body.scopes.join(', ') || 'no scopes'}; fingerprint ${fingerprint}`;
    if (command === 'pair') {
      const self = new SignetClient(await home.keys(), resolver, { trustedLogs: config.trustedLogs, snapshot: await home.snapshot() });
      const { code, channel } = await self.openPairing();
      ctx.out(`pairing code ${code} (valid for 10 minutes). On the new device: signet join ${code} --address ${identity.principal} ...`);
      const cert = await pairAsOwner(channel, identity.principal, code, async (request, fingerprint) => {
        ctx.out(describeRequest(request, fingerprint));
        const yes = opts.approve === true || ((await ctx.confirm?.('Approve it?')) ?? false);
        return yes ? certify(request) : null;
      });
      ctx.out(cert ? `approved ${cert.label} as ${cert.clientId} with scopes ${cert.scopes.join(', ') || '(none)'}` : 'declined');
      return;
    }
    if (command === 'approve') {
      const request = parseEnrollmentLink(required(rest[0], 'LINK'));
      ctx.out(describeRequest(request, enrollmentFingerprint(request)));
      const cert = await certify(request);
      ctx.out(`approved ${cert.label} as ${cert.clientId} with scopes ${cert.scopes.join(', ') || '(none)'}`);
      return;
    }
    if (command === 'unlisted') {
      const on = required(rest[0], 'on|off');
      if (on !== 'on' && on !== 'off') throw new Error('unlisted takes on or off');
      identity.setUnlisted(on === 'on');
      await publishLog(resolver, identity);
      await home.saveIdentity(identity);
      ctx.out(
        on === 'on'
          ? `${identity.principal} is unlisted: strangers can't tell it exists, and their first requests go through your domain's intake, which can read them`
          : `${identity.principal} is listed again`,
      );
      return;
    }
    if (command === 'rotate') {
      identity.rotateKey();
      await publishLog(resolver, identity);
      await home.saveIdentity(identity);
      ctx.out(`rotated the identity key for ${identity.principal}; contacts follow it from the key they pinned`);
      return;
    }
    if (command === 'recovery-key') {
      const out = required(opts.out, 'out');
      const recovery = identity.setRecovery();
      await publishLog(resolver, identity);
      await home.saveIdentity(identity);
      await writeFile(out, JSON.stringify(recovery), { mode: 0o600 });
      ctx.out(`wrote the recovery key to ${out}. Keep it offline: it can take this account back once if every device is lost`);
      return;
    }
    if (command === 'audience') {
      const agents = list(opts.agents);
      identity.setAudiencePolicy(agents);
      await publishLog(resolver, identity);
      await home.saveIdentity(identity);
      ctx.out(agents.length ? `agents ${agents.join(', ')} may read mail marked humans-only` : 'mail marked humans-only goes to your devices only');
      return;
    }
    if (command === 'revoke') {
      const clientId = required(rest[0], 'CLIENT_ID');
      identity.revoke(clientId);
      await publishLog(resolver, identity);
      await home.saveIdentity(identity);
      ctx.out(`revoked ${clientId}; run \`signet rekey THREAD\` on threads it was in`);
      return;
    }
    if (command === 'grant') {
      const agentHome = new Home(required(rest[0], 'AGENT_HOME'));
      const agent = await agentHome.keys();
      const grant: Grant = identity.grant({
        agent: agent.cert.clientId,
        counterparty: required(rest[1], 'COUNTERPARTY'),
        intents: list(required(opts.intents, 'intents')),
        limits: opts['limit-usd'] ? { commit_usd: Number(opts['limit-usd']) } : undefined,
        ttlDays: opts.days ? Number(opts.days) : undefined,
      });
      const agentClient = new SignetClient(agent, resolver, { trustedLogs: config.trustedLogs, snapshot: await agentHome.snapshot() });
      agentClient.addGrant(grant);
      await agentHome.write('snapshot.json', agentClient.snapshot());
      ctx.out(`granted ${agent.cert.label} ${grant.intents.join(', ')} with ${grant.counterparty} until ${grant.expires.slice(0, 10)} (${grant.id})`);
      return;
    }
    const kind = required(opts.kind, 'kind') as ClientKind;
    const keys = identity.enrollClient({
      kind,
      label: required(opts.label, 'label'),
      scopes: list(opts.scopes),
      limits: opts['limit-usd'] ? { commit_usd: Number(opts['limit-usd']) } : undefined,
    });
    if (opts.intake !== undefined) {
      if (kind !== 'agent') throw new Error('only an agent can be the intake');
      identity.setIntake({ clientId: keys.cert.clientId, intents: list(opts.intake), exclusive: opts['intake-only'] === true });
    }
    await publishLog(resolver, identity);
    await home.saveIdentity(identity);
    // This device approved it, so its own monitor shouldn't ask "was this you?".
    const self = new SignetClient(await home.keys(), resolver, { trustedLogs: config.trustedLogs, snapshot: await home.snapshot() });
    self.acknowledgeClient(keys.cert.clientId);
    await home.write('snapshot.json', self.snapshot());
    const target = await Home.create(required(opts.out, 'out'));
    await target.write('config.json', config);
    await target.write('client.json', keys);
    const added = new SignetClient(keys, resolver, { trustedLogs: config.trustedLogs });
    await added.ready();
    await target.write('snapshot.json', added.snapshot());
    ctx.out(`approved ${keys.cert.label} (${kind}) as ${keys.cert.clientId}; its keys are in ${opts.out}`);
    return;
  }

  const client = new SignetClient(await home.keys(), resolver, { trustedLogs: config.trustedLogs, snapshot: await home.snapshot(), ohttpRelay: config.ohttpRelay });
  try {
    await runClientCommand(command, rest, opts, client, home, ctx);
  } finally {
    await home.write('snapshot.json', client.snapshot());
  }
}

function gmail(): GmailMailbox {
  const token = process.env.SIGNET_GMAIL_TOKEN;
  if (!token) throw new Error('set SIGNET_GMAIL_TOKEN to a Gmail OAuth access token (gmail.send, and gmail.metadata to scan)');
  return new GmailMailbox({ accessToken: token, baseUrl: process.env.SIGNET_GMAIL_API });
}

type Opts = ReturnType<typeof parseArgs<{ options: typeof OPTIONS; allowPositionals: true }>>['values'];

async function runClientCommand(command: string, rest: string[], opts: Opts, client: SignetClient, home: Home, ctx: CliContext): Promise<void> {
  switch (command) {
    case 'clients': {
      const log = (await client.lookup(client.address))?.log;
      if (!log) throw new Error(`${client.address} is not enrolled`);
      const active = new Set(activeClients(log).map((cert) => cert.clientId));
      for (const cert of log.clients.values()) {
        ctx.out(`${cert.clientId}  ${cert.kind.padEnd(6)} ${cert.label}  ${active.has(cert.clientId) ? 'active' : 'revoked or expired'}  [${cert.scopes.join(', ')}]`);
      }
      return;
    }
    case 'lookup': {
      const address = required(rest[0], 'ADDRESS');
      let unlisted = false;
      const log = await client.lookup(address).catch((error: unknown) => {
        if (error instanceof UnlistedAddressError) {
          unlisted = true;
          return null;
        }
        if (error instanceof NotSignetDomainError) return null;
        throw error;
      });
      if (unlisted) {
        ctx.out(`${address} is unlisted or doesn't exist (its domain won't say); a request goes through the domain's intake`);
        return;
      }
      if (!log) {
        ctx.out(`${address} is not on Signet; mail goes by plain email`);
        return;
      }
      const { card, view } = log;
      const intake = card.intake ? `, intake agent handles ${card.intake.intents.join(', ') || 'requests only'}` : '';
      const shared = view ? `; you can see ${view.members.length} clients (${view.members.map((m) => m.kind).join(', ')})` : '';
      const keys = `${card.requestKeys.length} request key${card.requestKeys.length === 1 ? '' : 's'}`;
      ctx.out(`${address}: verified, ${keys}${intake}${shared}`);
      return;
    }
    case 'request': {
      const to = required(rest[0], 'ADDRESS');
      if (await client.escrowRecipient(to, Boolean(opts['humans-only']))) ctx.out(`note: ${to} has an organisation escrow client, which can read this request`);
      await client.sendRequest(
        to,
        { subject: required(opts.subject, 'subject'), note: opts.note, intent: intentFrom(opts.intent, opts.args) },
        { humansOnly: opts['humans-only'] },
      );
      ctx.out(`request sent to ${to}`);
      return;
    }
    case 'sync': {
      const events = await client.sync();
      const pending = await home.requests();
      const messages = await home.messages();
      for (const event of events) {
        if (event.kind === 'request') {
          if (opts['auto-accept'] && event.admission.admit) {
            ctx.out(`${describe(event)} -> accepted into ${await client.accept(event.request)}`);
            continue;
          }
          pending.push({ receivedAt: new Date().toISOString(), request: event.request, admission: event.admission });
        }
        if (event.kind === 'message') {
          messages.push({ thread: event.thread, message: event.message, sender: { clientId: event.sender.clientId, label: event.sender.label, kind: event.sender.kind } });
        }
        ctx.out(describe(event));
      }
      if (events.length === 0) ctx.out('nothing new');
      await home.write('requests.json', pending);
      await home.write('messages.json', messages);
      return;
    }
    case 'requests': {
      const pending = await home.requests();
      if (pending.length === 0) ctx.out('no requests waiting');
      for (const { request, admission } of pending) {
        ctx.out(`${request.body.id}  ${request.body.from}  "${request.body.subject}"  ${admission.reason}`);
      }
      return;
    }
    case 'accept': {
      const id = required(rest[0], 'REQUEST_ID');
      const pending = await home.requests();
      const found = pending.find((entry) => entry.request.body.id === id);
      if (!found) throw new Error(`no waiting request ${id}`);
      const thread = await client.accept(found.request);
      await home.write('requests.json', pending.filter((entry) => entry !== found));
      ctx.out(`started thread ${thread} with ${found.request.body.from}`);
      return;
    }
    case 'threads': {
      if (client.threadIds.length === 0) ctx.out('no threads');
      for (const thread of client.threadIds) {
        const sibling = client.humansOnlySibling(thread);
        const marks = `${client.isHumansOnly(thread) ? '  [humans only]' : ''}${sibling ? `  (humans-only: ${sibling})` : ''}`;
        ctx.out(`${thread}  ${people(await client.participants(thread))}${marks}`);
      }
      return;
    }
    case 'send': {
      const thread = required(rest[0], 'THREAD');
      const intent = intentFrom(opts.intent, opts.args);
      const message = await client.send(thread, {
        subject: opts.subject ?? '',
        text: required(opts.text, 'text'),
        intents: intent ? [intent] : [],
        files: await filesFrom(opts.attach),
        humansOnly: opts['humans-only'],
      });
      ctx.out(message.thread === thread ? `sent ${message.body.id}` : `sent ${message.body.id} in humans-only thread ${message.thread}`);
      return;
    }
    case 'handoff': {
      const thread = required(rest[0], 'THREAD');
      const reason = required(opts.reason, 'reason');
      await client.send(thread, { subject: 'Handed to a human', text: reason, intents: [{ name: 'handoff.human', args: { reason } }] });
      ctx.out(`handed ${thread} to a human: ${reason}`);
      return;
    }
    case 'rekey': {
      const { removed, added } = await client.rekey(required(rest[0], 'THREAD'));
      ctx.out(`removed ${removed.length}, added ${added.length}`);
      return;
    }
    case 'mail': {
      const to = required(rest[0], 'ADDRESS');
      if (opts.via === 'gmail') {
        const { id } = await client.sendViaGmail(gmail(), [to], {
          subject: required(opts.subject, 'subject'),
          text: required(opts.text, 'text'),
          files: await filesFrom(opts.attach),
          humansOnly: opts['humans-only'],
        });
        ctx.out(`sent to ${to} through Gmail (${id}) with an attested Signet header`);
        return;
      }
      const result = await client.mail(to, {
        subject: required(opts.subject, 'subject'),
        text: required(opts.text, 'text'),
        files: await filesFrom(opts.attach),
        humansOnly: opts['humans-only'],
      });
      ctx.out(result.via === 'smtp' ? `sent to ${to} by plain email` : result.thread ? `sent in ${result.thread}` : `sent a request to ${to}`);
      return;
    }
    case 'gmail-scan': {
      const mailbox = gmail();
      const saved = await home.read<{ historyId: string }>('gmail.json');
      if (!saved) {
        await home.write('gmail.json', { historyId: await mailbox.historyId() });
        ctx.out('watching Gmail from now on; run gmail-scan again to check new mail');
        return;
      }
      const { historyId, offers } = await client.scanGmail(mailbox, saved.historyId);
      await home.write('gmail.json', { historyId });
      if (offers.length === 0) ctx.out('no new mail with a Signet header');
      for (const offer of offers) ctx.out(`${offer.from}: "${offer.subject}"${signetNote(offer.signet)}`);
      return;
    }
    case 'attachment': {
      const [id, index] = [required(rest[0], 'MESSAGE_ID'), Number(required(rest[1], 'INDEX'))];
      const stored = (await home.messages()).find((entry) => entry.message.body.id === id);
      const ref = stored?.message.body.attachments[index];
      if (!ref) throw new Error(`no attachment ${index} on ${id}`);
      const out = required(opts.out, 'out');
      await writeFile(out, await client.fetchAttachment(ref));
      ctx.out(`saved ${ref.name} (${ref.size} bytes) to ${out}`);
      return;
    }
    case 'contact':
      await client.addContact(required(rest[0], 'ADDRESS'));
      ctx.out(`${rest[0]} is a contact`);
      return;
    case 'trust':
      await client.trustDomain(required(rest[0], 'DOMAIN'));
      ctx.out(`trusting ${rest[0]}`);
      return;
    case 'card': {
      ctx.out(await client.contactCard());
      return;
    }
    case 'import-card': {
      const directory = await client.importContactCard(required(rest[0], 'LINK'));
      ctx.out(`kept the contact card for ${directory.principal}; requests go to their own keys`);
      return;
    }
    case 'monitor': {
      const report = await client.monitor();
      for (const alert of report.alerts) ctx.out(`ALERT ${alert}`);
      for (const cert of report.newClients) ctx.out(`new client on your account: ${cert.label ?? cert.kind} (${cert.kind}, ${cert.clientId}). Was this you?`);
      if (report.alerts.length === 0 && report.newClients.length === 0) ctx.out('log history matches this account');
      return;
    }
    default:
      throw new Error(`unknown command ${command}\n\n${USAGE}`);
  }
}
