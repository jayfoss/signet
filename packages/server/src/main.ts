/* eslint-disable no-console */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { GatewayKey, KeyPair, Operators, OperatorHome, Resolver, TrustedLog, VrfKey } from '@signet/lib';
import { DnsResolver, FileSeqStore, StaticResolver, exportIssuerKey, generateIssuerKey, generateSigningKey, importIssuerKey, signOperators } from '@signet/lib';
import type { ClusterMember } from './cluster';
import { IssuerServer } from './issuer-server';
import { TransparencyLogServer } from './log-server';
import { HttpRegistrar, LocalRegistrar, RegistrarServer } from './registrar';
import { RelayServer } from './relay-server';
import type { Limits } from './server';
import { SignetServer } from './server';
import { InboundSmtp, OutboundSmtp } from './smtp';
import { ClusterWitness } from './witness';

/**
 * SIGNET_ROLE            "home" (default), "log", "issuer" (Privacy Pass), "relay" (Oblivious HTTP), "witness" (a replica
 *                        that only keeps the log and votes), "registrar" (the domain owner's service) or "sign-operators"
 *                        (print the owner's signed list of homes and exit)
 * SIGNET_KEY             JSON {"publicKey","privateKey"}: the domain key, or the log key. Unset: kept in SIGNET_DATA_DIR
 * SIGNET_DATA_DIR        folder for everything that must survive a restart: accounts and mailboxes (home), leaves
 *                        (log), the issuer key, and each role's own key. Unset: in memory, with a throwaway key
 * SIGNET_PUBLIC_URL      URL published in the policy (defaults to the listen address)
 * SIGNET_STATIC_SERVERS  JSON {"domain": "url"} to skip DNS, e.g. for local testing
 * PORT                   HTTP port (4100)
 *
 * Home servers also read:
 * SIGNET_DOMAIN          domain this server answers for (required)
 * SIGNET_LOG             JSON {"url","key"} of the transparency log (required)
 * SIGNET_OPEN_ENROLLMENT "1" lets anyone enroll over HTTP (demo only)
 * SIGNET_INTAKE        "1" runs a domain intake, so users can choose to be unlisted
 * SIGNET_SMTP_PORT       port for inbound plain email (off if unset)
 * SIGNET_SMTP_TLS_KEY / SIGNET_SMTP_TLS_CERT  files for STARTTLS
 * SIGNET_SMTP_RELAY      JSON {"host","port","secure","auth"} for outbound plain email (direct to MX if unset)
 * SIGNET_DKIM            JSON {"selector","privateKey"} to DKIM-sign outbound plain email
 * SIGNET_ISSUER          JSON {"url","key":{"name","publicKey"}} of the Privacy Pass issuer (anonymous requests)
 * SIGNET_OHTTP_RELAY     URL of the Oblivious HTTP relay for sealed and anonymous deliveries
 * SIGNET_LIMITS          JSON of daily limits to change, e.g. {"requestsPerSenderPerDay":2}. Each home counts its own,
 *                        so a domain with N homes can accept up to N times a limit; an owner who minds sets it lower
 *
 * Issuers read SIGNET_ISSUER_NAME. Their RSA key is kept in SIGNET_DATA_DIR.
 *
 * One operator, several replicas (Section 6.8). Home servers and witnesses read:
 * SIGNET_CLUSTER_ID           this replica's identifier (turns clustering on)
 * SIGNET_CLUSTER_MEMBERS      JSON [{"id","url","role":"home"|"witness"}] listing every replica, this one included
 * SIGNET_CLUSTER_ELECTION_MS  election timeout T (1000)
 * SIGNET_CLUSTER_SNAPSHOT_EVERY  compact the log after this many applied entries (1000; 0 turns it off)
 * SIGNET_CLUSTER_REJOIN       "1" when this replica lost its storage and rejoins under its old identifier
 * SIGNET_VRF_KEY, SIGNET_GATEWAY_KEY, SIGNET_INTAKE_KEY   JSON keys every replica of a home must share
 * The replicas' log is kept in SIGNET_DATA_DIR, which a cluster requires.
 *
 * Several operators (Section 6.9). A home that isn't run by the domain owner reads:
 * SIGNET_HOME_KEY             JSON {"publicKey","privateKey"}: this home's key. Setting it means no domain key
 * SIGNET_OPERATORS            the owner's signed statement, as JSON or a path to a file of it
 * SIGNET_DOMAIN_PUBLIC_KEY    the domain's public key
 * SIGNET_REGISTRAR_URL        the owner's registrar
 * Resolvers also read SIGNET_STATIC_PINS, JSON {"domain": "publicKey"}, the way a dk field pins a domain in DNS.
 *
 * The owner runs "registrar" with SIGNET_DOMAIN, SIGNET_KEY (the domain key), SIGNET_LOG, SIGNET_VRF_KEY,
 * SIGNET_OPERATORS and SIGNET_REGISTRAR_APPROVE (comma-separated addresses it may enroll), and signs the statement
 * with "sign-operators" using SIGNET_KEY, SIGNET_DOMAIN, SIGNET_OPERATORS_SEQ, SIGNET_OPERATORS_EXPIRES (ISO time)
 * and SIGNET_OPERATORS_HOMES (JSON [{"url","key","replicas","ohttp"}]).
 */
const env = (name: string): string | undefined => process.env[name] || undefined;
const jsonEnv = <T>(name: string): T | undefined => {
  const value = env(name);
  return value ? (JSON.parse(value) as T) : undefined;
};

const dataDir = (): string | undefined => {
  const dir = env('SIGNET_DATA_DIR');
  if (dir) mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
};

/** A JSON file in the data folder, created by `make` on first start and read on every start after. */
function kept<T>(name: string, make: () => T, save: (value: T) => unknown = (value) => value, load: (saved: never) => T = (saved) => saved): T | undefined {
  const dir = dataDir();
  if (!dir) return undefined;
  const file = join(dir, name);
  if (existsSync(file)) return load(JSON.parse(readFileSync(file, 'utf8')) as never);
  const value = make();
  writeFileSync(file, JSON.stringify(save(value)), { mode: 0o600 });
  return value;
}

function key(): KeyPair {
  const configured = jsonEnv<KeyPair>('SIGNET_KEY') ?? kept('key.json', generateSigningKey);
  if (configured) return configured;
  console.warn('SIGNET_KEY and SIGNET_DATA_DIR are unset; using a throwaway key, and nothing survives a restart');
  return generateSigningKey();
}

function resolver(): Resolver {
  const servers = jsonEnv<Record<string, string | string[]>>('SIGNET_STATIC_SERVERS');
  const pins = jsonEnv<Record<string, string>>('SIGNET_STATIC_PINS');
  const made = servers ? new StaticResolver(new Map(Object.entries(servers)), fetch, new Map(Object.entries(pins ?? {}))) : new DnsResolver();
  // The highest operators statement seen survives a restart, so an old one can't be played back.
  const dir = dataDir();
  if (dir) made.seqStore = new FileSeqStore(join(dir, 'operators-seq.json'));
  return made;
}

/** JSON given inline, or in the file the value names. */
function jsonOrFile<T>(name: string): T | undefined {
  const value = env(name);
  if (!value) return undefined;
  return JSON.parse(value.trim().startsWith('{') || value.trim().startsWith('[') ? value : readFileSync(value, 'utf8')) as T;
}

function clusterConfig() {
  const id = env('SIGNET_CLUSTER_ID');
  if (!id) return undefined;
  const members = jsonEnv<ClusterMember[]>('SIGNET_CLUSTER_MEMBERS');
  const dir = dataDir();
  if (!members) throw new Error('SIGNET_CLUSTER_MEMBERS is required with SIGNET_CLUSTER_ID');
  if (!dir) throw new Error('a cluster replica keeps its log in SIGNET_DATA_DIR, which must be set');
  const every = env('SIGNET_CLUSTER_SNAPSHOT_EVERY');
  return {
    id,
    members,
    dataDir: join(dir, 'raft'),
    electionMs: Number(env('SIGNET_CLUSTER_ELECTION_MS') ?? 1000),
    rejoin: env('SIGNET_CLUSTER_REJOIN') === '1',
    snapshotEvery: every === undefined ? undefined : Number(every),
  };
}

/** The key a home's replicas share: its own key in operator mode, otherwise the domain key. */
function sharedKey(): KeyPair {
  return jsonEnv<KeyPair>('SIGNET_HOME_KEY') ?? key();
}

async function main(): Promise<void> {
  const port = Number(env('PORT') ?? 4100);
  if (env('SIGNET_ROLE') === 'log') {
    const dir = dataDir();
    const log = new TransparencyLogServer(key(), resolver(), undefined, dir ? join(dir, 'leaves.jsonl') : undefined);
    const url = await log.listen(port, '0.0.0.0', env('SIGNET_PUBLIC_URL'));
    console.log(`signet transparency log at ${url}, key ${log.publicKey}`);
    return;
  }

  if (env('SIGNET_ROLE') === 'issuer') {
    const name = env('SIGNET_ISSUER_NAME') ?? 'issuer.signet';
    const issuerKey = kept('issuer-key.json', () => generateIssuerKey(name), exportIssuerKey, importIssuerKey);
    const issuer = new IssuerServer(name, resolver(), undefined, issuerKey);
    const url = await issuer.listen(port, '0.0.0.0', env('SIGNET_PUBLIC_URL'));
    console.log(`signet Privacy Pass issuer at ${url}: ${JSON.stringify(issuer.publicKey)}`);
    return;
  }
  if (env('SIGNET_ROLE') === 'relay') {
    const relay = new RelayServer(resolver());
    console.log(`signet OHTTP relay at ${await relay.listen(port, '0.0.0.0', env('SIGNET_PUBLIC_URL'))}`);
    return;
  }

  if (env('SIGNET_ROLE') === 'sign-operators') {
    const domain = env('SIGNET_DOMAIN');
    const homes = jsonEnv<OperatorHome[]>('SIGNET_OPERATORS_HOMES');
    if (!domain || !homes || !env('SIGNET_OPERATORS_SEQ') || !env('SIGNET_OPERATORS_EXPIRES')) throw new Error('SIGNET_DOMAIN, SIGNET_OPERATORS_HOMES, SIGNET_OPERATORS_SEQ and SIGNET_OPERATORS_EXPIRES are required');
    console.log(JSON.stringify(signOperators(key(), { domain, seq: Number(env('SIGNET_OPERATORS_SEQ')), notAfter: new Date(env('SIGNET_OPERATORS_EXPIRES') as string).toISOString(), homes })));
    return;
  }

  if (env('SIGNET_ROLE') === 'witness') {
    const domain = env('SIGNET_DOMAIN');
    const cluster = clusterConfig();
    if (!domain || !cluster) throw new Error('SIGNET_DOMAIN and SIGNET_CLUSTER_ID are required');
    const witness = new ClusterWitness({ ...cluster, domain, domainKey: sharedKey() });
    console.log(`signet witness ${cluster.id} for ${domain} at ${await witness.listen(port, '0.0.0.0', env('SIGNET_PUBLIC_URL'))}`);
    return;
  }

  if (env('SIGNET_ROLE') === 'registrar') {
    const domain = env('SIGNET_DOMAIN');
    const log = jsonEnv<TrustedLog>('SIGNET_LOG');
    const vrfKey = jsonEnv<VrfKey>('SIGNET_VRF_KEY');
    const operators = jsonOrFile<Operators>('SIGNET_OPERATORS');
    if (!domain || !log || !vrfKey || !operators) throw new Error('SIGNET_DOMAIN, SIGNET_LOG, SIGNET_VRF_KEY and SIGNET_OPERATORS are required');
    const domainKey = key();
    const registrar = new RegistrarServer({ domain, registrar: new LocalRegistrar({ domain, domainKey, log, vrfKey }), operators, domainPublicKey: domainKey.publicKey });
    for (const address of (env('SIGNET_REGISTRAR_APPROVE') ?? '').split(',').filter(Boolean)) registrar.approve(address.trim());
    console.log(`signet registrar for ${domain} at ${await registrar.listen(port, '0.0.0.0', env('SIGNET_PUBLIC_URL'))}`);
    return;
  }

  const domain = env('SIGNET_DOMAIN');
  const log = jsonEnv<TrustedLog>('SIGNET_LOG');
  if (!domain || !log) throw new Error('SIGNET_DOMAIN and SIGNET_LOG are required');
  const homeKey = jsonEnv<KeyPair>('SIGNET_HOME_KEY');
  const cluster = clusterConfig();
  const operatorMode = homeKey
    ? {
        homeKey,
        operators: jsonOrFile<Operators>('SIGNET_OPERATORS'),
        domainPublicKey: env('SIGNET_DOMAIN_PUBLIC_KEY'),
        registrar: env('SIGNET_REGISTRAR_URL') ? new HttpRegistrar({ url: env('SIGNET_REGISTRAR_URL') as string, domain, homeKey }) : undefined,
      }
    : { domainKey: key() };
  const server = new SignetServer({
    domain,
    ...operatorMode,
    cluster,
    vrfKey: jsonEnv<VrfKey>('SIGNET_VRF_KEY'),
    gatewayKey: jsonEnv<GatewayKey>('SIGNET_GATEWAY_KEY'),
    intakeKey: jsonEnv<KeyPair>('SIGNET_INTAKE_KEY'),
    resolver: resolver(),
    log,
    publicUrl: env('SIGNET_PUBLIC_URL'),
    openEnrollment: env('SIGNET_OPEN_ENROLLMENT') === '1',
    dataDir: cluster ? undefined : dataDir(),
    intake: env('SIGNET_INTAKE') === '1',
    outbound: new OutboundSmtp(domain, { relay: jsonEnv('SIGNET_SMTP_RELAY'), dkim: jsonEnv('SIGNET_DKIM') }),
    issuer: jsonEnv('SIGNET_ISSUER'),
    ohttpRelay: env('SIGNET_OHTTP_RELAY'),
    limits: jsonEnv<Partial<Limits>>('SIGNET_LIMITS'),
  });
  const url = await server.listen(port, '0.0.0.0');
  console.log(`signet home server for ${domain} at ${url}`);

  const smtpPort = env('SIGNET_SMTP_PORT');
  if (smtpPort) {
    const tlsKey = env('SIGNET_SMTP_TLS_KEY');
    const tlsCert = env('SIGNET_SMTP_TLS_CERT');
    const smtp = new InboundSmtp(server, tlsKey && tlsCert ? { tls: { key: readFileSync(tlsKey), cert: readFileSync(tlsCert) } } : {});
    console.log(`accepting plain email for ${domain} on port ${await smtp.listen(Number(smtpPort), '0.0.0.0')}`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
