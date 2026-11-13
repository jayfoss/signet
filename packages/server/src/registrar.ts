import type { DomainBinding, KeyPair, LogEntry, LogLeaf, Operators, Publication, TrustedLog, VrfKey } from '@signet/lib';
import {
  ReplayCache,
  activeClient,
  attestedSignetHeader,
  hashBody,
  bindIdentity,
  cardHash,
  domainAuthHeaders,
  entryHash,
  hasScope,
  homeAuthHeaders,
  proveIndex,
  replayLog,
  splitAddress,
  verifyCard,
  verifyClientAuth,
  verifyDomainCall,
  verifyView,
  viewHash,
} from '@signet/lib';
import type { HttpRequest, HttpResult } from './http';
import { HttpError, JsonServer, header, json } from './http';

/**
 * What a home asks of the domain owner (Section 6.9.4): the things only the domain key may do. The registrar
 * checks the user's signed publication itself and never signs anything a home hands it.
 */
export interface Registrar {
  /** Record the publication in the transparency log and return the domain's binding for its identity key. */
  bind(publication: Publication): Promise<DomainBinding>;
  /** Record in the transparency log that the address was released. */
  unbind(principal: string): Promise<void>;
  /** Attest outgoing plain email for a user who asked for it (Section 6.9.4). */
  attest(request: AttestRequest): Promise<string>;
}

/**
 * A request to attest plain email. `proof` is the user's own signed request to its home, passed on unchanged, so
 * the registrar can see for itself that one of the user's clients asked for exactly this mail.
 */
export interface AttestRequest {
  principal: string;
  to: string[];
  subject: string;
  bodyHash: string;
  audience?: 'humans';
  /** The home's URL, which the header carries as a hint. */
  server: string;
  proof: { method: string; path: string; body: string; headers: Record<string, string> };
}

const sameSet = (a: string[], b: string[]): boolean => a.length === b.length && [...a].map((x) => x.toLowerCase()).sort().join('\n') === [...b].map((x) => x.toLowerCase()).sort().join('\n');

export interface LocalRegistrarOptions {
  domain: string;
  domainKey: KeyPair;
  log: TrustedLog;
  vrfKey: VrfKey;
  fetchImpl?: typeof fetch;
}

/**
 * The registrar's own logic, in the owner's process. It remembers the account log of every address it has
 * bound and accepts a later publication only if it extends that log, so a home can't swap in a different one.
 */
export class LocalRegistrar implements Registrar {
  private readonly logs = new Map<string, { entries: LogEntry[]; card: string; view: string }>();
  private readonly proofs = new ReplayCache();

  constructor(private readonly options: LocalRegistrarOptions) {}

  /** Whether this registrar has bound the address before. */
  knows(principal: string): boolean {
    return this.logs.has(principal);
  }

  async bind(publication: Publication): Promise<DomainBinding> {
    const state = replayLog(publication.entries);
    verifyCard(publication.card, state.principal, state.identityKey);
    verifyView(publication.view, state.principal, state.identityKey);
    if (publication.card.card.logHead !== state.head || publication.view.view.logHead !== state.head) {
      throw new HttpError(400, 'card and view must be signed for the current log head');
    }
    if (splitAddress(state.principal).domain !== this.options.domain) throw new HttpError(400, `${state.principal} is not on ${this.options.domain}`);
    const known = this.logs.get(state.principal);
    if (known) {
      const extendsKnown = publication.entries.length >= known.entries.length && known.entries.every((entry, i) => entryHash(entry) === entryHash(publication.entries[i]));
      if (!extendsKnown) throw new HttpError(409, 'log must extend the log already bound');
    }
    const card = cardHash(publication.card);
    const view = viewHash(publication.view);
    // The same publication reaching the registrar from another home isn't a new change to log.
    if (!known || known.card !== card || known.view !== view) await this.append(state.principal, 'bound', state.identityKey, publication);
    this.logs.set(state.principal, { entries: structuredClone(publication.entries), card, view });
    return bindIdentity(this.options.domainKey, state.principal, state.identityKey);
  }

  async unbind(principal: string): Promise<void> {
    await this.append(principal, 'unbound', null, null);
    this.logs.delete(principal);
  }

  /** Sign the attestation only for mail one of the user's own clients asked for, as the account log the registrar bound shows it. */
  async attest({ principal, to, subject, bodyHash, audience, server, proof }: AttestRequest): Promise<string> {
    const known = this.logs.get(principal);
    if (!known) throw new HttpError(404, `${principal} is not bound`);
    const state = replayLog(known.entries);
    const cert = activeClient(state, proof.headers['signet-client'] ?? '');
    if (!cert || proof.headers['signet-principal'] !== principal || !hasScope(cert, 'send')) throw new HttpError(403, 'the request was not made by a client of this account that may send');
    if (proof.path !== '/v0/legacy/attest' && proof.path !== '/v0/legacy/send') throw new HttpError(400, 'the proof is not a request for a Signet header');
    const signed = verifyClientAuth(cert.sigKey, proof.headers['signet-sig'], proof.headers['signet-ts'], proof.headers['signet-nonce'], proof.method, proof.path, proof.body);
    if (!signed) throw new HttpError(401, 'the client signature does not verify');
    if (!this.proofs.firstUse(proof.headers['signet-sig'])) throw new HttpError(401, 'this request was already used');
    const asked = JSON.parse(proof.body) as { to?: string[]; subject?: string; text?: string; bodyHash?: string; humansOnly?: boolean };
    // /v0/legacy/send names the text itself; /v0/legacy/attest names its hash.
    const askedHash = asked.bodyHash ?? (typeof asked.text === 'string' ? hashBody(asked.text) : undefined);
    if (!Array.isArray(asked.to) || !sameSet(asked.to, to) || asked.subject !== subject || askedHash !== bodyHash || (asked.humansOnly ? 'humans' : undefined) !== audience) throw new HttpError(403, 'the client asked for different mail');
    return attestedSignetHeader(this.options.domainKey, server, state.identityKey, { from: principal, to, subject, bodyHash, audience });
  }

  private async append(principal: string, kind: LogLeaf['kind'], identityKey: string | null, publication: Publication | null): Promise<void> {
    const leaf: LogLeaf = {
      v: 0,
      index: proveIndex(this.options.vrfKey, principal).index,
      domain: this.options.domain,
      kind,
      identityKey,
      cardHash: publication ? cardHash(publication.card) : null,
      viewHash: publication ? viewHash(publication.view) : null,
      ts: new Date().toISOString(),
    };
    const body = JSON.stringify(leaf);
    const path = '/v0/append';
    const response = await (this.options.fetchImpl ?? fetch)(`${this.options.log.url}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...domainAuthHeaders(this.options.domain, this.options.domainKey, 'POST', path, body) },
      body,
    });
    if (!response.ok) throw new HttpError(502, `transparency log refused the change: ${response.status} ${await response.text()}`);
  }
}

export interface RegistrarServerOptions {
  domain: string;
  /** The registrar's logic. */
  registrar: LocalRegistrar;
  /** The owner's current statement: only the homes it lists may call. */
  operators: Operators;
  domainPublicKey: string;
  /** Decide whether a home may release an address. Without one, no home may: only the owner releases addresses. */
  authorizeUnbind?: (principal: string, home: string) => boolean | Promise<boolean>;
}

/**
 * The registrar as a service the domain owner runs (Section 6.9.4). Homes call it signed with their home
 * keys. It enrolls only addresses the owner approved, takes later publications only if they extend what it
 * bound, and releases an address only if the owner's rule says so.
 */
export class RegistrarServer {
  private readonly server: JsonServer;
  private readonly approved = new Set<string>();
  private readonly replays = new ReplayCache();

  constructor(private readonly options: RegistrarServerOptions) {
    this.server = new JsonServer((request) => this.route(request), 1024 * 1024);
  }

  get url(): string {
    return this.server.publicUrl;
  }

  /** The owner lets the address be enrolled. Homes can't create accounts on their own. */
  approve(principal: string): void {
    this.approved.add(principal);
  }

  listen(port = 0, host = '127.0.0.1', publicUrl?: string): Promise<string> {
    return this.server.listen(port, host, publicUrl);
  }

  close(): Promise<void> {
    return this.server.close();
  }

  private home(request: HttpRequest): string {
    const home = header(request.headers, 'signet-home');
    const policy = { domain: this.options.domain, domainKey: this.options.domainPublicKey, operators: this.options.operators };
    const ok = verifyDomainCall(
      policy,
      { sig: header(request.headers, 'signet-sig'), ts: header(request.headers, 'signet-ts'), nonce: header(request.headers, 'signet-nonce'), home },
      request.method,
      request.path,
      request.body,
    );
    if (!ok) throw new HttpError(401, 'calls to the registrar are signed by a home the owner listed');
    if (!this.replays.firstUse(header(request.headers, 'signet-sig'))) throw new HttpError(401, 'this call was already used');
    return home;
  }

  private async route(request: HttpRequest): Promise<HttpResult> {
    if (request.method !== 'POST') throw new HttpError(404, 'not found');
    const home = this.home(request);
    if (request.url.pathname === '/v0/registrar/bind') {
      const publication = json<Publication>(request);
      const { principal } = replayLog(publication.entries);
      if (!this.options.registrar.knows(principal) && !this.approved.has(principal)) throw new HttpError(403, `${principal} has not been approved for enrollment by the domain owner`);
      return this.options.registrar.bind(publication);
    }
    if (request.url.pathname === '/v0/registrar/unbind') {
      const { principal } = json<{ principal: string }>(request);
      if (!(await this.options.authorizeUnbind?.(principal, home))) throw new HttpError(403, 'only the domain owner releases an address');
      await this.options.registrar.unbind(principal);
      return {};
    }
    if (request.url.pathname === '/v0/registrar/attest') return { header: await this.options.registrar.attest(json<AttestRequest>(request)) };
    throw new HttpError(404, 'not found');
  }
}

export interface HttpRegistrarOptions {
  /** The registrar's base URL. */
  url: string;
  domain: string;
  /** This home's key, which the owner's statement lists. */
  homeKey: KeyPair;
  fetchImpl?: typeof fetch;
}

/** A home's connection to the owner's registrar service. */
export class HttpRegistrar implements Registrar {
  constructor(private readonly options: HttpRegistrarOptions) {}

  bind(publication: Publication): Promise<DomainBinding> {
    return this.post('/v0/registrar/bind', publication) as Promise<DomainBinding>;
  }

  async unbind(principal: string): Promise<void> {
    await this.post('/v0/registrar/unbind', { principal });
  }

  async attest(request: AttestRequest): Promise<string> {
    return ((await this.post('/v0/registrar/attest', request)) as { header: string }).header;
  }

  private async post(path: string, payload: unknown): Promise<unknown> {
    const body = JSON.stringify(payload);
    const response = await (this.options.fetchImpl ?? fetch)(`${this.options.url}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...homeAuthHeaders(this.options.domain, this.options.homeKey, 'POST', path, body) },
      body,
    });
    if (!response.ok) {
      const { error } = (await response.json().catch(() => ({ error: 'registrar error' }))) as { error?: string };
      throw new HttpError(response.status >= 500 ? 502 : response.status, `registrar: ${error ?? response.status}`);
    }
    return response.json();
  }
}
