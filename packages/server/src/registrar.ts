import type { DomainBinding, KeyPair, LogLeaf, Publication, TrustedLog, VrfKey } from '@signet/lib';
import { bindIdentity, cardHash, domainAuthHeaders, proveIndex, replayLog, splitAddress, verifyCard, verifyView, viewHash } from '@signet/lib';
import { HttpError } from './http';

/**
 * What a home asks of the domain owner (Section 6.9.4): the things only the domain key may do. The registrar
 * checks the user's signed publication itself and never signs anything a home hands it.
 */
export interface Registrar {
  /** Record the publication in the transparency log and return the domain's binding for its identity key. */
  bind(publication: Publication): Promise<DomainBinding>;
  /** Record in the transparency log that the address was released. */
  unbind(principal: string): Promise<void>;
}

export interface LocalRegistrarOptions {
  domain: string;
  domainKey: KeyPair;
  log: TrustedLog;
  vrfKey: VrfKey;
  fetchImpl?: typeof fetch;
}

/** A registrar in the same process as its caller. A deployment puts one behind a network call the domain owner runs. */
export class LocalRegistrar implements Registrar {
  constructor(private readonly options: LocalRegistrarOptions) {}

  async bind(publication: Publication): Promise<DomainBinding> {
    const state = replayLog(publication.entries);
    verifyCard(publication.card, state.principal, state.identityKey);
    verifyView(publication.view, state.principal, state.identityKey);
    if (publication.card.card.logHead !== state.head || publication.view.view.logHead !== state.head) {
      throw new HttpError(400, 'card and view must be signed for the current log head');
    }
    if (splitAddress(state.principal).domain !== this.options.domain) throw new HttpError(400, `${state.principal} is not on ${this.options.domain}`);
    await this.append(state.principal, 'bound', state.identityKey, publication);
    return bindIdentity(this.options.domainKey, state.principal, state.identityKey);
  }

  async unbind(principal: string): Promise<void> {
    await this.append(principal, 'unbound', null, null);
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
