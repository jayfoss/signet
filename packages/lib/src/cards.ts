/**
 * What other people get to see of an account, in three tiers:
 *
 * - **Public card** (anyone): the identity key, the keys a request can be sealed to, and the intake
 *   agent if there is one, with the intents it handles for strangers. No client ids beyond the intake,
 *   no labels, no scopes. Five devices are five unlabeled keys.
 * - **Contact view** (people the owner admitted): each client's keys and whether it is a device or an
 *   agent, plus revoked grants. Still no labels or scopes.
 * - **Private log** (the owner and its home server): labels, scopes, limits.
 *
 * Deeper authority for an agent is a per-contact **grant**, signed by the identity key and shown only to
 * the counterparty it names.
 */
import type { KeyPair } from './crypto';
import { sha256, signJson, verifyJson } from './crypto';
import { canonicalJson } from './encoding';
import type { ClientCert, KeyHistory, LogState, SignedKeyLink } from './identity';
import { activeClient, activeClients, grantKeys, hasScope, keyHistory } from './identity';

export interface RequestKey {
  keyId: string;
  agreeKey: string;
}

export interface PublicCard {
  v: 0;
  type: 'card';
  principal: string;
  identityKey: string;
  logHead: string;
  requestKeys: RequestKey[];
  /**
   * Where mail a sender marks humans-only goes: the owner's devices, plus any agents the owner opted in.
   * The sender only asks; this list, which the owner signs, decides. Unlabeled.
   */
  humanKeys: RequestKey[];
  intake?: { clientId: string; agreeKey: string; intents: string[] };
  /** Every identity-key change since genesis, so a contact who pinned an older key can follow it. */
  keyChain?: SignedKeyLink[];
}

export interface ViewMember {
  clientId: string;
  /** `escrow`: the organisation's escrow client. Contacts are told plainly that it receives everything. */
  kind: 'device' | 'agent' | 'escrow';
  sigKey: string;
  agreeKey: string;
  /** Joins every thread (holds read:*). */
  reads: boolean;
  /** Receives messages a sender marked humans-only: devices, and agents the owner opted in. */
  humansOnly: boolean;
  expires: string;
}

export interface ContactView {
  v: 0;
  type: 'view';
  principal: string;
  identityKey: string;
  logHead: string;
  members: ViewMember[];
  revokedGrants: string[];
}

export interface SignedCard {
  card: PublicCard;
  sig: string;
}

export interface SignedView {
  view: ContactView;
  sig: string;
}

export interface GrantBody {
  v: 0;
  type: 'grant';
  id: string;
  principal: string;
  agent: string;
  counterparty: string;
  intents: string[];
  limits?: Record<string, number>;
  expires: string;
}

export interface Grant extends GrantBody {
  sig: string;
}

/** What a verified lookup yields. `view` only for contacts; `log` only for the owner's own clients. */
export interface Directory {
  principal: string;
  identityKey: string;
  card: PublicCard;
  view?: ContactView;
  /** The view hash the transparency log holds right now; a presented view must match it. */
  viewHash: string | null;
  index: string;
  log?: LogState;
}

export const cardKeyHistory = (card: PublicCard): KeyHistory => keyHistory(card.principal, card.keyChain ?? [], card.identityKey);

export const requestKeyId = (agreeKey: string): string => sha256(`signet0 request key ${agreeKey}`);
export const cardHash = (signed: SignedCard): string => sha256(canonicalJson(signed));
export const viewHash = (signed: SignedView): string => sha256(canonicalJson(signed));

/**
 * Who receives mail a sender marked humans-only: devices, agents the owner opted in, and always the
 * organisation's escrow client. Escrow that skips some mail isn't escrow, so neither the sender's flag nor
 * the owner's policy can keep it out.
 */
export const readsHumansOnly = (log: LogState, cert: ClientCert): boolean =>
  cert.kind === 'device' || cert.kind === 'org-escrow' || log.agentsReadHumansOnly.has(cert.clientId);

const isEscrow = (cert: ClientCert): boolean => cert.kind === 'org-escrow';

export function cardFromLog(log: LogState, now = new Date()): PublicCard {
  const active = activeClients(log, now);
  const intakeCert = log.intake ? activeClient(log, log.intake.clientId, now) : undefined;
  const front = log.intake?.exclusive && intakeCert ? [intakeCert] : active.filter((cert) => hasScope(cert, 'admit') || cert === intakeCert);
  // Escrow gets a copy of every request too, even with an exclusive intake.
  const admitters = [...front, ...active.filter((cert) => isEscrow(cert) && !front.includes(cert))];
  return {
    v: 0,
    type: 'card',
    principal: log.principal,
    identityKey: log.identityKey,
    logHead: log.head,
    requestKeys: admitters.map((cert) => ({ keyId: requestKeyId(cert.agreeKey), agreeKey: cert.agreeKey })),
    humanKeys: active.filter((cert) => readsHumansOnly(log, cert)).map((cert) => ({ keyId: requestKeyId(cert.agreeKey), agreeKey: cert.agreeKey })),
    intake: intakeCert && log.intake ? { clientId: intakeCert.clientId, agreeKey: intakeCert.agreeKey, intents: log.intake.intents } : undefined,
    keyChain: log.keyChain.length > 0 ? log.keyChain : undefined,
  };
}

export function viewFromLog(log: LogState, now = new Date()): ContactView {
  return {
    v: 0,
    type: 'view',
    principal: log.principal,
    identityKey: log.identityKey,
    logHead: log.head,
    members: activeClients(log, now).map((cert) => ({
      clientId: cert.clientId,
      kind: cert.kind === 'device' ? 'device' : isEscrow(cert) ? 'escrow' : 'agent',
      sigKey: cert.sigKey,
      agreeKey: cert.agreeKey,
      reads: hasScope(cert, 'read:*') || isEscrow(cert),
      humansOnly: readsHumansOnly(log, cert),
      expires: cert.expires,
    })),
    revokedGrants: [...log.revokedGrants],
  };
}

export const signCard = (key: KeyPair, card: PublicCard): SignedCard => ({ card, sig: signJson(key, card) });
export const signView = (key: KeyPair, view: ContactView): SignedView => ({ view, sig: signJson(key, view) });
export const signGrant = (key: KeyPair, body: GrantBody): Grant => ({ ...body, sig: signJson(key, body) });

export class CardError extends Error {}

export function verifyCard(signed: SignedCard, principal: string, identityKey: string): PublicCard {
  const { card } = signed;
  if (card.principal !== principal || card.identityKey !== identityKey || !verifyJson(identityKey, card, signed.sig)) {
    throw new CardError(`card for ${principal} is not signed by its identity key`);
  }
  try {
    keyHistory(principal, card.keyChain ?? [], identityKey);
  } catch (error) {
    throw new CardError(error instanceof Error ? error.message : String(error));
  }
  return card;
}

export function verifyView(signed: SignedView, principal: string, identityKey: string): ContactView {
  const { view } = signed;
  if (view.principal !== principal || view.identityKey !== identityKey || !verifyJson(identityKey, view, signed.sig)) {
    throw new CardError(`contact view for ${principal} is not signed by its identity key`);
  }
  return view;
}

/** A view someone presented themselves (in a request or introduction): signed, and the one the log holds now. */
export function acceptPresentedView(signed: SignedView, directory: Directory): ContactView {
  const view = verifyView(signed, directory.principal, directory.identityKey);
  if (directory.viewHash !== viewHash(signed)) throw new CardError(`contact view for ${directory.principal} is not current`);
  return view;
}

export function viewMember(view: ContactView | undefined, clientId: string, now = new Date()): ViewMember | undefined {
  const member = view?.members.find((candidate) => candidate.clientId === clientId);
  return member && Date.parse(member.expires) > now.getTime() ? member : undefined;
}

const covers = (patterns: string[], intent: string): boolean =>
  patterns.some((pattern) => pattern === intent || (pattern.endsWith('*') && intent.startsWith(pattern.slice(0, -1))));

/** A grant from `directory`'s owner letting `agent` send `intent` to `verifier`. */
export function findGrant(grants: Grant[], directory: Directory, agent: string, verifier: string, intent: string, now = new Date()): Grant | undefined {
  return grants.find((grant) => {
    const { sig, ...body } = grant;
    return (
      grant.principal === directory.principal &&
      grant.agent === agent &&
      grant.counterparty === verifier.toLowerCase() &&
      Date.parse(grant.expires) > now.getTime() &&
      !directory.view?.revokedGrants.includes(grant.id) &&
      covers(grant.intents, intent) &&
      grantKeys(cardKeyHistory(directory.card)).some((key) => verifyJson(key, body, sig))
    );
  });
}

export const intakeCovers = (card: PublicCard, clientId: string, intent: string): boolean =>
  card.intake?.clientId === clientId && covers(card.intake.intents, intent);
