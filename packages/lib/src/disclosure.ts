/**
 * Asking a colleague's agent for something it may not be free to share.
 *
 * The asking agent sends `info.request`: the question, why it is asking, and claims its organisation
 * signed about its principal ("team:corporate"). The answering agent decides with verified facts rather
 * than guesses from prose: who is asking, which claims check out, and exactly which clients would read an
 * answer. It answers, refuses, or escalates: an approval card goes to its owner's own devices only,
 * showing the draft and that audience. The owner releases to the thread, to the asker's devices only
 * (humans-only), a narrower answer, or nothing. A release is bound to the membership the owner approved:
 * if anyone has joined since, the owner's client refuses to send it until they approve again.
 */
import type { KeyPair } from './crypto';
import { sha256, signJson, verifyJson } from './crypto';
import { canonicalJson } from './encoding';
import type { DomainPolicy } from './directory';
import { splitAddress } from './directory';

/** A statement an organisation signs with its domain key about one of its people, e.g. "team:corporate". */
export interface OrgClaimBody {
  type: 'claim';
  principal: string;
  claim: string;
  issued: string;
  expires: string;
}

export interface OrgClaim {
  body: OrgClaimBody;
  sig: string;
}

export class DisclosureError extends Error {}

export function signOrgClaim(domainKey: KeyPair, principal: string, claim: string, now = new Date(), ttlDays = 30): OrgClaim {
  const body: OrgClaimBody = {
    type: 'claim',
    principal: principal.toLowerCase(),
    claim,
    issued: now.toISOString(),
    expires: new Date(now.getTime() + ttlDays * 86_400_000).toISOString(),
  };
  return { body, sig: signJson(domainKey, body) };
}

/** Signed by the principal's own domain, about this principal, and current. */
export function verifyOrgClaim(claim: OrgClaim, principal: string, policy: DomainPolicy, now = new Date()): boolean {
  const { body } = claim;
  return (
    body?.type === 'claim' &&
    body.principal === principal.toLowerCase() &&
    splitAddress(principal).domain === policy.domain &&
    Date.parse(body.expires) > now.getTime() &&
    verifyJson(policy.domainKey, body, claim.sig)
  );
}

/** One hash for a thread's exact membership: the client ids, sorted. Approvals are bound to it. */
export const audienceHash = (clientIds: string[]): string => sha256(canonicalJson([...clientIds].sort()));

/** Who would read an answer, as the answering side shows it to the person deciding. */
export interface AudienceMember {
  principal: string;
  clientId: string;
  kind: string;
  label?: string;
}

/** What an answering agent knows, verified, about an `info.request`. */
export interface DisclosureContext {
  thread: string;
  requestId: string;
  question: string;
  purpose?: string;
  requester: string;
  /** The asking client's kind in its owner's view: `device`, `agent` or `escrow`. */
  requesterKind: string;
  /** Claims that verified against the requester's domain key; the rest are dropped. */
  claims: string[];
  audience: AudienceMember[];
  audienceHash: string;
}

/** The approval card an agent sends to its owner's devices. */
export interface ApprovalCard extends DisclosureContext {
  draft: string;
}

export type ApprovalChoice =
  | { release: 'thread'; text?: string }
  | { release: 'requester-only'; text?: string }
  | { release: 'refuse'; reason: string };
