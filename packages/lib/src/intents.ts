import type { Directory, Grant } from './cards';
import { findGrant, intakeCovers } from './cards';
import type { ClientCert } from './identity';
import { hasScope } from './identity';

export interface Intent {
  name: string;
  args: Record<string, unknown>;
}

export class IntentError extends Error {}

/** An agent asked to commit beyond its certificate's limits: the thread goes to its human. */
export class IntentLimitError extends IntentError {}

type Check = (args: Record<string, unknown>) => string | null;

const isString = (value: unknown): value is string => typeof value === 'string' && value.length > 0;
const isStringList = (value: unknown): value is string[] => Array.isArray(value) && value.every(isString);
const isAmount = (value: unknown): boolean => typeof value === 'number' && Number.isFinite(value) && value > 0;
const optional = (value: unknown, test: (v: unknown) => boolean) => value === undefined || test(value);

/** The core set (v1). Anything else must use a reverse-DNS name, e.g. com.example.quote.request. */
const CORE: Record<string, Check> = {
  'schedule.propose': (a) =>
    optional(a.durationMin, (v) => typeof v === 'number' && v > 0) && optional(a.slots, isStringList) && optional(a.window, isString)
      ? null
      : 'expects durationMin (number), slots (string[]) or window (string)',
  'schedule.confirm': (a) => (isString(a.slot) && optional(a.location, isString) ? null : 'expects slot (string)'),
  'file.request': (a) => (isString(a.description) && optional(a.deadline, isString) ? null : 'expects description (string)'),
  'status.ask': (a) => (isString(a.topic) ? null : 'expects topic (string)'),
  // Asking to be paid, and saying you have. Signet never moves money: payment happens wherever the two
  // sides already pay each other; these only carry the ask and the receipt, signed.
  'pay.request': (a) =>
    isAmount(a.amountUsd) && isString(a.description) && optional(a.due, isString) && optional(a.reference, isString) && optional(a.link, isString)
      ? null
      : 'expects amountUsd (positive number) and description (string), and optionally due, reference and link',
  'pay.sent': (a) => (isAmount(a.amountUsd) && isString(a.reference) && optional(a.method, isString) ? null : 'expects amountUsd (positive number) and reference (string)'),
  // Asking a colleague's agent for information, and its answer. Neither commits anyone: what may be
  // disclosed is the answering side's decision, made with verified facts (see disclosure.ts).
  'info.request': (a) =>
    isString(a.question) && optional(a.purpose, isString) && optional(a.neededBy, isString) && optional(a.claims, Array.isArray)
      ? null
      : 'expects question (string), and optionally purpose, neededBy and claims',
  'info.answer': (a) =>
    isString(a.requestId) && ['answered', 'narrowed', 'refused'].includes(a.decision as string) && optional(a.approvedFor, isString) && optional(a.reason, isString)
      ? null
      : "expects requestId (string) and decision ('answered', 'narrowed' or 'refused')",
  // An agent asking its own owner's devices to decide on a disclosure. Only sent within one account.
  'info.approval': (a) =>
    isString(a.thread) && isString(a.requestId) && isString(a.draft) && isString(a.audienceHash) && Array.isArray(a.audience)
      ? null
      : 'expects thread, requestId, draft and audienceHash (strings) and audience (list)',
  'handoff.human': (a) => (isString(a.reason) ? null : 'expects reason (string)'),
  // Escalate a thread to a live A2A session. The URL is only ever shared inside the thread.
  'session.offer': (a) =>
    a.protocol === 'a2a' && isString(a.url) && isString(a.sessionId) && isString(a.expires) && optional(a.cardHash, isString)
      ? null
      : "expects protocol 'a2a', url, sessionId and expires (strings), and optionally cardHash",
  'session.end': (a) => (isString(a.sessionId) && optional(a.reason, isString) ? null : 'expects sessionId (string)'),
};

/**
 * Intents whose amount commits nobody to anything: an ask to be paid, or a receipt. They need the
 * scope, but no spending limit. Any other intent with `amountUsd` (core or extension) is a commitment.
 */
const NON_COMMITTING = new Set(['pay.request', 'pay.sent']);

/** The amount an intent would commit its sender's owner to, if any. */
const committedAmount = (name: string, intent: Intent): number | undefined => {
  const amount = intent.args?.amountUsd;
  return typeof amount === 'number' && !NON_COMMITTING.has(name) ? amount : undefined;
};

const EXTENSION_NAME = /^[a-z0-9-]+(\.[a-z0-9-]+){2,}$/;

/** `schedule.propose@1` and `schedule.propose` are the same intent; only major version 1 exists. */
export function baseName(name: string): string {
  const [base, version] = name.split('@');
  if (version !== undefined && version !== '1') throw new IntentError(`${base} has no version ${version}`);
  return base;
}

export const isCoreIntent = (name: string): boolean => baseName(name) in CORE;

export function validateIntent(intent: Intent): void {
  const name = baseName(intent.name);
  const check = CORE[name];
  if (check) {
    const problem = check(intent.args ?? {});
    if (problem) throw new IntentError(`${name} ${problem}`);
    return;
  }
  if (!EXTENSION_NAME.test(name)) throw new IntentError(`${name} is not a core intent or a reverse-DNS extension`);
}

/**
 * Sender side, enforced by the owner's own clients: devices may send any intent; agents and tools only
 * what their private scopes name, and never above their `commit_usd` limit. `handoff.human` is always
 * allowed. Receivers check grants instead (`verifyIntentAuthority`), since they never see scopes.
 */
export function checkIntentAuthority(cert: ClientCert, intent: Intent): void {
  validateIntent(intent);
  if (cert.kind === 'device') return;
  const name = baseName(intent.name);
  if (name !== 'handoff.human' && !hasScope(cert, `intent:${name}`)) {
    throw new IntentError(`${cert.label} (${cert.kind}) is not allowed to send ${name}`);
  }
  const amount = committedAmount(name, intent);
  const limit = cert.limits?.commit_usd;
  if (amount !== undefined && amount > (limit ?? 0)) {
    throw new IntentLimitError(`${cert.label} may commit up to $${limit ?? 0}; ${name} asks for $${amount}`);
  }
}

/**
 * Receiver side. Someone's own devices may send any intent, and an owner's own clients accept their
 * agents' intents. Anyone else's agent needs either the intake listing (for the intents it publishes,
 * with no spending authority) or a grant from its owner naming this receiver.
 */
export function verifyIntentAuthority(
  intent: Intent,
  sender: { clientId: string; kind: 'device' | 'agent' | 'escrow' },
  senderDirectory: Directory,
  receiver: string,
  grants: Grant[],
  now = new Date(),
): void {
  validateIntent(intent);
  if (sender.kind === 'device' || senderDirectory.principal === receiver.toLowerCase()) return;
  const name = baseName(intent.name);
  // A live-session offer only opens a channel the receiver may decline; nothing binding happens there.
  // Asking and answering questions commits nobody either; the answering side's own rules govern disclosure.
  if (name === 'handoff.human' || name.startsWith('session.') || name === 'info.request' || name === 'info.answer') return;
  const amount = committedAmount(name, intent);
  const grant = findGrant(grants, senderDirectory, sender.clientId, receiver, name, now);
  if (grant) {
    const limit = grant.limits?.commit_usd ?? 0;
    if (amount !== undefined && amount > limit) {
      throw new IntentLimitError(`${senderDirectory.principal}'s agent may commit up to $${limit} with you; ${name} asks for $${amount}`);
    }
    return;
  }
  if (intakeCovers(senderDirectory.card, sender.clientId, name)) {
    if (amount !== undefined && amount > 0) throw new IntentLimitError(`an intake agent can't commit money; ${name} asks for $${amount}`);
    return;
  }
  throw new IntentError(`${senderDirectory.principal}'s agent has no grant to send ${name} to ${receiver}`);
}
