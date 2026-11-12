import type { Directory, Grant, PublicCard, SignedView } from './cards';
import { acceptPresentedView, requestKeyId, viewMember } from './cards';
import type { Sealed } from './crypto';
import { open, randomId, seal, signJson, verifyJson } from './crypto';
import { canonicalJson, utf8 } from './encoding';
import type { ClientKeys } from './identity';
import type { Intent } from './intents';
import { checkIntentAuthority, verifyIntentAuthority } from './intents';

export const MAX_REQUEST_BYTES = 8192;
export const MAX_NOTE_CHARS = 500;

/** A contact's signed statement that `introduced` may reach `to` about `context`, until `expires`. */
export interface IntroductionBody {
  type: 'intro';
  introducer: string;
  introducerClient: string;
  introduced: string;
  to: string;
  context: string;
  expires: string;
}

/** Carries the introducer's own contact view, so the recipient can check the signature without a lookup grant. */
export interface Introduction {
  body: IntroductionBody;
  sig: string;
  introducerView: SignedView;
}

/**
 * What an unadmitted sender may say: who they are, one typed intent, a short note. The sender presents
 * its own contact view, so the recipient can verify it and, if admitted, add its clients to a thread.
 */
export interface RequestBody {
  v: 0;
  type: 'request';
  id: string;
  from: string;
  fromClient: string;
  to: string;
  subject: string;
  intent?: Intent;
  note?: string;
  introduction?: Introduction;
  /** Grants naming the recipient, when an agent sends an intent beyond what intake allows. */
  grants?: Grant[];
  /**
   * Lets the recipient deliver its welcome without revealing who it is to the sender's server: the
   * sender has registered this token's hash with its own home server.
   */
  replyToken?: string;
  /** `humans`: the sender asks that no agent read this, and it is sealed only to the recipient's devices. */
  audience?: 'humans';
  senderView: SignedView;
  ts: string;
}

export interface SignedRequest {
  body: RequestBody;
  sig: string;
}

export interface SealedCopy {
  /** For requests: the request key's id from the card. For legacy mail: the client id. */
  clientId: string;
  sealed: Sealed;
}

/**
 * One sealed copy per request key on the recipient's public card. The server sees only to and size,
 * plus `from` unless the request is anonymous, in which case the sender is only inside the sealed copies.
 */
export interface SealedRequest {
  from?: string;
  to: string;
  copies: SealedCopy[];
}

export class RequestError extends Error {}

export const requestInfo = (to: string) => `signet0 request ${to}`;

export function createIntroduction(
  introducer: ClientKeys,
  introducerView: SignedView,
  introduced: string,
  to: string,
  context: string,
  now = new Date(),
  ttlDays = 14,
): Introduction {
  const body: IntroductionBody = {
    type: 'intro',
    introducer: introducer.cert.principal,
    introducerClient: introducer.cert.clientId,
    introduced,
    to,
    context,
    expires: new Date(now.getTime() + ttlDays * 86_400_000).toISOString(),
  };
  return { body, sig: signJson(introducer.signing, body), introducerView };
}

/** True when the introduction names this sender and recipient, hasn't expired, and a current client of the introducer signed it. */
export function verifyIntroduction(intro: Introduction, request: RequestBody, introducer: Directory, now = new Date()): boolean {
  const { body } = intro;
  if (body.introduced !== request.from || body.to !== request.to || body.introducer !== introducer.principal) return false;
  if (Date.parse(body.expires) <= now.getTime()) return false;
  try {
    const member = viewMember(acceptPresentedView(intro.introducerView, introducer), body.introducerClient, now);
    return member !== undefined && verifyJson(member.sigKey, body, intro.sig);
  } catch {
    return false;
  }
}

export async function createRequest(
  sender: ClientKeys,
  senderView: SignedView,
  recipient: { principal: string; card: Pick<PublicCard, 'requestKeys' | 'humanKeys'> },
  fields: { subject: string; intent?: Intent; note?: string; introduction?: Introduction; replyToken?: string; grants?: Grant[]; humansOnly?: boolean },
  now = new Date(),
  anonymous = false,
): Promise<SealedRequest> {
  if (fields.intent) checkIntentAuthority(sender.cert, fields.intent);
  if (fields.note && fields.note.length > MAX_NOTE_CHARS) throw new RequestError(`notes are limited to ${MAX_NOTE_CHARS} characters`);
  const body: RequestBody = {
    v: 0,
    type: 'request',
    id: randomId('r'),
    from: sender.cert.principal,
    fromClient: sender.cert.clientId,
    to: recipient.principal,
    subject: fields.subject,
    intent: fields.intent,
    note: fields.note,
    introduction: fields.introduction,
    grants: fields.grants?.filter((grant) => grant.counterparty === recipient.principal.toLowerCase()),
    replyToken: fields.replyToken,
    audience: fields.humansOnly ? 'humans' : undefined,
    senderView,
    ts: now.toISOString(),
  };
  const bytes = utf8(canonicalJson({ body, sig: signJson(sender.signing, body) }));
  if (bytes.length > MAX_REQUEST_BYTES) {
    throw new RequestError(`request is ${bytes.length} bytes; the limit is ${MAX_REQUEST_BYTES}`);
  }
  const keys = fields.humansOnly ? recipient.card.humanKeys : recipient.card.requestKeys;
  if (keys.length === 0) throw new RequestError(`${recipient.principal} has no ${fields.humansOnly ? 'device' : 'client'} that can receive this`);
  return {
    from: anonymous ? undefined : body.from,
    to: body.to,
    copies: await Promise.all(
      keys.map(async (key) => ({ clientId: key.keyId, sealed: await seal(key.agreeKey, bytes, requestInfo(body.to)) })),
    ),
  };
}

export const myCopy = (me: ClientKeys, request: SealedRequest): SealedCopy | undefined =>
  request.copies.find((candidate) => candidate.clientId === requestKeyId(me.cert.agreeKey));

/**
 * Open this client's copy and check it: signed by a current client in the sender's presented contact
 * view, which must be signed by the sender's identity key and be the one the transparency log holds.
 * The sender is looked up only after decrypting, because an anonymous request names it only inside.
 */
export async function openRequest(
  me: ClientKeys,
  request: SealedRequest,
  lookup: (address: string) => Promise<Directory>,
  now = new Date(),
): Promise<SignedRequest> {
  const copy = myCopy(me, request);
  if (!copy) throw new RequestError('no copy of this request for this client');
  const signed = JSON.parse((await open(me.agreement, copy.sealed, requestInfo(me.cert.principal))).toString()) as SignedRequest;
  const { body } = signed;
  if (body.to !== me.cert.principal || (request.from && body.from !== request.from)) {
    throw new RequestError('request envelope does not match its contents');
  }
  const sender = await lookup(body.from);
  let member;
  try {
    member = viewMember(acceptPresentedView(body.senderView, sender), body.fromClient, now);
  } catch (error) {
    throw new RequestError(error instanceof Error ? error.message : String(error));
  }
  if (!member || !verifyJson(member.sigKey, body, signed.sig)) throw new RequestError('request is not signed by an active sender client');
  if (body.intent) verifyIntentAuthority(body.intent, member, sender, me.cert.principal, body.grants ?? [], now);
  return signed;
}
