import type { AttachmentRef } from './attachments';
import type { Directory, Grant, ViewMember } from './cards';
import { randomId, signJson, verifyJson } from './crypto';
import { MAX_HTML_BYTES } from './html';
import type { ClientKeys } from './identity';
import type { Intent } from './intents';
import { checkIntentAuthority, verifyIntentAuthority } from './intents';

/**
 * The plaintext inside an MLS application message. MLS already authenticates the sending leaf; the
 * extra signature makes the message portable evidence of what that client said, which matters when an
 * agent confirms something on its principal's behalf.
 */
export interface MessageBody {
  v: 0;
  id: string;
  thread: string;
  inReplyTo?: string;
  from: string;
  fromClient: string;
  ts: string;
  subject: string;
  text: string;
  /** An html alternative to `text`, shown only after `sanitizeHtml` (Section 8.4.1). */
  html?: string;
  intents: Intent[];
  attachments: AttachmentRef[];
  /** Grants this agent relies on; each names the one counterparty allowed to see it. */
  grants?: Grant[];
  /** A label the sender chose to share with this thread, e.g. "Phone" or "Clerk". Never in the directory. */
  profile?: { label: string };
  /** `humans`: not for agents. Sent in the thread's humans-only sibling, whose members are devices and opted-in agents. */
  audience?: 'humans';
}

export interface SignedMessage {
  body: MessageBody;
  sig: string;
}

export interface MessageFields {
  subject: string;
  text: string;
  html?: string;
  inReplyTo?: string;
  intents?: Intent[];
  attachments?: AttachmentRef[];
  grants?: Grant[];
  profile?: { label: string };
  audience?: 'humans';
}

export function composeMessage(me: ClientKeys, thread: string, fields: MessageFields, now = new Date()): SignedMessage {
  const intents = fields.intents ?? [];
  for (const intent of intents) checkIntentAuthority(me.cert, intent);
  const body: MessageBody = {
    v: 0,
    id: randomId('m'),
    thread,
    inReplyTo: fields.inReplyTo,
    from: me.cert.principal,
    fromClient: me.cert.clientId,
    ts: now.toISOString(),
    subject: fields.subject,
    text: fields.text,
    html: fields.html,
    intents,
    attachments: fields.attachments ?? [],
    grants: fields.grants?.length ? fields.grants : undefined,
    profile: fields.profile,
    audience: fields.audience,
  };
  return { body, sig: signJson(me.signing, body) };
}

/**
 * Check a decrypted message: right thread, signed by the sender's current client, and every intent
 * within that client's authority as this receiver can see it (intake listing or a grant naming it).
 */
export function verifyMessage(
  message: SignedMessage,
  thread: string,
  sender: Directory,
  member: ViewMember,
  receiver: string,
  now = new Date(),
): void {
  const { body } = message;
  if (body.thread !== thread) throw new Error('message belongs to another thread');
  if (body.from !== sender.principal || body.fromClient !== member.clientId) throw new Error('message sender does not match its client');
  if (!verifyJson(member.sigKey, body, message.sig)) throw new Error('message is not signed by an active client');
  if (body.html !== undefined && (typeof body.html !== 'string' || Buffer.byteLength(body.html) > MAX_HTML_BYTES)) throw new Error(`a message's html is at most ${MAX_HTML_BYTES} bytes`);
  for (const intent of body.intents) verifyIntentAuthority(intent, member, sender, receiver, body.grants ?? [], now);
}
