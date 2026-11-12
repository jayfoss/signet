/**
 * Sealed sender for thread traffic. Messages, commits and welcomes inside a thread travel without a
 * sender address or client: the MLS ciphertext already hides who sent them, and the recipient's server
 * authorizes the delivery with a token instead of the sender's identity.
 *
 * The token is an MLS exporter secret for the current epoch, which only current members can derive.
 * Each member registers hash(token | its own address) with its home server; the server accepts a
 * sealed delivery for an address only if the presented token hashes to a registered value. Removed
 * members can't derive the next epoch's token. The server learns which deliveries belong to the same
 * thread epoch, but not who sent them.
 */
import { randomBytes } from 'node:crypto';
import { sha256 } from './crypto';
import { b64u } from './encoding';

export const DELIVERY_LABEL = 'signet delivery v0';

/** How many epochs' tokens a client keeps registered, so late messages from the previous epoch still land. */
export const TOKEN_EPOCHS_KEPT = 3;

export const deliveryTokenHash = (token: string, recipient: string): string => sha256(`${token}|${recipient.toLowerCase()}`);

/** A one-off token for a reply to a request, before any thread exists. */
export const randomToken = (): string => b64u(randomBytes(32));
