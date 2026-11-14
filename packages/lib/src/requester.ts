import { signJson, verifyJson } from './crypto';
import { b64u, fromB64u } from './encoding';
import type { SignedView, ViewMember } from './cards';
import { verifyView, viewMember } from './cards';
import { requesterHash, splitAddress } from './directory';
import type { ClientKeys } from './identity';

/** How far a requester proof's timestamp may be from the verifier's clock (Section 4.7). */
const PROOF_SKEW_MS = 5 * 60_000;

/** What the requesting client sends with a lookup that asks for contact level (Section 4.7). */
export interface RequesterProof {
  address: string;
  /** The requester's signed contact view: its active clients' kinds and keys, and no labels, scopes or limits. */
  view: SignedView;
  clientId: string;
  ts: string;
  sig: string;
}

const signed = (requester: string, target: string, ts: string) => ({ v: 'signet0', requester, target, ts });

/** The `signet-requester` header value: this client's proof that it is the requester it names. */
export function signRequesterProof(keys: ClientKeys, address: string, view: SignedView, target: string, now = new Date()): string {
  const ts = now.toISOString();
  const sig = signJson(keys.signing, signed(requesterHash(address), target, ts));
  const proof: RequesterProof = { address, view, clientId: keys.cert.clientId, ts, sig };
  return b64u(Buffer.from(JSON.stringify(proof)));
}

/**
 * Check a proof against the requester hash the lookup carried and the address being looked up. It looks at the proof's
 * shape, age and hash first, and only then asks `vouched` for the identity key and log head that the requester's own
 * domain gives for its address (Section 4.7 step 3): the view must be signed by that identity key, be for that head,
 * and list the signing client as active. Returns that client's entry in the view.
 */
export async function verifyRequesterProof(
  header: string,
  hash: string,
  target: string,
  vouched: (address: string) => Promise<{ identityKey: string; logHead: string }>,
  now = new Date(),
): Promise<ViewMember> {
  const proof = JSON.parse(Buffer.from(fromB64u(header)).toString('utf8')) as RequesterProof;
  if (typeof proof.address !== 'string' || typeof proof.clientId !== 'string' || typeof proof.ts !== 'string' || typeof proof.sig !== 'string' || typeof proof.view?.view !== 'object') {
    throw new Error('malformed requester proof');
  }
  if (Math.abs(now.getTime() - Date.parse(proof.ts)) > PROOF_SKEW_MS) throw new Error('requester proof is not fresh');
  if (requesterHash(proof.address) !== hash) throw new Error('requester proof is for another requester');
  splitAddress(proof.address);
  const { identityKey, logHead } = await vouched(proof.address);
  const view = verifyView(proof.view, proof.address.toLowerCase(), identityKey);
  if (view.logHead !== logHead) throw new Error('requester proof is for an out of date contact view');
  const member = viewMember(view, proof.clientId, now);
  if (!member) throw new Error('requester proof is signed by a client that is not active');
  if (!verifyJson(member.sigKey, signed(hash, target, proof.ts), proof.sig)) throw new Error('requester proof signature is invalid');
  return member;
}
