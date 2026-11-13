import { signJson, verifyJson } from './crypto';
import { b64u, fromB64u } from './encoding';
import { requesterHash, splitAddress } from './directory';
import type { ClientKeys, LogEntry, LogState } from './identity';
import { activeClient, replayLog } from './identity';

/** How far a requester proof's timestamp may be from the verifier's clock (Section 4.7). */
const PROOF_SKEW_MS = 5 * 60_000;

/** What the requesting client sends with a lookup that asks for contact level (Section 4.7). */
export interface RequesterProof {
  address: string;
  /** The entries of the requester's account log, which contain the signing client's certificate. */
  log: LogEntry[];
  clientId: string;
  ts: string;
  sig: string;
}

const signed = (requester: string, target: string, ts: string) => ({ v: 'signet0', requester, target, ts });

/** The `signet-requester` header value: this client's proof that it is the requester it names. */
export function signRequesterProof(keys: ClientKeys, address: string, log: LogEntry[], target: string, now = new Date()): string {
  const ts = now.toISOString();
  const sig = signJson(keys.signing, signed(requesterHash(address), target, ts));
  const proof: RequesterProof = { address, log, clientId: keys.cert.clientId, ts, sig };
  return b64u(Buffer.from(JSON.stringify(proof)));
}

/**
 * Check a proof against the requester hash the lookup carried and the address being looked up. Returns the
 * requester's replayed log; the caller still has to check that its identity key is the one the requester's
 * own domain vouches for (Section 4.7 step 3).
 */
export function verifyRequesterProof(header: string, hash: string, target: string, now = new Date()): LogState {
  const proof = JSON.parse(Buffer.from(fromB64u(header)).toString('utf8')) as RequesterProof;
  if (typeof proof.address !== 'string' || !Array.isArray(proof.log) || typeof proof.clientId !== 'string' || typeof proof.ts !== 'string' || typeof proof.sig !== 'string') {
    throw new Error('malformed requester proof');
  }
  if (Math.abs(now.getTime() - Date.parse(proof.ts)) > PROOF_SKEW_MS) throw new Error('requester proof is not fresh');
  if (requesterHash(proof.address) !== hash) throw new Error('requester proof is for another requester');
  splitAddress(proof.address);
  const state = replayLog(proof.log);
  if (state.principal !== proof.address.toLowerCase()) throw new Error('requester proof log is for another principal');
  const cert = activeClient(state, proof.clientId, now);
  if (!cert) throw new Error('requester proof is signed by a client that is not active');
  if (!verifyJson(cert.sigKey, signed(hash, target, proof.ts), proof.sig)) throw new Error('requester proof signature is invalid');
  return state;
}
