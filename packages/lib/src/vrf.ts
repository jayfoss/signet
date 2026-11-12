/**
 * The transparency log is indexed by a VRF of each address (ECVRF-EDWARDS25519-SHA512-TAI, RFC 9381),
 * computed by the native core. Only the domain holding the VRF key can compute an index; it proves the
 * index on every lookup, so the log can't be used to test guessed addresses.
 */
import { normalizeAddress } from './directory';
import { b64u, utf8 } from './encoding';
import { native } from './native';

export interface VrfKey {
  secret: string;
  public: string;
}

export interface VrfProof {
  index: string;
  proof: string;
}

const alpha = (address: string): string => b64u(utf8(`signet0 ${normalizeAddress(address)}`));

export const generateVrfKey = (): VrfKey => native().vrfKeygen();

export function proveIndex(key: VrfKey, address: string): VrfProof {
  const { proof, output } = native().vrfProve(key.secret, alpha(address));
  return { index: output, proof };
}

/** The address's log index if the proof is valid for this VRF key; throws otherwise. */
export function verifyIndex(publicKey: string, address: string, proof: VrfProof): string {
  const output = native().vrfVerify(publicKey, alpha(address), proof.proof);
  if (output !== proof.index) throw new Error('VRF index does not match its proof');
  return output;
}
