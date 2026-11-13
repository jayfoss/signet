import type { KeyPair } from './crypto';
import { signJson, verifyJson } from './crypto';
import type { DomainPolicy } from './directory';
import { verifiedDomainSigner } from './operators';

/**
 * What a recipient's home says about a delivery it was given (Section 6.9.5). The sender's own home can't
 * make one up: it is signed by the recipient domain's key, or by the key of one of its homes.
 */
export interface ReceiptBody {
  v: 0;
  /** The delivery id. */
  id: string;
  /** The recipient's domain. */
  domain: string;
  /** Addresses whose mailbox now holds the delivery. */
  to: string[];
  /** Addresses for which the home is holding it, such as a sealed delivery waiting for its token. */
  held: string[];
  ts: string;
  /** The home key that signed in place of the domain key. */
  home?: string;
}

export interface Receipt {
  body: ReceiptBody;
  sig: string;
}

export function signReceipt(signer: KeyPair, fields: { id: string; domain: string; to: string[]; held: string[] }, now = new Date(), asHome = false): Receipt {
  const body: ReceiptBody = { v: 0, ...fields, ts: now.toISOString(), ...(asHome ? { home: signer.publicKey } : {}) };
  return { body, sig: signJson(signer, body) };
}

/** True if the receipt is for this delivery and domain and is signed by the domain or one of its listed homes. */
export function verifyReceipt(receipt: Receipt, policy: Pick<DomainPolicy, 'domain' | 'domainKey' | 'operators'>, id: string): boolean {
  const { body } = receipt ?? {};
  if (body?.v !== 0 || body.id !== id || body.domain !== policy.domain) return false;
  const signer = verifiedDomainSigner(policy, body.home);
  return signer !== undefined && verifyJson(signer, body, receipt.sig);
}
