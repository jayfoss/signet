import type { KeyPair } from './crypto';
import { signJson, verifyJson } from './crypto';
import type { DomainPolicy } from './directory';

/** One operator's home: where it is, the key it signs server calls with, and other URLs of the same home. */
export interface OperatorHome {
  url: string;
  key: string;
  replicas?: string[];
}

export interface OperatorsBody {
  v: 'signet0';
  domain: string;
  /** Rises with every statement; a client that has seen a higher one refuses a lower. */
  seq: number;
  notAfter: string;
  homes: OperatorHome[];
}

/** The domain owner's signed list of independent homes (Section 6.9.2). Operators serve it but can't change it. */
export interface Operators {
  body: OperatorsBody;
  sig: string;
}

export const MAX_HOMES = 7;

export class OperatorsError extends Error {}

export function signOperators(domainKey: KeyPair, body: Omit<OperatorsBody, 'v'>): Operators {
  const full: OperatorsBody = { v: 'signet0', ...body };
  return { body: full, sig: signJson(domainKey, full) };
}

/** Check a statement against the domain key; returns its homes. Throws if it isn't the domain's, is expired, or is malformed. */
export function checkOperators(operators: Operators, domain: string, domainKey: string, now = new Date()): OperatorHome[] {
  const { body, sig } = operators;
  if (body?.v !== 'signet0' || body.domain !== domain) throw new OperatorsError(`operators statement is not for ${domain}`);
  if (!verifyJson(domainKey, body, sig)) throw new OperatorsError('operators statement is not signed by the domain key');
  if (!(Date.parse(body.notAfter) > now.getTime())) throw new OperatorsError('operators statement has expired');
  if (!Array.isArray(body.homes) || body.homes.length < 1 || body.homes.length > MAX_HOMES) throw new OperatorsError(`a domain needs one to ${MAX_HOMES} homes`);
  for (const home of body.homes) {
    if (typeof home.url !== 'string' || typeof home.key !== 'string') throw new OperatorsError('a home needs a url and a key');
    new URL(home.url);
    for (const replica of home.replicas ?? []) new URL(replica);
  }
  return body.homes;
}

/** The keys a home may sign with, as the policy's verified statement lists them. Empty for a domain without operators. */
export const homeKeys = (policy: Pick<DomainPolicy, 'operators'>): string[] => policy.operators?.body.homes.map((home) => home.key) ?? [];

/** Whether `signer` may speak as the domain: the domain key itself, or the key of one of its homes. */
export function verifiedDomainSigner(policy: Pick<DomainPolicy, 'domainKey' | 'operators'>, home: string | undefined): string | undefined {
  if (home === undefined) return policy.domainKey;
  return homeKeys(policy).includes(home) ? home : undefined;
}
