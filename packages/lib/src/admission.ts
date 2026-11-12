import { normalizeAddress, splitAddress } from './directory';
import type { Directory } from './cards';
import type { SignedRequest } from './request';
import { verifyIntroduction } from './request';

/** Evaluated on the recipient's own clients. The server never learns who someone's contacts are. */
export interface AdmissionPolicy {
  contacts: string[];
  trustedDomains: string[];
}

export type AdmissionDecision = { admit: true; reason: string } | { admit: false; reason: string; lookalike?: string };

/** Characters attackers swap in to make one domain read as another. */
const CONFUSABLES: [RegExp, string][] = [
  [/rn/g, 'm'],
  [/vv/g, 'w'],
  [/[0]/g, 'o'],
  [/[1|]/g, 'l'],
  [/[5]/g, 's'],
  [/-/g, ''],
];

const skeleton = (domain: string): string =>
  CONFUSABLES.reduce((text, [pattern, replacement]) => text.replace(pattern, replacement), domain.normalize('NFKC').toLowerCase().replace(/i/g, 'l'));

function editDistance(a: string, b: string): number {
  const row = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i += 1) {
    let previous = row[0];
    row[0] = i;
    for (let j = 1; j <= b.length; j += 1) {
      const current = row[j];
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, previous + (a[i - 1] === b[j - 1] ? 0 : 1));
      previous = current;
    }
  }
  return row[b.length];
}

/**
 * A domain that isn't one you know but reads like one: same skeleton after swapping confusable
 * characters, or one edit away. Signet stops anyone sending *as* acme.com; it can't stop someone
 * registering acrne.com, so the client has to point it out.
 */
export function lookalikeOf(domain: string, known: string[]): string | null {
  const target = domain.toLowerCase();
  for (const candidate of new Set(known.map((d) => d.toLowerCase()))) {
    if (candidate === target) return null;
  }
  for (const candidate of new Set(known.map((d) => d.toLowerCase()))) {
    if (skeleton(candidate) === skeleton(target) || (Math.min(candidate.length, target.length) >= 6 && editDistance(candidate, target) <= 1)) {
      return candidate;
    }
  }
  return null;
}

/** Domains a sender might try to imitate: your own, your trusted domains, your contacts' domains. */
export const knownDomains = (policy: AdmissionPolicy, me: string): string[] => [
  splitAddress(me).domain,
  ...policy.trustedDomains,
  ...policy.contacts.map((contact) => splitAddress(contact).domain),
];

/** Would this address be admitted on its own, without an introduction? */
export function isTrusted(policy: AdmissionPolicy, me: string, address: string): string | null {
  const who = normalizeAddress(address);
  const { domain } = splitAddress(who);
  if (policy.contacts.map(normalizeAddress).includes(who)) return 'contact';
  if (domain === splitAddress(me).domain) return 'same organisation';
  if (policy.trustedDomains.map((d) => d.toLowerCase()).includes(domain)) return `trusted domain ${domain}`;
  return null;
}

/**
 * Contacts, the recipient's own organisation and trusted domains go straight to a conversation.
 * So does anyone carrying a valid introduction from someone who would be admitted themselves.
 * Everyone else waits in the request queue.
 */
export async function decideAdmission(
  policy: AdmissionPolicy,
  me: string,
  request: SignedRequest,
  lookup: (address: string) => Promise<Directory>,
): Promise<AdmissionDecision> {
  const direct = isTrusted(policy, me, request.body.from);
  if (direct) return { admit: true, reason: direct };
  const imitated = lookalikeOf(splitAddress(request.body.from).domain, knownDomains(policy, me));
  if (imitated) return { admit: false, reason: `${splitAddress(request.body.from).domain} looks like ${imitated}: possible impersonation`, lookalike: imitated };
  const intro = request.body.introduction;
  if (intro) {
    const introducer = intro.body.introducer;
    if (!isTrusted(policy, me, introducer)) return { admit: false, reason: `introduced by ${introducer}, who is not trusted` };
    if (verifyIntroduction(intro, request.body, await lookup(introducer))) {
      return { admit: true, reason: `introduced by ${introducer}: ${intro.body.context}` };
    }
    return { admit: false, reason: `introduction from ${introducer} did not verify` };
  }
  return { admit: false, reason: 'unknown sender' };
}
