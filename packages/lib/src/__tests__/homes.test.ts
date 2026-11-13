import { HomeRegistry, failoverFetch, parseSignetTxt, policyHomes } from '..';

const policy = { server: 'https://a.example.com', replicas: ['https://a.example.com', 'https://b.example.com', 'https://c.example.com'] };

/** A fetch whose answer per origin is scripted; records the URLs it was asked for. */
function scripted(answers: Record<string, () => Response | Error>) {
  const calls: string[] = [];
  const fetchImpl = (async (input: string | URL | Request) => {
    const url = String(input);
    calls.push(url);
    const answer = answers[new URL(url).origin]?.();
    if (!answer) throw new Error('unscripted');
    if (answer instanceof Error) throw answer;
    return answer;
  }) as typeof fetch;
  return { fetchImpl, calls };
}

const ok = () => new Response('{}', { status: 200 });
const status = (code: number, headers: Record<string, string> = {}) => () => new Response('', { status: code, headers });
const down = () => new Error('connect ECONNREFUSED');

function registry() {
  const homes = new HomeRegistry();
  homes.register(policy);
  return homes;
}

describe('failoverFetch', () => {
  it('moves to the next home when one is down, and remembers the one that worked', async () => {
    const { fetchImpl, calls } = scripted({ 'https://a.example.com': down, 'https://b.example.com': ok, 'https://c.example.com': ok });
    const fetchHome = failoverFetch(registry(), fetchImpl);
    expect((await fetchHome('https://a.example.com/v0/mailbox?after=3')).status).toBe(200);
    expect(calls).toEqual(['https://a.example.com/v0/mailbox?after=3', 'https://b.example.com/v0/mailbox?after=3']);
    calls.length = 0;
    await fetchHome('https://a.example.com/v0/mailbox');
    expect(calls).toEqual(['https://b.example.com/v0/mailbox']);
  });

  it('follows a 421 to the primary it names, once, when the policy lists it', async () => {
    const { fetchImpl, calls } = scripted({
      'https://a.example.com': status(421, { 'signet-primary': 'https://c.example.com' }),
      'https://b.example.com': ok,
      'https://c.example.com': ok,
    });
    expect((await failoverFetch(registry(), fetchImpl)('https://a.example.com/v0/submit', { method: 'POST', body: '{}' })).status).toBe(200);
    expect(calls).toEqual(['https://a.example.com/v0/submit', 'https://c.example.com/v0/submit']);
  });

  it('ignores a Signet-Primary that is not one of the policy homes', async () => {
    const { fetchImpl, calls } = scripted({
      'https://a.example.com': status(421, { 'signet-primary': 'https://evil.example.org' }),
      'https://b.example.com': ok,
    });
    await failoverFetch(registry(), fetchImpl)('https://a.example.com/v0/mailbox');
    expect(calls).toEqual(['https://a.example.com/v0/mailbox', 'https://b.example.com/v0/mailbox']);
  });

  it('treats a 5xx as a reason to try the next home, and a 4xx as an answer', async () => {
    const first = scripted({ 'https://a.example.com': status(503), 'https://b.example.com': status(404) });
    expect((await failoverFetch(registry(), first.fetchImpl)('https://a.example.com/x')).status).toBe(404);
    expect(first.calls).toHaveLength(2);
  });

  it('returns the last failure when every home fails', async () => {
    const all = scripted({ 'https://a.example.com': status(503), 'https://b.example.com': down, 'https://c.example.com': status(500) });
    expect((await failoverFetch(registry(), all.fetchImpl)('https://a.example.com/x')).status).toBe(500);
    const none = scripted({ 'https://a.example.com': down, 'https://b.example.com': down, 'https://c.example.com': down });
    await expect(failoverFetch(registry(), none.fetchImpl)('https://a.example.com/x')).rejects.toThrow('ECONNREFUSED');
  });

  it('leaves other hosts and single-home domains alone', async () => {
    const { fetchImpl, calls } = scripted({ 'https://log.example.org': status(503) });
    const homes = registry();
    homes.register({ server: 'https://solo.example.net' });
    const wrapped = failoverFetch(homes, fetchImpl);
    expect((await wrapped('https://log.example.org/v0/head')).status).toBe(503);
    expect(calls).toEqual(['https://log.example.org/v0/head']);
  });

  it('keeps the preferred home across a policy refresh while it is still listed', async () => {
    const { fetchImpl, calls } = scripted({ 'https://a.example.com': down, 'https://b.example.com': ok });
    const homes = registry();
    const wrapped = failoverFetch(homes, fetchImpl);
    await wrapped('https://a.example.com/x');
    homes.register(policy);
    calls.length = 0;
    await wrapped('https://a.example.com/x');
    expect(calls).toEqual(['https://b.example.com/x']);
  });
});

describe('policy homes and the DNS record', () => {
  it('lists the policy homes without duplicates, or just server', () => {
    expect(policyHomes(policy)).toEqual(['https://a.example.com', 'https://b.example.com', 'https://c.example.com']);
    expect(policyHomes({ server: 'https://solo.example.net/' })).toEqual(['https://solo.example.net']);
  });

  it('reads several comma-separated hosts, all under the domain', () => {
    expect(parseSignetTxt([['v=signet0; host=a.example.com, b.example.com']], 'example.com')).toEqual({ hosts: ['a.example.com', 'b.example.com'] });
    expect(parseSignetTxt([['v=signet0; host=a.example.com,evil.example.org']], 'example.com')).toBeNull();
  });
});
