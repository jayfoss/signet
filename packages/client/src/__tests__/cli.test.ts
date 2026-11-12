import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Testbed } from '@signet/server/testbed';
import { run } from '../cli';

describe('signet CLI', () => {
  let bed: Testbed;
  let root: string;

  beforeEach(async () => {
    bed = await Testbed.start(['alpha.test', 'beta.test'], { openEnrollment: true, intake: ['beta.test'] });
    root = await mkdtemp(join(tmpdir(), 'signet-cli-'));
  });

  afterEach(async () => {
    await bed.close();
    await rm(root, { recursive: true, force: true });
  });

  /** Run a command as one client and return what it printed. */
  async function as(who: string, ...argv: string[]): Promise<string[]> {
    const lines: string[] = [];
    await run(argv, { home: join(root, who), out: (line) => lines.push(line), resolver: bed.resolver });
    return lines;
  }

  // `=` form: a base64url key can start with '-', which would otherwise read as a flag.
  const logArgs = () => [`--log-url=${bed.trustedLog.url}`, `--log-key=${bed.trustedLog.key}`];

  it('takes two people from enrollment through an agent-run thread, a revocation and plain email', async () => {
    expect(await as('alice', 'init', '--address', 'alice@alpha.test', '--label', 'Phone', ...logArgs())).toEqual([
      expect.stringMatching(/^enrolled alice@alpha.test with this device as c_/),
    ]);
    await as('jerzy', 'init', '--address', 'jerzy@beta.test', '--label', 'Phone', ...logArgs());
    const [approved] = await as(
      'jerzy',
      'add-client',
      '--kind',
      'agent',
      '--label',
      'Clerk',
      '--scopes',
      'read:*,send,admit,intent:schedule.*',
      '--intake',
      'schedule.*',
      '--out',
      join(root, 'clerk'),
    );
    const clerkId = /as (c_\S+);/.exec(approved)?.[1] ?? '';
    expect(await as('alice', 'lookup', 'jerzy@beta.test')).toEqual(['jerzy@beta.test: verified, 2 request keys, intake agent handles schedule.*']);

    await as('alice', 'request', 'jerzy@beta.test', '--subject', 'Series A docs', '--intent', 'schedule.propose', '--args', '{"durationMin":30}');
    const [incoming] = await as('clerk', 'sync');
    expect(incoming).toMatch(/^request r_\S+ from alice@alpha.test: "Series A docs" \[schedule.propose\] \(waiting: unknown sender\)$/);
    const requestId = /request (r_\S+)/.exec(incoming)?.[1] ?? '';
    const [started] = await as('clerk', 'accept', requestId);
    const thread = /thread (t_\S+)/.exec(started)?.[1] ?? '';

    const agenda = join(root, 'agenda.txt');
    await writeFile(agenda, '1. Cap table\n');
    await as('clerk', 'send', thread, '--text', 'Tuesday 3pm?', '--intent', 'schedule.propose', '--args', '{"slots":["Tue 15:00"]}', '--attach', agenda);

    const aliceSync = await as('alice', 'sync');
    // Labels aren't shared by default: Alice sees Jerzy's clients only as a device and an agent.
    expect(aliceSync[0]).toMatch(/^joined t_\S+ at epoch 1 with jerzy@beta.test \((device, agent|agent, device)\), alice@alpha.test \(Phone\)$/);
    expect(aliceSync[1]).toMatch(/from jerzy@beta.test \(agent\): Tuesday 3pm\? \[schedule.propose, attachment agenda.txt\]$/);
    expect(await as('alice', 'threads')).toEqual([expect.stringMatching(/^t_\S+  jerzy@beta.test \((device, agent|agent, device)\), alice@alpha.test \(Phone\)$/)]);
    const messageId = /message (m_\S+)/.exec(aliceSync[1])?.[1] ?? '';
    const saved = join(root, 'saved.txt');
    await as('alice', 'attachment', messageId, '0', '--out', saved);
    expect(await readFile(saved, 'utf8')).toBe('1. Cap table\n');

    await as('jerzy', 'sync');
    await as('jerzy', 'revoke', clerkId);
    expect(await as('jerzy', 'rekey', thread)).toEqual(['removed 1, added 0']);
    await as('jerzy', 'send', thread, '--text', 'Confirmed for Tuesday');
    await expect(as('clerk', 'sync')).rejects.toThrow('401');
    expect((await as('alice', 'sync')).at(-1)).toMatch(/from jerzy@beta.test \(device\): Confirmed for Tuesday$/);

    expect(await as('jerzy', 'monitor')).toEqual(['log history matches this account']);
    expect(await as('alice', 'mail', 'pat@gmail.test', '--subject', 'Hi', '--text', 'Plain email')).toEqual(['sent to pat@gmail.test by plain email']);
    expect(bed.sent.map((mail) => mail.to)).toEqual([['pat@gmail.test']]);
  });

  it('rotates the identity key, then takes the account back with the recovery key after losing every device', async () => {
    await as('alice', 'init', '--address', 'alice@alpha.test', ...logArgs());
    await as('jerzy', 'init', '--address', 'jerzy@beta.test', ...logArgs());
    await as('jerzy', 'lookup', 'alice@alpha.test');

    expect(await as('alice', 'rotate')).toEqual(['rotated the identity key for alice@alpha.test; contacts follow it from the key they pinned']);
    await as('jerzy', 'lookup', 'alice@alpha.test');
    expect(await as('jerzy', 'sync')).toEqual(['alice@alpha.test rotated their identity key']);

    const recoveryFile = join(root, 'alice-recovery.json');
    await as('alice', 'recovery-key', '--out', recoveryFile);
    await rm(join(root, 'alice'), { recursive: true });

    const recovered = await as('alice-new', 'recover', '--address', 'alice@alpha.test', '--recovery-key', recoveryFile, '--label', 'New phone', ...logArgs());
    expect(recovered[0]).toMatch(/^recovered alice@alpha.test with a new identity key; this device is c_/);
    await as('jerzy', 'lookup', 'alice@alpha.test');
    expect((await as('jerzy', 'sync'))[0]).toMatch(/^alice@alpha.test's identity key was RECOVERED/);
    expect(await as('alice-new', 'monitor')).toEqual(['log history matches this account']);
    await expect(as('alice-again', 'recover', '--address', 'alice@alpha.test', '--recovery-key', recoveryFile, ...logArgs())).rejects.toThrow('404');
  });

  it('unlists an address so strangers reach it only through the domain intake', async () => {
    await as('alice', 'init', '--address', 'alice@alpha.test', ...logArgs());
    await as('jerzy', 'init', '--address', 'jerzy@beta.test', ...logArgs());
    expect((await as('jerzy', 'unlisted', 'on'))[0]).toMatch(/^jerzy@beta.test is unlisted/);
    await expect(as('alice', 'unlisted', 'on')).rejects.toThrow('has no intake');

    const unlisted = "is unlisted or doesn't exist (its domain won't say); a request goes through the domain's intake";
    expect(await as('alice', 'lookup', 'jerzy@beta.test')).toEqual([`jerzy@beta.test ${unlisted}`]);
    expect(await as('alice', 'lookup', 'nobody@beta.test')).toEqual([`nobody@beta.test ${unlisted}`]);

    await as('alice', 'request', 'jerzy@beta.test', '--subject', 'Hello');
    expect((await as('jerzy', 'sync'))[0]).toMatch(/^request r_\S+ from alice@alpha.test: "Hello"/);
  });

  it('adds a device with a pairing code and an agent with a link, their keys made where they run', async () => {
    await as('alice', 'init', '--address', 'alice@alpha.test', '--label', 'Phone', ...logArgs());

    const lines: string[] = [];
    const owner = run(['pair', '--approve'], { home: join(root, 'alice'), out: (line) => lines.push(line), resolver: bed.resolver });
    while (!lines.some((line) => line.startsWith('pairing code'))) await new Promise((resolve) => setTimeout(resolve, 20));
    const code = /pairing code (\S+)/.exec(lines[0])?.[1] ?? '';
    const joined = await as('laptop', 'join', code, '--address', 'alice@alpha.test', '--label', 'Laptop', ...logArgs());
    await owner;
    const fingerprint = /shows (\S+)$/.exec(joined[0])?.[1] ?? '';
    expect(lines[1]).toBe(`a new device "Laptop" asks for read:*, send, admit; fingerprint ${fingerprint}`);
    expect(joined[1]).toMatch(/^enrolled this device as c_\S+ with scopes read:\*, send, admit$/);

    const [link, note] = await as('assistant', 'enroll-request', '--address', 'alice@alpha.test', '--kind', 'agent', '--label', 'Assistant', '--scopes', 'read:*,send,intent:*', ...logArgs());
    expect(link).toMatch(/^signet:enroll\?r=/);
    await expect(as('assistant', 'enroll-finish')).rejects.toThrow('not approved yet');
    const approved = await as('alice', 'approve', link, '--scopes', 'read:*,send');
    expect(approved[0]).toContain(`fingerprint ${/fingerprint (\S+);/.exec(note)?.[1]}`);
    expect(await as('assistant', 'enroll-finish')).toEqual([expect.stringMatching(/^enrolled this agent as c_\S+ with scopes read:\*, send$/)]);
    expect(await as('alice', 'monitor')).toEqual(['log history matches this account']);
  });

  it('auto-accepts requests from contacts', async () => {
    await as('alice', 'init', '--address', 'alice@alpha.test', ...logArgs());
    await as('jerzy', 'init', '--address', 'jerzy@beta.test', ...logArgs());
    await as('jerzy', 'contact', 'alice@alpha.test');
    await as('alice', 'request', 'jerzy@beta.test', '--subject', 'Hello');

    const [line] = await as('jerzy', 'sync', '--auto-accept');
    expect(line).toMatch(/\(admitted: contact\) -> accepted into t_/);
    expect((await as('alice', 'sync'))[0]).toMatch(/^joined /);
  });
});
