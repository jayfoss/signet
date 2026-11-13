import { Mix } from '../mix';

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** A random source that returns the given numbers in turn, then 0. */
const scripted = (values: number[]) => () => values.shift() ?? 0;

describe('mixing deliveries (Section 10.6.1)', () => {
  it('runs at once when the window is 0', async () => {
    const mix = new Mix(0);
    expect(mix.enabled).toBe(false);
    await expect(mix.run('a', async () => 7)).resolves.toBe(7);
  });

  it('holds work until the edge of the window, then runs all of it together', async () => {
    // A fake clock 20 ms into a 100 ms window: the edge is 80 ms away.
    const start = Date.now();
    const mix = new Mix(100, Math.random, () => Math.floor(Date.now() / 100) * 100 + 20);
    const ran: number[] = [];
    const first = mix.run('a', async () => ran.push(Date.now() - start));
    await sleep(40);
    const second = mix.run('b', async () => ran.push(Date.now() - start));
    expect(mix.held).toBe(2);
    expect(ran).toEqual([]);
    await Promise.all([first, second]);
    expect(ran).toHaveLength(2);
    expect(ran[0]).toBeGreaterThanOrEqual(70);
    expect(Math.abs(ran[0] - ran[1])).toBeLessThan(30);
    expect(mix.held).toBe(0);
  });

  it("keeps one sender's work in the order it was given, whatever order the senders go in", async () => {
    for (let trial = 0; trial < 20; trial += 1) {
      const mix = new Mix(10_000);
      const order: string[] = [];
      const held = ['a1', 'b1', 'a2', 'c1', 'b2', 'a3'].map((name) => mix.run(name[0], async () => void order.push(name)));
      await mix.flush();
      await Promise.all(held);
      for (const sender of ['a', 'b', 'c']) {
        const mine = order.filter((name) => name[0] === sender);
        expect(mine).toEqual([...mine].sort());
      }
      expect(order).toHaveLength(6);
    }
  });

  it('starts the senders in a random order, not the order they arrived in', async () => {
    const firsts = new Set<string>();
    for (let trial = 0; trial < 60; trial += 1) {
      const mix = new Mix(10_000);
      const order: string[] = [];
      const held = ['a', 'b', 'c'].map((sender) => mix.run(sender, async () => void order.push(sender)));
      await mix.flush();
      await Promise.all(held);
      firsts.add(order.join(''));
    }
    // Six orders are possible; in sixty trials a fair shuffle shows most of them.
    expect(firsts.size).toBeGreaterThanOrEqual(4);
  });

  it('uses the random source it is given, so a shuffle is reproducible', async () => {
    const run = async (random: () => number) => {
      const mix = new Mix(10_000, random);
      const order: string[] = [];
      const held = ['a', 'b', 'c', 'd'].map((sender) => mix.run(sender, async () => void order.push(sender)));
      await mix.flush();
      await Promise.all(held);
      return order.join('');
    };
    expect(await run(scripted([0.1, 0.5, 0.9]))).toBe(await run(scripted([0.1, 0.5, 0.9])));
    expect(await run(scripted([0.99, 0.99, 0.99]))).not.toBe(await run(scripted([0, 0, 0])));
  });

  it("fails only the work that failed, and carries on with the rest", async () => {
    const mix = new Mix(10_000);
    const bad = mix.run('a', async () => {
      throw new Error('refused');
    });
    const good = mix.run('a', async () => 'sent');
    const other = mix.run('b', async () => 'also sent');
    await mix.flush();
    await expect(bad).rejects.toThrow('refused');
    await expect(good).resolves.toBe('sent');
    await expect(other).resolves.toBe('also sent');
  });

  it('lets a flush send what is held now, as a server does when it stops', async () => {
    const mix = new Mix(60_000);
    const held = mix.run('a', async () => 'out');
    expect(mix.held).toBe(1);
    await mix.flush();
    await expect(held).resolves.toBe('out');
  });

  it('asks its sources for work at every edge, even when nothing was submitted', async () => {
    const mix = new Mix(40);
    let edges = 0;
    const sent: string[] = [];
    mix.addSource(() => {
      edges += 1;
      return [{ key: `cover:${edges}`, run: async () => void sent.push('cover'), resolve: () => undefined, reject: () => undefined }];
    });
    mix.start();
    await sleep(220);
    await mix.stop();
    expect(edges).toBeGreaterThanOrEqual(4);
    expect(sent.length).toBe(edges);
    const after = edges;
    await sleep(100);
    expect(edges).toBe(after);
  });

  it('puts real work and a source’s work into one shuffle', async () => {
    const mix = new Mix(10_000);
    const order: string[] = [];
    mix.addSource(() => [{ key: 'cover', run: async () => void order.push('cover'), resolve: () => undefined, reject: () => undefined }]);
    const real = mix.run('alice', async () => void order.push('real'));
    await mix.flush();
    await real;
    expect([...order].sort()).toEqual(['cover', 'real']);
  });
});
