/**
 * Holds work until the end of a clock-aligned window and then starts all of it together, groups in a random order
 * (Section 10.6.1). What an observer of the outgoing traffic sees is that deliveries leave at the window's edge, in an
 * order unrelated to when they were submitted, so the moment one user sent says little about the moment a delivery
 * left. Work from one sender keeps its order: a commit never overtakes the message before it.
 *
 * It hides nothing when only one sender has work in a window, and it sends no cover traffic.
 */
export class Mix {
  private pending: { key: string; run: () => Promise<unknown>; resolve: (value: unknown) => void; reject: (error: unknown) => void }[] = [];
  private timer?: NodeJS.Timeout;

  constructor(
    private readonly windowMs: number,
    private readonly random: () => number = Math.random,
    private readonly now: () => number = Date.now,
  ) {}

  get enabled(): boolean {
    return this.windowMs > 0;
  }

  /** Run `work` at the end of the current window. `key` names the sender: its work runs in the order it was given. */
  run<T>(key: string, work: () => Promise<T>): Promise<T> {
    if (!this.enabled) return work();
    return new Promise<T>((resolve, reject) => {
      this.pending.push({ key, run: work, resolve: resolve as (value: unknown) => void, reject });
      this.timer ??= setTimeout(() => void this.flush(), this.windowMs - (this.now() % this.windowMs));
      this.timer.unref();
    });
  }

  /** Start everything held now, and wait for it. Used at the end of a window, and when the server stops. */
  async flush(): Promise<void> {
    if (this.timer) clearTimeout(this.timer);
    this.timer = undefined;
    const batch = this.pending;
    this.pending = [];
    const groups = new Map<string, typeof batch>();
    for (const item of batch) groups.set(item.key, [...(groups.get(item.key) ?? []), item]);
    const order = [...groups.values()];
    // Fisher-Yates: a uniformly random order of senders.
    for (let i = order.length - 1; i > 0; i -= 1) {
      const j = Math.floor(this.random() * (i + 1));
      [order[i], order[j]] = [order[j], order[i]];
    }
    await Promise.all(
      order.map(async (group) => {
        for (const item of group) {
          try {
            item.resolve(await item.run());
          } catch (error) {
            item.reject(error);
          }
        }
      }),
    );
  }

  /** The number of items held. */
  get held(): number {
    return this.pending.length;
  }
}
