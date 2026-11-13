import type { Work } from './mix';

/** More real deliveries are waiting for a covered domain than the limit allows (Section 10.6.2). */
export class BacklogFull extends Error {
  constructor(readonly domain: string) {
    super(`too many deliveries are waiting for ${domain}`);
  }
}

/**
 * Sends exactly `rate` deliveries to each covered domain at every edge of the window: real ones from a backlog, in the
 * order they were submitted, and cover for the rest (Section 10.6.2). The number leaving does not depend on what the
 * users did. Deliveries beyond the rate wait for a later window.
 */
export class CoverPacer {
  private readonly backlog = new Map<string, Work[]>();
  private readonly unsupported = new Set<string>();

  constructor(
    private readonly options: { domains: string[]; rate: number; limit: number; cover: (domain: string) => Work },
  ) {}

  /** Whether deliveries to this domain are paced: it is one the operator named, and it has not turned out to refuse cover. */
  covers(domain: string): boolean {
    return this.options.domains.includes(domain) && !this.unsupported.has(domain);
  }

  /** The domain does not accept cover, or cannot be sent it at this rate: stop pacing it, and let what waits go out. */
  markUnsupported(domain: string): void {
    this.unsupported.add(domain);
  }

  get rate(): number {
    return this.options.rate;
  }

  /** Hold a real delivery for the next edge with room for it. */
  submit<T>(domain: string, key: string, run: () => Promise<T>): Promise<T> {
    const queue = this.backlog.get(domain) ?? [];
    if (queue.length >= this.options.limit) return Promise.reject(new BacklogFull(domain));
    return new Promise<T>((resolve, reject) => {
      queue.push({ key, run, resolve: resolve as (value: unknown) => void, reject });
      this.backlog.set(domain, queue);
    });
  }

  /** What to send at this edge: for each covered domain, `rate` deliveries, real first. */
  source(): Work[] {
    const work: Work[] = [];
    for (const domain of this.options.domains) {
      const queue = this.backlog.get(domain) ?? [];
      // A domain that stopped being covered sends what it was holding, and nothing more.
      const take = this.unsupported.has(domain) ? queue.length : Math.min(this.options.rate, queue.length);
      work.push(...queue.splice(0, take));
      if (!this.unsupported.has(domain)) for (let i = take; i < this.options.rate; i += 1) work.push(this.options.cover(domain));
    }
    return work;
  }
}
