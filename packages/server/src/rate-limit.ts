/** How fast a source may send: `perSecond` on average, in bursts of up to `burst`. */
export interface Rate {
  perSecond: number;
  burst: number;
}

/**
 * Token buckets by key. A key may take `burst` at once and then `perSecond` on average. Keys that have been idle long
 * enough to be full again are forgotten, and when there are still too many the one idle longest goes, so the memory it
 * takes is bounded however many keys are made up.
 */
export class RateLimiter {
  private readonly buckets = new Map<string, { tokens: number; at: number }>();
  /** How many requests were refused, for tests and monitoring. */
  refused = 0;

  constructor(
    private readonly rate: Rate,
    private readonly maxKeys = 10_000,
    private readonly now: () => number = Date.now,
  ) {}

  /** Take one for `key`. Returns 0 if allowed, otherwise the seconds until one would be. */
  take(key: string): number {
    const now = this.now();
    const bucket = this.buckets.get(key) ?? { tokens: this.rate.burst, at: now };
    bucket.tokens = Math.min(this.rate.burst, bucket.tokens + ((now - bucket.at) / 1000) * this.rate.perSecond);
    bucket.at = now;
    // Re-insert, so the map stays in order of last use.
    this.buckets.delete(key);
    this.buckets.set(key, bucket);
    if (this.buckets.size > this.maxKeys) this.evict(now);
    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return 0;
    }
    this.refused += 1;
    return Math.ceil((1 - bucket.tokens) / this.rate.perSecond);
  }

  private evict(now: number): void {
    const fullAfter = (this.rate.burst / this.rate.perSecond) * 1000;
    for (const [key, bucket] of this.buckets) {
      if (now - bucket.at < fullAfter) break;
      this.buckets.delete(key);
    }
    // Still over: drop the least recently used.
    while (this.buckets.size > this.maxKeys) {
      const oldest = this.buckets.keys().next().value as string;
      this.buckets.delete(oldest);
    }
  }

  get size(): number {
    return this.buckets.size;
  }
}
