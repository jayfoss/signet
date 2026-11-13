/** JSON that also carries Buffers and Dates, for what replicas send each other and snapshot. */
export const encode = (value: unknown): unknown =>
  JSON.parse(
    JSON.stringify(value, function (this: Record<string, unknown>, key: string, current: unknown) {
      const original = this[key];
      if (Buffer.isBuffer(original)) return { $b: original.toString('base64') };
      if (original instanceof Date) return { $d: original.toISOString() };
      return current;
    }),
  );

export const decode = (value: unknown): unknown => {
  if (Array.isArray(value)) return value.map(decode);
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    if (typeof record.$b === 'string' && Object.keys(record).length === 1) return Buffer.from(record.$b, 'base64');
    if (typeof record.$d === 'string' && Object.keys(record).length === 1) return new Date(record.$d);
    return Object.fromEntries(Object.entries(record).map(([key, item]) => [key, decode(item)]));
  }
  return value;
};

