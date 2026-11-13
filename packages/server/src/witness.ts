import type { ClusterOptions } from './cluster';
import { Cluster } from './cluster';
import { HttpError, JsonServer } from './http';

/**
 * A witness (Section 6.8.2): it keeps the replication log and votes, so two homes survive the loss of one.
 * It serves only the replicas' own calls, applies nothing and never becomes primary. It still holds
 * everything the log holds, so it is as trusted as a home.
 */
export class ClusterWitness {
  readonly cluster: Cluster;
  private readonly http: JsonServer;

  constructor(options: ClusterOptions) {
    this.cluster = new Cluster(options);
    this.http = new JsonServer(async (request) => {
      if (request.url.pathname.startsWith('/v0/cluster/')) return this.cluster.handle(request);
      throw new HttpError(404, 'a witness serves only cluster calls');
    });
  }

  get url(): string {
    return this.http.publicUrl;
  }

  async listen(port = 0, host = '127.0.0.1', publicUrl?: string): Promise<string> {
    const url = await this.http.listen(port, host, publicUrl);
    this.cluster.start();
    return url;
  }

  async close(): Promise<void> {
    this.cluster.close();
    await this.http.close();
  }
}
