// Reverse DNS names of report source IPs, cached for a few hours.
import { isIP } from 'node:net';
import { mapLimit } from './checks/util.ts';
import { DnsClient } from './dns.ts';

const TTL_MS = 6 * 3_600_000;

export class PtrCache {
  private readonly cache = new Map<string, { name: string | null; until: number }>();
  private readonly servers: string[];
  private readonly timeoutMs: number;

  constructor(servers: string[], timeoutMs: number) {
    this.servers = servers;
    this.timeoutMs = timeoutMs;
  }

  async resolve(ips: string[]): Promise<Map<string, string | null>> {
    const now = Date.now();
    const out = new Map<string, string | null>();
    const todo: string[] = [];
    for (const ip of new Set(ips)) {
      const hit = this.cache.get(ip);
      if (hit && hit.until > now) out.set(ip, hit.name);
      else if (isIP(ip)) todo.push(ip);
    }
    if (todo.length) {
      // A fresh client per batch: DnsClient caches for its own lifetime.
      const dns = new DnsClient(this.servers, this.timeoutMs);
      await mapLimit(todo, 20, async (ip) => {
        const r = await dns.ptr(ip);
        const name = r.records[0] ?? null;
        out.set(ip, name);
        this.cache.set(ip, { name, until: now + TTL_MS });
      });
      if (this.cache.size > 20_000) this.cache.clear();
    }
    return out;
  }
}
