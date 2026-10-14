import type { FastifyBaseLogger } from 'fastify';
import type { Config } from './config.js';

/** What this server was built from. Baked into the Docker image at build time; "dev" when run from a checkout. */
export interface BuildInfo {
  version: string;
  commit: string | null;
  builtAt: string | null;
}

export function buildInfo(env: NodeJS.ProcessEnv = process.env): BuildInfo {
  return {
    version: env.ANYSSH_BUILD_VERSION || 'dev',
    commit: env.ANYSSH_BUILD_COMMIT || null,
    builtAt: env.ANYSSH_BUILD_DATE || null,
  };
}

/** The newest image published for the tag this install follows. */
export interface PublishedImage {
  version: string | null;
  commit: string | null;
  builtAt: string | null;
}

export interface UpdateStatus {
  checkedAt: number | null;
  latest: PublishedImage | null;
  /** null when it can't be told (never checked, or this is a development build). */
  updateAvailable: boolean | null;
  error: string | null;
}

type Fetch = typeof fetch;

const MANIFEST_TYPES = [
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.docker.distribution.manifest.v2+json',
].join(', ');
const MAX_BODY = 1024 * 1024;

function dockerArch(arch = process.arch): string {
  return arch === 'x64' ? 'amd64' : arch;
}

/** "ghcr.io/owner/name" → registry host and repository path. Docker Hub short names are expanded. */
export function parseImage(image: string): { registry: string; repo: string } {
  const parts = image.split('/');
  if (parts.length > 1 && /[.:]/.test(parts[0]!)) return { registry: parts[0]!, repo: parts.slice(1).join('/') };
  return { registry: 'registry-1.docker.io', repo: parts.length === 1 ? `library/${image}` : image };
}

/**
 * Reads the labels of the image a tag points at, straight from the registry (anonymous pull access,
 * as `docker pull` would use). Only the registry is contacted, and nothing about this server is sent.
 */
export async function fetchPublishedImage(image: string, tag: string, fetchImpl: Fetch = fetch): Promise<PublishedImage> {
  const { registry, repo } = parseImage(image);
  const base = `https://${registry}/v2/${repo}`;
  let token: string | null = null;

  const getJson = async (url: string, accept?: string): Promise<{ body: any; type: string }> => {
    const headers: Record<string, string> = {};
    if (accept) headers.accept = accept;
    if (token) headers.authorization = `Bearer ${token}`;
    let res = await fetchImpl(url, { headers, signal: AbortSignal.timeout(15_000) });
    if (res.status === 401 && !token) {
      token = await anonymousToken(res.headers.get('www-authenticate'), fetchImpl);
      headers.authorization = `Bearer ${token}`;
      res = await fetchImpl(url, { headers, signal: AbortSignal.timeout(15_000) });
    }
    if (!res.ok) throw new Error(`${registry} answered ${res.status}`);
    const text = await res.text();
    if (text.length > MAX_BODY) throw new Error(`${registry} sent an unexpectedly large response`);
    return { body: JSON.parse(text), type: res.headers.get('content-type') ?? '' };
  };

  let { body: manifest } = await getJson(`${base}/manifests/${encodeURIComponent(tag)}`, MANIFEST_TYPES);
  if (Array.isArray(manifest.manifests)) {
    // Multi-platform image: follow the entry for this server's CPU (attestations have platform unknown).
    const arch = dockerArch();
    const entry =
      manifest.manifests.find((m: any) => m.platform?.os === 'linux' && m.platform?.architecture === arch) ??
      manifest.manifests.find((m: any) => m.platform?.os === 'linux');
    if (!entry?.digest) throw new Error(`No ${arch} image published for tag ${tag}`);
    ({ body: manifest } = await getJson(`${base}/manifests/${entry.digest}`, MANIFEST_TYPES));
  }
  const configDigest = manifest.config?.digest;
  if (typeof configDigest !== 'string') throw new Error('The registry returned a manifest without an image config');
  const { body: config } = await getJson(`${base}/blobs/${configDigest}`);
  const labels: Record<string, string> = config.config?.Labels ?? {};
  return {
    version: labels['org.opencontainers.image.version'] ?? null,
    commit: labels['org.opencontainers.image.revision'] ?? null,
    builtAt: labels['org.opencontainers.image.created'] ?? config.created ?? null,
  };
}

async function anonymousToken(challenge: string | null, fetchImpl: Fetch): Promise<string> {
  const params = Object.fromEntries([...(challenge ?? '').matchAll(/(\w+)="([^"]*)"/g)].map((m) => [m[1]!, m[2]!]));
  if (!/^bearer /i.test(challenge ?? '') || !params.realm?.startsWith('https://')) throw new Error('Unsupported registry authentication');
  const url = new URL(params.realm);
  if (params.service) url.searchParams.set('service', params.service);
  if (params.scope) url.searchParams.set('scope', params.scope);
  const res = await fetchImpl(url, { signal: AbortSignal.timeout(15_000) });
  if (!res.ok) throw new Error(`Registry token request failed (${res.status})`);
  const json = (await res.json()) as { token?: string; access_token?: string };
  const token = json.token ?? json.access_token;
  if (!token) throw new Error('The registry did not issue a token');
  return token;
}

/** Keeps the latest known published version, refreshed every few hours when checks are enabled. */
export class UpdateChecker {
  readonly build: BuildInfo;
  private status: UpdateStatus = { checkedAt: null, latest: null, updateAvailable: null, error: null };
  private timer: NodeJS.Timeout | null = null;
  private inFlight: Promise<UpdateStatus> | null = null;

  constructor(
    private readonly config: Config,
    private readonly log: FastifyBaseLogger,
    opts: { build?: BuildInfo; fetch?: Fetch } = {},
  ) {
    this.build = opts.build ?? buildInfo();
    this.fetchImpl = opts.fetch ?? fetch;
  }
  private readonly fetchImpl: Fetch;

  get current(): UpdateStatus {
    return this.status;
  }

  /** Starts background checks: shortly after startup, then every 6 hours. */
  start(intervalMs = 6 * 3600_000, firstDelayMs = 60_000): void {
    if (!this.config.updateCheck || this.timer) return;
    const run = () => void this.check();
    this.timer = setTimeout(function tick(this: UpdateChecker) {
      run();
      this.timer = setTimeout(tick.bind(this), intervalMs);
      this.timer.unref();
    }.bind(this), firstDelayMs);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  /** Checks now. Concurrent callers share one request; results younger than 30 seconds are reused. */
  check(): Promise<UpdateStatus> {
    if (this.status.checkedAt && Date.now() - this.status.checkedAt < 30_000) return Promise.resolve(this.status);
    this.inFlight ??= this.run().finally(() => (this.inFlight = null));
    return this.inFlight;
  }

  private async run(): Promise<UpdateStatus> {
    try {
      const latest = await fetchPublishedImage(this.config.updateImage, this.config.updateTag, this.fetchImpl);
      const updateAvailable = isNewer(this.build, latest);
      if (updateAvailable && !this.status.updateAvailable) {
        this.log.info({ current: this.build.commit, latest: latest.commit }, 'A newer Any-SSH version is available');
      }
      this.status = { checkedAt: Date.now(), latest, updateAvailable, error: null };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.log.warn({ err: message }, 'Update check failed');
      this.status = { ...this.status, checkedAt: Date.now(), error: message };
    }
    return this.status;
  }
}

/** True when the published image was built from a different, later commit than this one. */
export function isNewer(build: BuildInfo, latest: PublishedImage): boolean | null {
  if (!build.commit || !latest.commit) return null;
  if (latest.commit === build.commit) return false;
  if (build.builtAt && latest.builtAt) return Date.parse(latest.builtAt) > Date.parse(build.builtAt);
  return true;
}
