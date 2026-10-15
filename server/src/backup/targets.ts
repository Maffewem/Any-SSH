import { createHash, createHmac, randomBytes } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdir, readdir, readFile, rename, rm, stat } from 'node:fs/promises';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import ssh2 from 'ssh2';
import { resolveTarget } from '../ssh/target.js';
import { sshFingerprint } from '../ssh/fingerprint.js';

const { Client } = ssh2;

/** Where encrypted backups go. Every implementation only ever sees ciphertext. */
export interface BackupTarget {
  readonly label: string;
  /** Stores the file under `name`; resolves to the size the destination reports. */
  put(file: string, name: string): Promise<number>;
  /** Names of the backups stored here (only files that look like Any-SSH backups). */
  list(): Promise<string[]>;
  remove(name: string): Promise<void>;
  /** Writes, reads back and deletes a small test object. */
  probe(): Promise<void>;
}

export const BACKUP_NAME = /^any-ssh-\d{8}T\d{6}Z\.anybak$/;

export type TargetConfig =
  | { kind: 'local'; dir: string }
  | { kind: 's3'; endpoint: string; region: string; bucket: string; prefix: string; accessKeyId: string; secretKey: string; pathStyle: boolean; allowLoopback: boolean }
  | { kind: 'sftp'; host: string; port: number; username: string; path: string; hostKeyFingerprint: string; password?: string; privateKey?: string; allowLoopback: boolean };

export function createTarget(cfg: TargetConfig): BackupTarget {
  if (cfg.kind === 'local') return new LocalTarget(cfg.dir);
  if (cfg.kind === 's3') return new S3Target(cfg);
  return new SftpTarget(cfg);
}

const probeName = () => `any-ssh-probe-${randomBytes(6).toString('hex')}.tmp`;
const clip = (s: string) => s.replace(/\s+/g, ' ').trim().slice(0, 300);

// ---- Local directory (inside the data volume) ----

class LocalTarget implements BackupTarget {
  readonly label: string;
  constructor(private readonly dir: string) {
    this.label = `this server (${dir})`;
  }
  async put(file: string, name: string): Promise<number> {
    await mkdir(this.dir, { recursive: true, mode: 0o700 });
    const dest = path.join(this.dir, name);
    if (path.resolve(file) !== path.resolve(dest)) await rename(file, dest);
    return (await stat(dest)).size;
  }
  async list(): Promise<string[]> {
    return (await readdir(this.dir).catch(() => [] as string[])).filter((n) => BACKUP_NAME.test(n));
  }
  async remove(name: string): Promise<void> {
    await rm(path.join(this.dir, name), { force: true });
  }
  async probe(): Promise<void> {
    const f = path.join(this.dir, probeName());
    await mkdir(this.dir, { recursive: true, mode: 0o700 });
    const { writeFile } = await import('node:fs/promises');
    await writeFile(f, 'probe', { mode: 0o600 });
    await rm(f);
  }
}

// ---- S3-compatible (AWS, Backblaze B2, Cloudflare R2, MinIO, Wasabi ...) over plain HTTPS + Signature V4 ----

const rfc3986 = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
const hmac = (key: string | Buffer, data: string) => createHmac('sha256', key).update(data).digest();
const sha256hex = (data: string | Buffer) => createHash('sha256').update(data).digest('hex');

/** AWS Signature Version 4. Returns the headers to send (host, x-amz-date, x-amz-content-sha256, authorization, plus `headers`). */
export function signV4(p: {
  method: string;
  url: URL;
  headers?: Record<string, string>;
  payloadHash: string;
  region: string;
  accessKeyId: string;
  secretKey: string;
  now?: Date;
  service?: string;
}): Record<string, string> {
  const now = p.now ?? new Date();
  const amzDate = now.toISOString().replace(/[-:]|\.\d{3}/g, '');
  const day = amzDate.slice(0, 8);
  const service = p.service ?? 's3';
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(p.headers ?? {})) headers[k.toLowerCase()] = v.trim();
  headers.host = p.url.host;
  headers['x-amz-date'] = amzDate;
  headers['x-amz-content-sha256'] = p.payloadHash;
  const names = Object.keys(headers).sort();
  const canonicalQuery = [...p.url.searchParams.entries()]
    .map(([k, v]) => [rfc3986(k), rfc3986(v)] as const)
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : 1))
    .map(([k, v]) => `${k}=${v}`)
    .join('&');
  const canonical = [
    p.method,
    p.url.pathname,
    canonicalQuery,
    ...names.map((n) => `${n}:${headers[n]}`),
    '',
    names.join(';'),
    p.payloadHash,
  ].join('\n');
  const scope = `${day}/${p.region}/${service}/aws4_request`;
  const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256hex(canonical)].join('\n');
  const signingKey = hmac(hmac(hmac(hmac(`AWS4${p.secretKey}`, day), p.region), service), 'aws4_request');
  const signature = createHmac('sha256', signingKey).update(toSign).digest('hex');
  headers.authorization = `AWS4-HMAC-SHA256 Credential=${p.accessKeyId}/${scope}, SignedHeaders=${names.join(';')}, Signature=${signature}`;
  return headers;
}

class S3Target implements BackupTarget {
  readonly label: string;
  private readonly base: URL;
  private readonly prefix: string;

  constructor(private readonly cfg: Extract<TargetConfig, { kind: 's3' }>) {
    const endpoint = new URL(cfg.endpoint || `https://s3.${cfg.region}.amazonaws.com`);
    this.base = endpoint;
    this.prefix = cfg.prefix ? `${cfg.prefix.replace(/^\/+|\/+$/g, '')}/` : '';
    this.label = `S3 bucket ${cfg.bucket}${this.prefix ? `/${this.prefix}` : ''}`;
  }

  private url(key: string): URL {
    if (this.cfg.pathStyle) return new URL(`${this.base.origin}/${this.cfg.bucket}/${key}`);
    return new URL(`${this.base.protocol}//${this.cfg.bucket}.${this.base.host}/${key}`);
  }

  private async request(method: string, url: URL, opts: { body?: Buffer; headers?: Record<string, string>; timeoutMs?: number } = {}): Promise<Response> {
    await resolveTarget(url.hostname, this.cfg.allowLoopback);
    const headers = signV4({
      method,
      url,
      headers: opts.headers ?? {},
      payloadHash: opts.body ? sha256hex(opts.body) : sha256hex(''),
      region: this.cfg.region,
      accessKeyId: this.cfg.accessKeyId,
      secretKey: this.cfg.secretKey,
    });
    delete headers.host;
    const res = await fetch(url, {
      method,
      headers,
      ...(opts.body ? { body: new Uint8Array(opts.body) } : {}),
      redirect: 'error',
      signal: AbortSignal.timeout(opts.timeoutMs ?? 30_000),
    });
    return res;
  }

  private async expect(res: Response, ok: number[], what: string): Promise<string> {
    const text = await res.text().catch(() => '');
    if (ok.includes(res.status)) return text;
    const code = /<Code>([^<]*)<\/Code>/.exec(text)?.[1];
    const message = /<Message>([^<]*)<\/Message>/.exec(text)?.[1];
    throw new Error(clip(`${what} failed: the storage answered ${res.status}${code ? ` ${code}` : ''}${message ? ` (${message})` : ''}`));
  }

  private async store(body: Buffer, name: string): Promise<number> {
    const url = this.url(this.prefix + name);
    const res = await this.request('PUT', url, {
      body,
      headers: { 'content-type': 'application/octet-stream', 'content-md5': createHash('md5').update(body).digest('base64') },
      timeoutMs: 15 * 60_000,
    });
    await this.expect(res, [200], 'Upload');
    const head = await this.request('HEAD', url);
    await this.expect(head, [200], 'Checking the upload');
    return Number(head.headers.get('content-length') ?? NaN);
  }

  async put(file: string, name: string): Promise<number> {
    return this.store(await readFile(file), name);
  }

  async list(): Promise<string[]> {
    const names: string[] = [];
    let token: string | undefined;
    do {
      const url = this.cfg.pathStyle ? new URL(`${this.base.origin}/${this.cfg.bucket}`) : new URL(`${this.base.protocol}//${this.cfg.bucket}.${this.base.host}/`);
      url.searchParams.set('list-type', '2');
      url.searchParams.set('prefix', this.prefix);
      if (token) url.searchParams.set('continuation-token', token);
      const xml = await this.expect(await this.request('GET', url), [200], 'Listing the bucket');
      for (const m of xml.matchAll(/<Key>([^<]+)<\/Key>/g)) {
        const key = m[1]!;
        if (key.startsWith(this.prefix) && BACKUP_NAME.test(key.slice(this.prefix.length))) names.push(key.slice(this.prefix.length));
      }
      token = /<IsTruncated>true<\/IsTruncated>/.test(xml) ? /<NextContinuationToken>([^<]+)<\/NextContinuationToken>/.exec(xml)?.[1] : undefined;
    } while (token);
    return names;
  }

  async remove(name: string): Promise<void> {
    await this.expect(await this.request('DELETE', this.url(this.prefix + name)), [200, 204], 'Deleting an old backup');
  }

  async probe(): Promise<void> {
    const name = probeName();
    const size = await this.store(Buffer.from('any-ssh probe'), name);
    if (size !== 'any-ssh probe'.length) throw new Error('The storage reported an unexpected size for the test file.');
    await this.expect(await this.request('DELETE', this.url(this.prefix + name)), [200, 204], 'Deleting the test file');
  }
}

// ---- SFTP ----

type Sftp = ssh2.SFTPWrapper;

class SftpTarget implements BackupTarget {
  readonly label: string;
  constructor(private readonly cfg: Extract<TargetConfig, { kind: 'sftp' }>) {
    this.label = `SFTP ${cfg.username}@${cfg.host}:${cfg.path}`;
  }

  private async connect(): Promise<{ conn: ssh2.Client; sftp: Sftp }> {
    const ip = await resolveTarget(this.cfg.host, this.cfg.allowLoopback);
    const expected = this.cfg.hostKeyFingerprint;
    let presented = '';
    const conn = new Client();
    try {
      await new Promise<void>((resolve, reject) => {
        conn.once('ready', resolve);
        conn.once('error', (err: Error) => {
          if (presented && presented !== expected) {
            reject(
              new Error(
                expected
                  ? `The SFTP server's host key is ${presented}, not the ${expected} that was entered. If the server was rebuilt, enter the new fingerprint; otherwise do not trust this connection.`
                  : `The SFTP server's host key is ${presented}. If that is what you expect, enter it as the host key fingerprint, then try again.`,
              ),
            );
          } else reject(err);
        });
        conn.connect({
          host: ip,
          port: this.cfg.port,
          username: this.cfg.username,
          ...(this.cfg.password ? { password: this.cfg.password } : {}),
          ...(this.cfg.privateKey ? { privateKey: this.cfg.privateKey } : {}),
          readyTimeout: 20_000,
          hostVerifier: (key: Buffer) => {
            presented = sshFingerprint(key);
            return !!expected && presented === expected;
          },
        });
      });
      const sftp = await new Promise<Sftp>((resolve, reject) => conn.sftp((err, s) => (err ? reject(err) : resolve(s))));
      return { conn, sftp };
    } catch (err) {
      conn.end();
      throw err;
    }
  }

  private async withSftp<T>(fn: (s: Sftp, dir: string) => Promise<T>): Promise<T> {
    const { conn, sftp } = await this.connect();
    try {
      const dir = this.cfg.path.replace(/\/+$/, '') || '/';
      await new Promise<void>((resolve, reject) =>
        sftp.stat(dir, (err) => (err ? sftp.mkdir(dir, { mode: 0o700 }, (e) => (e ? reject(new Error(`The folder ${dir} does not exist and could not be created: ${e.message}`)) : resolve())) : resolve())),
      );
      return await fn(sftp, dir);
    } finally {
      conn.end();
    }
  }

  private upload(sftp: Sftp, local: string, remote: string): Promise<void> {
    return pipeline(createReadStream(local), sftp.createWriteStream(remote, { mode: 0o600 }));
  }

  private size(sftp: Sftp, remote: string): Promise<number> {
    return new Promise((resolve, reject) => sftp.stat(remote, (err, st) => (err ? reject(err) : resolve(st.size))));
  }

  private rename(sftp: Sftp, from: string, to: string): Promise<void> {
    return new Promise((resolve, reject) => sftp.rename(from, to, (err) => (err ? reject(err) : resolve())));
  }

  private unlink(sftp: Sftp, remote: string): Promise<void> {
    return new Promise((resolve, reject) => sftp.unlink(remote, (err) => (err ? reject(err) : resolve())));
  }

  async put(file: string, name: string): Promise<number> {
    return this.withSftp(async (sftp, dir) => {
      // Written under a temporary name first, so a half-finished upload is never mistaken for a backup.
      const final = path.posix.join(dir, name);
      const partial = `${final}.partial`;
      try {
        await this.upload(sftp, file, partial);
        await this.rename(sftp, partial, final);
      } catch (err) {
        await this.unlink(sftp, partial).catch(() => {});
        throw err;
      }
      return this.size(sftp, final);
    });
  }

  async list(): Promise<string[]> {
    return this.withSftp(
      (sftp, dir) =>
        new Promise<string[]>((resolve, reject) =>
          sftp.readdir(dir, (err, entries) => (err ? reject(err) : resolve(entries.map((e) => e.filename).filter((n) => BACKUP_NAME.test(n))))),
        ),
    );
  }

  async remove(name: string): Promise<void> {
    await this.withSftp((sftp, dir) => this.unlink(sftp, path.posix.join(dir, name)));
  }

  async probe(): Promise<void> {
    const local = path.join((await import('node:os')).tmpdir(), probeName());
    const { writeFile } = await import('node:fs/promises');
    await writeFile(local, 'any-ssh probe', { mode: 0o600 });
    try {
      await this.withSftp(async (sftp, dir) => {
        const remote = path.posix.join(dir, probeName());
        await this.upload(sftp, local, remote);
        const size = await this.size(sftp, remote);
        await this.unlink(sftp, remote);
        if (size !== 'any-ssh probe'.length) throw new Error('The server reported an unexpected size for the test file.');
      });
    } finally {
      await rm(local, { force: true });
    }
  }
}
