import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { createServer, type Server as HttpServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import ssh2 from 'ssh2';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { BackupFormatError, backupKeyId, decryptFile, encryptFile, generateBackupKeyPair, publicKeyFromSecret } from '../src/backup/format.js';
import { lastSlot } from '../src/backup/service.js';
import { signV4 } from '../src/backup/targets.js';
import { verifyDatabaseFile } from '../src/backup/verify.js';
import { ADMIN_PASSWORD, createUser, makeApp, setupAdmin, type Client } from './helpers.js';

const { Server, utils } = ssh2;

let tmp: string;
beforeEach(() => {
  tmp = mkdtempSync(path.join(os.tmpdir(), 'anyssh-backup-'));
});
afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

describe('encrypted backup format', () => {
  it('round-trips files of every shape, across chunk boundaries', async () => {
    const { publicKey, secretKey } = generateBackupKeyPair();
    for (const size of [0, 1, 1024 * 1024 - 1, 1024 * 1024, 1024 * 1024 + 1, 3 * 1024 * 1024 + 17]) {
      const src = path.join(tmp, `src-${size}`);
      const enc = path.join(tmp, `enc-${size}`);
      const out = path.join(tmp, `out-${size}`);
      writeFileSync(src, randomBytes(size));
      const { bytes, sha256 } = await encryptFile(src, enc, publicKey);
      expect(sha256).toBe(createHash('sha256').update(readFileSync(enc)).digest('hex'));
      expect(bytes).toBe(readFileSync(enc).length);
      await decryptFile(enc, out, secretKey);
      expect(readFileSync(out).equals(readFileSync(src))).toBe(true);
    }
  });

  it('does not leak plaintext and differs every time', async () => {
    const { publicKey } = generateBackupKeyPair();
    const src = path.join(tmp, 'src');
    writeFileSync(src, 'SQLite format 3 very recognisable text');
    await encryptFile(src, path.join(tmp, 'a'), publicKey);
    await encryptFile(src, path.join(tmp, 'b'), publicKey);
    expect(readFileSync(path.join(tmp, 'a')).includes('recognisable')).toBe(false);
    expect(readFileSync(path.join(tmp, 'a')).equals(readFileSync(path.join(tmp, 'b')))).toBe(false);
  });

  it('refuses the wrong key, tampering, truncation and appended data', async () => {
    const { publicKey, secretKey } = generateBackupKeyPair();
    const other = generateBackupKeyPair();
    const src = path.join(tmp, 'src');
    const enc = path.join(tmp, 'enc');
    writeFileSync(src, randomBytes(2.5 * 1024 * 1024));
    await encryptFile(src, enc, publicKey);
    const good = readFileSync(enc);
    const attempt = async (data: Buffer, key = secretKey) => {
      const f = path.join(tmp, 'bad');
      const o = path.join(tmp, 'bad.out');
      writeFileSync(f, data);
      await expect(decryptFile(f, o, key)).rejects.toThrow(BackupFormatError);
      expect(existsSync(o)).toBe(false);
      rmSync(f);
    };
    await attempt(good, other.secretKey);
    const flipped = Buffer.from(good);
    flipped[good.length - 40] ^= 1;
    await attempt(flipped);
    const flippedHeader = Buffer.from(good);
    flippedHeader[40] ^= 1;
    await attempt(flippedHeader);
    await attempt(good.subarray(0, good.length - 1));
    // Dropping the last frame leaves valid-looking frames but no final one.
    const firstFrameEnd = 48 + 5 + 1024 * 1024 + 16;
    await attempt(good.subarray(0, firstFrameEnd));
    await attempt(Buffer.concat([good, Buffer.from('x')]));
    await attempt(Buffer.from('not a backup at all, just some text that is long enough to have a header'));
  });

  it('derives the public key and a stable key id from the secret key', () => {
    const { publicKey, secretKey } = generateBackupKeyPair();
    expect(publicKeyFromSecret(secretKey)).toBe(publicKey);
    expect(backupKeyId(publicKey)).toMatch(/^[0-9a-f]{16}$/);
  });
});

describe('request signing', () => {
  it('matches the AWS Signature V4 documentation example', () => {
    const h = signV4({
      method: 'GET',
      url: new URL('https://examplebucket.s3.amazonaws.com/test.txt'),
      headers: { Range: 'bytes=0-9' },
      payloadHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      region: 'us-east-1',
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      secretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      now: new Date('2013-05-24T00:00:00Z'),
    });
    expect(h.authorization).toBe(
      'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41',
    );
  });
});

describe('schedule', () => {
  const at = (iso: string) => Date.parse(iso);
  it('finds the most recent due moment', () => {
    expect(lastSlot(at('2026-10-15T10:00:00Z'), { frequency: 'hourly', hourUtc: 0, weekday: 0 })).toBe(at('2026-10-15T10:00:00Z'));
    expect(lastSlot(at('2026-10-15T10:30:00Z'), { frequency: 'daily', hourUtc: 3, weekday: 0 })).toBe(at('2026-10-15T03:00:00Z'));
    expect(lastSlot(at('2026-10-15T02:30:00Z'), { frequency: 'daily', hourUtc: 3, weekday: 0 })).toBe(at('2026-10-14T03:00:00Z'));
    // 2026-10-15 is a Thursday; the last Sunday is the 11th.
    expect(lastSlot(at('2026-10-15T10:30:00Z'), { frequency: 'weekly', hourUtc: 3, weekday: 0 })).toBe(at('2026-10-11T03:00:00Z'));
  });
});

// ---- Fake storage servers ----

interface FakeS3 {
  url: string;
  objects: Map<string, Buffer>;
  requests: { method: string; auth: string }[];
  failPuts: { on: boolean };
  close(): void;
}

function startFakeS3(): Promise<FakeS3> {
  const objects = new Map<string, Buffer>();
  const requests: FakeS3['requests'] = [];
  const failPuts = { on: false };
  const server: HttpServer = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const url = new URL(req.url!, 'http://x');
      requests.push({ method: req.method!, auth: String(req.headers.authorization) });
      if (!/^AWS4-HMAC-SHA256 Credential=AKIATEST\/\d{8}\/us-east-1\/s3\/aws4_request, SignedHeaders=[a-z0-9;-]+, Signature=[0-9a-f]{64}$/.test(String(req.headers.authorization))) {
        res.writeHead(403).end('<Error><Code>SignatureDoesNotMatch</Code></Error>');
        return;
      }
      const key = decodeURIComponent(url.pathname.replace(/^\/bucket\//, ''));
      if (req.method === 'PUT') {
        const body = Buffer.concat(chunks);
        if (failPuts.on) return void res.writeHead(500).end('<Error><Code>InternalError</Code><Message>try later</Message></Error>');
        if (createHash('md5').update(body).digest('base64') !== req.headers['content-md5']) return void res.writeHead(400).end('<Error><Code>BadDigest</Code></Error>');
        objects.set(key, body);
        return void res.writeHead(200).end();
      }
      if (req.method === 'HEAD') {
        const o = objects.get(key);
        return void res.writeHead(o ? 200 : 404, o ? { 'content-length': String(o.length) } : {}).end();
      }
      if (req.method === 'DELETE') {
        objects.delete(key);
        return void res.writeHead(204).end();
      }
      if (req.method === 'GET' && url.searchParams.get('list-type') === '2') {
        const prefix = url.searchParams.get('prefix') ?? '';
        const keys = [...objects.keys()].filter((k) => k.startsWith(prefix)).sort();
        return void res.writeHead(200, { 'content-type': 'application/xml' }).end(`<ListBucketResult><IsTruncated>false</IsTruncated>${keys.map((k) => `<Contents><Key>${k}</Key></Contents>`).join('')}</ListBucketResult>`);
      }
      res.writeHead(400).end();
    });
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve({ url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, objects, requests, failPuts, close: () => server.close() })),
  );
}

interface FakeSftp {
  port: number;
  fingerprint: string;
  files: Map<string, Buffer>;
  close(): void;
}

/** Minimal SFTP server: a flat folder at /backups, password login "backup" / "pw". */
function startFakeSftp(): Promise<FakeSftp> {
  const privateKey = utils.generateKeyPairSync('ed25519').private;
  const hostKey = utils.parseKey(privateKey);
  if (hostKey instanceof Error || Array.isArray(hostKey)) throw new Error('key');
  const fingerprint = `SHA256:${createHash('sha256').update(hostKey.getPublicSSH()).digest('base64').replace(/=+$/, '')}`;
  const files = new Map<string, Buffer>();
  const S = utils.sftp.STATUS_CODE;
  const server = new Server({ hostKeys: [privateKey] }, (client) => {
    client.on('authentication', (ctx) => (ctx.method === 'password' && ctx.username === 'backup' && ctx.password === 'pw' ? ctx.accept() : ctx.reject(['password'])));
    client.on('ready', () => {
      client.on('session', (accept) => {
        const session = accept();
        session.on('sftp', (acceptSftp) => {
          const sftp = acceptSftp();
          const handles = new Map<string, { path: string; dir: boolean; sent?: boolean }>();
          let next = 0;
          const nameOf = (p: string) => p.replace(/^\/backups\/?/, '');
          const attrs = (size: number, dir = false) => ({ mode: (dir ? 0o040755 : 0o100644), uid: 0, gid: 0, size, atime: 0, mtime: 0 });
          sftp.on('REALPATH', (id, p) => sftp.name(id, [{ filename: p, longname: p, attrs: attrs(0) }]));
          const stat = (id: number, p: string) => {
            if (p === '/backups') return sftp.attrs(id, attrs(0, true));
            const f = files.get(nameOf(p));
            return f ? sftp.attrs(id, attrs(f.length)) : sftp.status(id, S.NO_SUCH_FILE);
          };
          sftp.on('STAT', stat);
          sftp.on('LSTAT', stat);
          sftp.on('OPENDIR', (id, p) => {
            const h = Buffer.from(String(next++));
            handles.set(h.toString(), { path: p, dir: true });
            sftp.handle(id, h);
          });
          sftp.on('READDIR', (id, h) => {
            const entry = handles.get(h.toString());
            if (!entry || entry.sent) return sftp.status(id, S.EOF);
            entry.sent = true;
            sftp.name(id, [...files.entries()].map(([filename, b]) => ({ filename, longname: filename, attrs: attrs(b.length) })));
          });
          sftp.on('OPEN', (id, p) => {
            const h = Buffer.from(String(next++));
            handles.set(h.toString(), { path: nameOf(p), dir: false });
            files.set(nameOf(p), Buffer.alloc(0));
            sftp.handle(id, h);
          });
          sftp.on('WRITE', (id, h, offset, data) => {
            const entry = handles.get(h.toString())!;
            const cur = files.get(entry.path)!;
            const grown = Buffer.alloc(Math.max(cur.length, offset + data.length));
            cur.copy(grown);
            data.copy(grown, offset);
            files.set(entry.path, grown);
            sftp.status(id, S.OK);
          });
          sftp.on('CLOSE', (id, h) => {
            handles.delete(h.toString());
            sftp.status(id, S.OK);
          });
          sftp.on('FSTAT', (id, h) => {
            const entry = handles.get(h.toString());
            sftp.attrs(id, attrs(entry ? (files.get(entry.path)?.length ?? 0) : 0));
          });
          sftp.on('REMOVE', (id, p) => {
            files.delete(nameOf(p));
            sftp.status(id, S.OK);
          });
          sftp.on('RENAME', (id, from, to) => {
            const f = files.get(nameOf(from));
            if (f) {
              files.set(nameOf(to), f);
              files.delete(nameOf(from));
            }
            sftp.status(id, S.OK);
          });
          sftp.on('MKDIR', (id) => sftp.status(id, S.OK));
          sftp.on('SETSTAT', (id) => sftp.status(id, S.OK));
          sftp.on('FSETSTAT', (id) => sftp.status(id, S.OK));
        });
      });
    });
    client.on('error', () => {});
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve({ port: (server.address() as AddressInfo).port, fingerprint, files, close: () => server.close() })),
  );
}

// ---- Through the API ----

let built: Awaited<ReturnType<typeof makeApp>>;
let admin: Client;
let keys: { publicKey: string; secretKey: string };
let dataDir: string;

beforeEach(async () => {
  dataDir = path.join(tmp, 'data');
  built = await makeApp({ dataDir, allowLoopbackTargets: true });
  admin = await setupAdmin(built);
  keys = generateBackupKeyPair();
});
afterEach(async () => {
  await built.app.close();
});

const settingsBody = (over: Record<string, unknown> = {}) => ({
  enabled: true,
  frequency: 'daily',
  hourUtc: 3,
  weekday: 0,
  keep: 3,
  publicKey: keys.publicKey,
  target: { kind: 'local' },
  currentPassword: ADMIN_PASSWORD,
  ...over,
});

describe('backup settings', () => {
  it('are admin-only, need the password and an encryption key', async () => {
    const { client } = await createUser(built, admin, 'bob');
    expect((await client.get('/api/admin/backup')).status).toBe(403);
    expect((await client.put('/api/admin/settings/backup', settingsBody())).status).toBe(403);
    expect((await client.post('/api/admin/backup/run')).status).toBe(403);
    expect((await client.post('/api/admin/backup/keypair')).status).toBe(403);

    const wrong = await admin.put('/api/admin/settings/backup', settingsBody({ currentPassword: 'not the password at all' }));
    expect(wrong.status).toBe(400);
    expect(wrong.body.error).toMatch(/Password is incorrect/);
    const noKey = await admin.put('/api/admin/settings/backup', settingsBody({ publicKey: '' }));
    expect(noKey.status).toBe(400);
    expect(noKey.body.error).toMatch(/recovery key/);
    const badKey = await admin.put('/api/admin/settings/backup', settingsBody({ publicKey: 'ssh-ed25519 AAAA' }));
    expect(badKey.status).toBe(400);

    const ok = await admin.put('/api/admin/settings/backup', settingsBody());
    expect(ok.status).toBe(200);
    expect(ok.body.backup).toMatchObject({ enabled: true, keep: 3, publicKey: keys.publicKey, target: { kind: 'local' } });
    expect(ok.body.backup.keyId).toBe(backupKeyId(keys.publicKey));
  });

  it('hands out a key pair without storing it', async () => {
    const pair = (await admin.post('/api/admin/backup/keypair')).body;
    expect(publicKeyFromSecret(pair.secretKey)).toBe(pair.publicKey);
    expect(JSON.stringify(built.ctx.db.prepare('SELECT * FROM settings').all())).not.toContain(pair.secretKey);
    expect(JSON.stringify(built.ctx.db.prepare('SELECT * FROM audit_log').all())).not.toContain(pair.secretKey);
  });

  it('will not run without a key or destination', async () => {
    const res = await admin.post('/api/admin/backup/run');
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/where backups go/);
  });

  it('audits what changed (never secrets) and emails a notice', async () => {
    await admin.put('/api/admin/settings/backup', settingsBody());
    const row = built.ctx.db.prepare("SELECT details FROM audit_log WHERE action = 'admin.settings_change' AND target_id = 'backup' AND outcome = 'success'").get() as { details: string };
    expect(JSON.parse(row.details).changed).toEqual(expect.arrayContaining(['enabled', 'publicKey', 'destination']));
    // The public key is not secret and is recorded; secrets only ever show as present or absent.
    expect(JSON.parse(row.details).changes.publicKey).toEqual({ from: '', to: keys.publicKey });
    expect(row.details).not.toContain(keys.secretKey);
  });
});

describe('backing up and restoring', () => {
  it('writes an encrypted backup that restores and verifies, and prunes old ones', async () => {
    // A sealed secret in the database, so the master-key check has something to try.
    await admin.put('/api/admin/settings/mail', { enabled: true, host: 'smtp.example.com', port: 587, security: 'starttls', password: 'smtp-secret', from: 'Any-SSH <a@example.com>' });
    await admin.put('/api/admin/settings/backup', settingsBody({ keep: 2 }));
    const names: string[] = [];
    for (let i = 0; i < 3; i++) {
      const res = await admin.post('/api/admin/backup/run');
      expect(res.status).toBe(200);
      expect(res.body.run).toMatchObject({ outcome: 'success', trigger: 'manual' });
      names.push(res.body.run.name);
      // Names carry the second; space them so they sort.
      await new Promise((r) => setTimeout(r, 1100));
    }
    const dir = path.join(dataDir, 'backups');
    const left = readdirSync(dir).sort();
    expect(left).toEqual(names.slice(1));
    const file = path.join(dir, left[1]!);
    expect(readFileSync(file).includes('SQLite format 3')).toBe(false);

    const out = path.join(tmp, 'restored.db');
    await decryptFile(file, out, keys.secretKey);
    const report = verifyDatabaseFile(out, built.ctx.box);
    expect(report.ok).toBe(true);
    expect(report.checks.map((c) => c.name)).toEqual(['Database integrity', 'Schema', 'Contents', 'Audit log chain', 'Master key']);
    expect(report.checks.find((c) => c.name === 'Contents')!.detail).toMatch(/1 user/);

    // A different master key is caught: the backup would restore but nothing in it could be decrypted.
    const { SecretBox } = await import('../src/crypto.js');
    const wrong = verifyDatabaseFile(out, new SecretBox(randomBytes(32)));
    expect(wrong.ok).toBe(false);
    expect(wrong.checks.find((c) => c.name === 'Master key')!.detail).toMatch(/not the master key/);
    const status = (await admin.get('/api/admin/backup')).body;
    expect(status.runs).toHaveLength(3);
    expect(status.status).toMatchObject({ configured: true, scheduled: true, running: false });
    expect(status.status.lastSuccess.name).toBe(names[2]);
  }, 20_000);

  it('rejects a damaged database instead of backing it up', () => {
    const bad = path.join(tmp, 'bad.db');
    writeFileSync(bad, 'this is not a database');
    expect(verifyDatabaseFile(bad).ok).toBe(false);
  });

  it('records a failure, emails admins once, and retries a missed slot', async () => {
    await admin.post('/api/admin/account/email', { email: 'admin@example.com', currentPassword: ADMIN_PASSWORD }).catch(() => {});
    built.ctx.db.prepare("UPDATE users SET email = 'admin@example.com' WHERE username = 'admin'").run();
    const s3 = await startFakeS3();
    try {
      s3.failPuts.on = true;
      const save = await admin.put(
        '/api/admin/settings/backup',
        settingsBody({ target: { kind: 's3', endpoint: s3.url, bucket: 'bucket', prefix: 'any-ssh', accessKeyId: 'AKIATEST', secretKey: 'secret', pathStyle: true } }),
      );
      expect(save.status).toBe(200);
      const first = (await admin.post('/api/admin/backup/run')).body.run;
      expect(first.outcome).toBe('failure');
      expect(first.error).toMatch(/500 InternalError/);
      const second = (await admin.post('/api/admin/backup/run')).body.run;
      expect(second.outcome).toBe('failure');
      expect(built.mail.sent.filter((m) => m.subject === 'Any-SSH backup failed')).toHaveLength(1);
      expect(built.mail.sent.at(-1)!.text).toContain('500 InternalError');
      expect(JSON.stringify(built.mail.sent)).not.toContain('secret');
      expect((await admin.get('/api/admin/backup')).body.status.last.outcome).toBe('failure');

      // The scheduler retries a failed slot after half an hour, a few times, and mails only once a day.
      const svc = built.ctx.backups;
      const now = Date.now();
      await svc.tick(now);
      expect(svc.recent()[0]).toMatchObject({ trigger: 'schedule', outcome: 'failure' });
      expect(svc.due(now + 60_000)).toBe(false);
      expect(svc.due(now + 31 * 60_000)).toBe(true);
      s3.failPuts.on = false;
      await svc.tick(now + 31 * 60_000);
      expect(svc.recent()[0]).toMatchObject({ trigger: 'schedule', outcome: 'success' });
      expect(svc.due(now + 62 * 60_000)).toBe(false);
      expect(built.mail.sent.filter((m) => m.subject === 'Any-SSH backup failed')).toHaveLength(1);
    } finally {
      s3.close();
    }
  }, 20_000);

  it('stores to an S3-compatible bucket with signed requests, prunes, and drops the secret when the bucket moves', async () => {
    const s3 = await startFakeS3();
    try {
      const target = { kind: 's3', endpoint: s3.url, bucket: 'bucket', prefix: 'any-ssh', accessKeyId: 'AKIATEST', secretKey: 'top-secret-key', pathStyle: true };
      const res = await admin.put('/api/admin/settings/backup', settingsBody({ keep: 1, target }));
      expect(res.body.backup.target).toMatchObject({ kind: 's3', hasSecretKey: true });
      expect(JSON.stringify(res.body)).not.toContain('top-secret-key');
      const row = built.ctx.db.prepare("SELECT value, value_enc FROM settings WHERE id = 'backup'").get() as { value: string; value_enc: string };
      expect(row.value).not.toContain('top-secret-key');
      expect(row.value_enc).toMatch(/^v1\./);

      expect((await admin.post('/api/admin/backup/test')).status).toBe(200);
      expect(s3.objects.size).toBe(0);

      const a = (await admin.post('/api/admin/backup/run')).body.run;
      expect(a.outcome).toBe('success');
      expect([...s3.objects.keys()]).toEqual([`any-ssh/${a.name}`]);
      const stored = s3.objects.get(`any-ssh/${a.name}`)!;
      expect(createHash('sha256').update(stored).digest('hex')).toBe(a.sha256);
      const out = path.join(tmp, 's3.db');
      writeFileSync(path.join(tmp, 's3.enc'), stored);
      await decryptFile(path.join(tmp, 's3.enc'), out, keys.secretKey);
      expect(verifyDatabaseFile(out, built.ctx.box).ok).toBe(true);
      // Nothing is left in the data volume: the copy only exists at the destination.
      expect(readdirSync(path.join(dataDir, 'backups'))).toEqual([]);

      await new Promise((r) => setTimeout(r, 1100));
      const b = (await admin.post('/api/admin/backup/run')).body.run;
      expect([...s3.objects.keys()]).toEqual([`any-ssh/${b.name}`]);
      expect(s3.requests.every((r) => r.auth.startsWith('AWS4-HMAC-SHA256'))).toBe(true);

      // Re-pointing at another bucket drops the saved secret unless a new one comes with it.
      const moved = await admin.put('/api/admin/settings/backup', settingsBody({ target: { ...target, secretKey: undefined, bucket: 'other-bucket' } }));
      expect(moved.body.backup.target.hasSecretKey).toBe(false);
      const refused = await admin.post('/api/admin/backup/run');
      expect(refused.body.error).toMatch(/secret access key/);
      const kept = await admin.put('/api/admin/settings/backup', settingsBody({ keep: 5, target: { ...target, secretKey: 'new-secret' } }));
      expect(kept.body.backup.target.hasSecretKey).toBe(true);
      const sameBucket = await admin.put('/api/admin/settings/backup', settingsBody({ keep: 6, target: { ...target, secretKey: undefined } }));
      expect(sameBucket.body.backup.target.hasSecretKey).toBe(true);
    } finally {
      s3.close();
    }
  }, 30_000);

  it('stores over SFTP only after the host key is pinned', async () => {
    const sftp = await startFakeSftp();
    try {
      const target = { kind: 'sftp', host: '127.0.0.1', port: sftp.port, username: 'backup', path: '/backups', password: 'pw', hostKeyFingerprint: '' };
      await admin.put('/api/admin/settings/backup', settingsBody({ target }));
      const untrusted = await admin.post('/api/admin/backup/test');
      expect(untrusted.status).toBe(400);
      expect(untrusted.body.error).toContain(sftp.fingerprint);
      expect((await admin.post('/api/admin/backup/run')).body.error).toMatch(/host key fingerprint/);

      const wrongPin = await admin.put('/api/admin/settings/backup', settingsBody({ target: { ...target, hostKeyFingerprint: `SHA256:${'A'.repeat(43)}` } }));
      expect(wrongPin.status).toBe(200);
      const mismatch = await admin.post('/api/admin/backup/test');
      expect(mismatch.status).toBe(400);
      expect(mismatch.body.error).toMatch(/not the SHA256:A+/);

      const res = await admin.put('/api/admin/settings/backup', settingsBody({ keep: 1, target: { ...target, password: undefined, hostKeyFingerprint: sftp.fingerprint } }));
      expect(res.body.backup.target).toMatchObject({ hasPassword: true });
      expect((await admin.post('/api/admin/backup/test')).status).toBe(200);
      expect([...sftp.files.keys()]).toEqual([]);

      const a = (await admin.post('/api/admin/backup/run')).body.run;
      expect(a).toMatchObject({ outcome: 'success' });
      expect([...sftp.files.keys()]).toEqual([a.name]);
      expect(createHash('sha256').update(sftp.files.get(a.name)!).digest('hex')).toBe(a.sha256);
      await new Promise((r) => setTimeout(r, 1100));
      const b = (await admin.post('/api/admin/backup/run')).body.run;
      expect([...sftp.files.keys()]).toEqual([b.name]);
    } finally {
      sftp.close();
    }
  }, 30_000);

  it('the scheduler runs a missed slot once and leaves a satisfied one alone', async () => {
    await admin.put('/api/admin/settings/backup', settingsBody());
    const svc = built.ctx.backups;
    const now = Date.now();
    expect(svc.due(now)).toBe(true);
    await svc.tick(now);
    expect(svc.recent()).toHaveLength(1);
    expect(svc.recent()[0]).toMatchObject({ trigger: 'schedule', outcome: 'success' });
    expect(svc.due(now)).toBe(false);
    expect(svc.due(now + 60_000)).toBe(false);
    // The next day's slot is due again.
    expect(svc.due(now + 25 * 3600_000)).toBe(true);
    // Switching it off stops the schedule but not manual runs.
    await admin.put('/api/admin/settings/backup', settingsBody({ enabled: false }));
    expect(svc.due(now + 25 * 3600_000)).toBe(false);
  });

  it('reports a schedule that has gone quiet as stale', async () => {
    await admin.put('/api/admin/settings/backup', settingsBody({ frequency: 'hourly' }));
    await built.ctx.backups.run('manual');
    expect(built.ctx.backups.status().stale).toBe(false);
    expect(built.ctx.backups.status(Date.now() + 3 * 3600_000).stale).toBe(true);
  });
});
