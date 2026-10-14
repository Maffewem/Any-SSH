import { randomBytes } from 'node:crypto';
import { buildApp, CSRF_HEADER, type BuiltApp } from '../src/app.js';
import { loadConfig, type Config } from '../src/config.js';
import { openDatabase } from '../src/db.js';
import { MemoryMailer } from '../src/mail.js';

type BuildOpts = NonNullable<Parameters<typeof buildApp>[1]>['updates'];

export function testConfig(overrides: Partial<Config> = {}): Config {
  return {
    ...loadConfig({ ANYSSH_MASTER_KEY: randomBytes(32).toString('base64'), ANYSSH_WEB_ROOT: '' }),
    dbPath: ':memory:',
    ...overrides,
  };
}

export async function makeApp(overrides: Partial<Config> = {}, updates?: BuildOpts): Promise<BuiltApp & { mail: MemoryMailer }> {
  const config = testConfig(overrides);
  const mail = new MemoryMailer();
  return { ...(await buildApp(config, { db: openDatabase(':memory:'), logger: false, mailer: mail, ...(updates ? { updates } : {}) })), mail };
}

/** Pulls the token out of the link in the most recent email to `to`. */
export function lastLinkToken(mail: MemoryMailer, to: string): string {
  const msg = [...mail.sent].reverse().find((m) => m.to === to);
  const match = msg && /token=([A-Za-z0-9_-]+)/.exec(msg.text);
  if (!match) throw new Error(`no link emailed to ${to}`);
  return match[1]!;
}

export const ADMIN_PASSWORD = 'correct horse battery staple';

/** Minimal cookie-jar client over app.inject. */
export class Client {
  cookie = '';
  constructor(private readonly built: BuiltApp) {}

  async req(method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE', url: string, body?: unknown, headers: Record<string, string> = {}) {
    const res = await this.built.app.inject({
      method,
      url,
      payload: body as Record<string, unknown> | undefined,
      headers: {
        ...(method === 'GET' ? {} : { [CSRF_HEADER]: '1' }),
        ...(this.cookie ? { cookie: this.cookie } : {}),
        ...headers,
      },
    });
    const set = res.cookies.find((c) => c.name.endsWith('anyssh_sid'));
    if (set) this.cookie = set.value ? `${set.name}=${set.value}` : '';
    return { status: res.statusCode, body: res.body ? (JSON.parse(res.body) as any) : null };
  }

  get = (url: string) => this.req('GET', url);
  post = (url: string, body: unknown = {}) => this.req('POST', url, body);
  patch = (url: string, body: unknown) => this.req('PATCH', url, body);
  put = (url: string, body: unknown) => this.req('PUT', url, body);
  del = (url: string) => this.req('DELETE', url);
}

/** Runs first-time setup and returns a signed-in admin client. */
export async function setupAdmin(built: BuiltApp): Promise<Client> {
  const admin = new Client(built);
  const res = await admin.post('/api/setup', { setupToken: built.setup.token, username: 'admin', password: ADMIN_PASSWORD });
  if (res.status !== 200) throw new Error(`setup failed: ${JSON.stringify(res.body)}`);
  const login = await admin.post('/api/auth/login', { username: 'admin', password: ADMIN_PASSWORD });
  if (login.status !== 200) throw new Error('admin login failed');
  return admin;
}

/** Admin creates a user; the user signs in and replaces the temporary password. */
export async function createUser(built: BuiltApp, admin: Client, username: string, role: 'user' | 'admin' = 'user') {
  const created = await admin.post('/api/admin/users', { username, role });
  const client = new Client(built);
  await client.post('/api/auth/login', { username, password: created.body.temporaryPassword });
  const password = `Str0ng-passphrase-${username.length}-violet!`;
  const changed = await client.post('/api/auth/password', { currentPassword: created.body.temporaryPassword, newPassword: password });
  if (changed.status !== 200) throw new Error(`password change failed: ${JSON.stringify(changed.body)}`);
  return { client, id: created.body.user.id as string, password };
}
