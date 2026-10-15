import { randomToken, sha256 } from '../crypto.js';
import type { ServerAccess } from '../types.js';

const TICKET_TTL_MS = 30_000;

/**
 * Which credentials a connection uses. `saved` is whatever the owner stored on the server;
 * the rest are the connecting user's own. A one-off key exists only in this object, in memory:
 * it is never written to the database and is dropped when the ticket is redeemed or expires.
 */
export type ConnectCredential =
  | { type: 'saved' }
  | { type: 'key'; keyId: string }
  | { type: 'oneoff'; privateKey: string; passphrase?: string; fingerprint: string }
  | { type: 'password' };

export interface TerminalTicket {
  userId: string;
  serverId: string;
  sessionIdHash: string;
  access: ServerAccess;
  credential: ConnectCredential;
  /** SSH login name for this connection: the server's, unless the user brought their own credentials. */
  username: string;
  /** Id of a live (detached) terminal of this user's to re-attach to instead of opening a new one. */
  resume?: string;
}

export interface LiveTerminal {
  /** Random, unguessable; the browser holds it in memory to re-attach after a dropped connection. */
  id: string;
  userId: string;
  serverId: string;
  /** The web session this terminal answers to. Follows the user's most recent re-attach. */
  sessionIdHash: string;
  /** The jump host this terminal runs through, if any. */
  jumpHostId: string | null;
  /** True while a browser is not attached and the SSH session is being kept for a re-attach. */
  detached: boolean;
  close(reason: string): void;
  /** Pauses (locked) or resumes the terminal while its web session is locked. */
  setLocked(locked: boolean): void;
}

/**
 * Tracks live SSH terminals so that revoking access (logout, share removal, user disabled,
 * server deleted) tears down connections immediately rather than at the next reconnect.
 * Also holds the single-use tickets that authorise opening a terminal WebSocket.
 */
export class TerminalRegistry {
  private readonly tickets = new Map<string, TerminalTicket & { expiresAt: number }>();
  private readonly live = new Set<LiveTerminal>();

  issueTicket(t: TerminalTicket): string {
    this.sweepTickets();
    const token = randomToken(32);
    this.tickets.set(sha256(token), { ...t, expiresAt: Date.now() + TICKET_TTL_MS });
    return token;
  }

  /** Returns the ticket once; a second redemption, or one after expiry, gets null. */
  redeemTicket(token: string): TerminalTicket | null {
    const key = sha256(token);
    const t = this.tickets.get(key);
    this.tickets.delete(key);
    if (!t || t.expiresAt < Date.now()) return null;
    const { expiresAt: _e, ...ticket } = t;
    return ticket;
  }

  private sweepTickets(): void {
    const now = Date.now();
    for (const [k, t] of this.tickets) if (t.expiresAt < now) this.tickets.delete(k);
  }

  add(t: LiveTerminal): () => void {
    this.live.add(t);
    return () => this.live.delete(t);
  }

  /** A terminal this user may re-attach to: still open and kept alive after its browser dropped. */
  resumable(userId: string, id: string): LiveTerminal | null {
    for (const t of this.live) if (t.id === id && t.userId === userId && t.detached) return t;
    return null;
  }

  countForUser(userId: string): number {
    let n = 0;
    for (const t of this.live) if (t.userId === userId) n++;
    return n;
  }

  private closeWhere(pred: (t: LiveTerminal) => boolean, reason: string): void {
    for (const t of [...this.live]) if (pred(t)) t.close(reason);
  }

  closeForUser(userId: string, reason: string): void {
    this.closeWhere((t) => t.userId === userId, reason);
  }

  closeForJumpHost(jumpHostId: string, reason: string): void {
    this.closeWhere((t) => t.jumpHostId === jumpHostId, reason);
  }

  closeForServer(serverId: string, reason: string): void {
    this.closeWhere((t) => t.serverId === serverId, reason);
  }

  closeForUserServer(userId: string, serverId: string, reason: string): void {
    this.closeWhere((t) => t.userId === userId && t.serverId === serverId, reason);
  }

  closeForSessions(idHashes: string[], reason: string): void {
    const set = new Set(idHashes);
    this.closeWhere((t) => set.has(t.sessionIdHash), reason);
  }

  setLockedForSession(idHash: string, locked: boolean): void {
    for (const t of this.live) if (t.sessionIdHash === idHash) t.setLocked(locked);
  }

  closeAll(reason: string): void {
    this.closeWhere(() => true, reason);
  }
}
