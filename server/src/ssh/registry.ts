import { randomToken, sha256 } from '../crypto.js';
import type { ServerAccess } from '../types.js';

const TICKET_TTL_MS = 30_000;

export interface TerminalTicket {
  userId: string;
  serverId: string;
  sessionIdHash: string;
  access: ServerAccess;
}

interface LiveTerminal {
  userId: string;
  serverId: string;
  sessionIdHash: string;
  close(reason: string): void;
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

  closeAll(reason: string): void {
    this.closeWhere(() => true, reason);
  }
}
