import { lookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';

// Addresses an SSH target may never resolve to unless explicitly allowed: the Any-SSH host
// itself, cloud metadata endpoints (169.254.169.254) and other non-routable ranges.
// Private LAN ranges (10/8, 192.168/16, ...) stay allowed: reaching them is the point.
const blocked = new BlockList();
blocked.addSubnet('0.0.0.0', 8, 'ipv4');
blocked.addSubnet('127.0.0.0', 8, 'ipv4');
blocked.addSubnet('169.254.0.0', 16, 'ipv4');
blocked.addSubnet('224.0.0.0', 4, 'ipv4');
blocked.addSubnet('240.0.0.0', 4, 'ipv4');
blocked.addAddress('::', 'ipv6');
blocked.addAddress('::1', 'ipv6');
blocked.addSubnet('fe80::', 10, 'ipv6');
blocked.addSubnet('ff00::', 8, 'ipv6');
blocked.addSubnet('fd00:ec2::', 32, 'ipv6');

export function isBlockedAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return blocked.check(address, 'ipv4');
  if (family === 6) {
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
    if (mapped) return blocked.check(mapped[1]!, 'ipv4');
    return blocked.check(address, 'ipv6');
  }
  return true;
}

/**
 * Resolves the target once and returns the IP to dial. Connecting to the vetted IP (not the
 * name) means a DNS answer cannot change between the check and the connection.
 */
export async function resolveTarget(host: string, allowLoopback: boolean): Promise<string> {
  const addresses = isIP(host) ? [{ address: host }] : await lookup(host, { all: true, verbatim: true });
  if (!addresses.length) throw new Error(`Could not resolve ${host}`);
  if (allowLoopback) return addresses[0]!.address;
  const ok = addresses.find((a) => !isBlockedAddress(a.address));
  if (!ok) throw new Error(`${host} resolves to an address this server is not allowed to connect to.`);
  return ok.address;
}
