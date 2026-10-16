#!/usr/bin/env bash
# Prepares a machine to act as an Any-SSH jump host (bastion).
#
# It creates a dedicated, unprivileged account that can only relay TCP connections: no shell, no
# agent or X11 forwarding, no tunnels. Any-SSH logs in with its own key and opens a channel to the
# target; the session to the target stays end to end, so this machine never sees the user's
# credentials or keystrokes.
#
# Run as root on the jump host. Review it first; it changes nothing except what is listed below.
#
#   sudo bash jump-host-setup.sh --key 'ssh-ed25519 AAAA… any-ssh' [--user anyssh-jump] [--allow host:port ...]
#
#   --key    The public key shown for this jump host in Any-SSH (Settings → Access → Jump hosts).
#   --user   Account to create (default: anyssh-jump).
#   --allow  Restrict the account to these destinations (repeatable). Without it any destination
#            the jump host itself can reach is allowed.
#
# Changes made: the account, its authorized_keys, and /etc/ssh/sshd_config.d/anyssh-jump.conf.
# Nothing is overwritten without a backup, and sshd's configuration is validated before reload.
set -euo pipefail

user="anyssh-jump"
key=""
allow=()

while [ $# -gt 0 ]; do
  case "$1" in
    --key) key="${2:-}"; shift 2 ;;
    --user) user="${2:-}"; shift 2 ;;
    --allow) allow+=("${2:-}"); shift 2 ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "Run this as root (for example with sudo)." >&2; exit 1; }
[[ "$key" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp[0-9]+)\ [A-Za-z0-9+/=]+(\ .*)?$ ]] || { echo "Pass the Any-SSH public key with --key '<key>'." >&2; exit 2; }
[[ "$user" =~ ^[a-z_][a-z0-9_-]{0,30}$ ]] || { echo "Invalid account name: $user" >&2; exit 2; }
for a in "${allow[@]:-}"; do
  [ -z "$a" ] || [[ "$a" =~ ^[A-Za-z0-9._:-]+:[0-9]{1,5}$ ]] || { echo "--allow expects host:port, got: $a" >&2; exit 2; }
done
command -v sshd >/dev/null || { echo "OpenSSH server (sshd) is not installed." >&2; exit 1; }

if ! id "$user" >/dev/null 2>&1; then
  shell=/usr/sbin/nologin; [ -x "$shell" ] || shell=/sbin/nologin; [ -x "$shell" ] || shell=/bin/false
  useradd --create-home --shell "$shell" --comment "Any-SSH jump host" "$user"
  echo "Created account $user."
fi
# Key-only: a locked password means the account cannot sign in with one.
passwd -l "$user" >/dev/null 2>&1 || true

home="$(getent passwd "$user" | cut -d: -f6)"
install -d -m 700 -o "$user" -g "$(id -gn "$user")" "$home/.ssh"
options="restrict,port-forwarding"
for a in "${allow[@]:-}"; do [ -z "$a" ] || options+=",permitopen=\"$a\""; done
line="$options $key"
auth="$home/.ssh/authorized_keys"
if [ -f "$auth" ] && ! grep -qxF "$line" "$auth"; then cp -p "$auth" "$auth.bak.$(date +%s)"; fi
grep -qxF "$line" "$auth" 2>/dev/null || echo "$line" >> "$auth"
chown "$user:$(id -gn "$user")" "$auth"; chmod 600 "$auth"

conf=/etc/ssh/sshd_config.d/anyssh-jump.conf
mkdir -p /etc/ssh/sshd_config.d
cat > "$conf" <<CONF
# Written by Any-SSH jump-host-setup.sh
Match User $user
    AllowTcpForwarding yes
    AllowAgentForwarding no
    X11Forwarding no
    PermitTTY no
    PermitTunnel no
    GatewayPorts no
    ForceCommand /bin/false
CONF
grep -Eqs '^\s*Include\s+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config || echo "Note: /etc/ssh/sshd_config does not Include sshd_config.d; add that line for $conf to apply." >&2

if sshd -t; then
  systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || service ssh reload 2>/dev/null || echo "Reload sshd yourself to apply the change." >&2
else
  rm -f "$conf"
  echo "sshd rejected the configuration, so the change was removed." >&2
  exit 1
fi

echo
echo "Done. Verify this host key in Any-SSH before trusting it:"
for f in /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_rsa_key.pub; do
  [ -f "$f" ] && ssh-keygen -lf "$f"
done
