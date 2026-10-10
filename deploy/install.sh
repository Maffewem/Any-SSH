#!/usr/bin/env bash
# Any-SSH installer for a fresh Linux server.
#
#   curl -fsSL https://raw.githubusercontent.com/Maffewem/Any-SSH/main/deploy/install.sh | sudo bash
#
# It installs Docker if needed, asks for your domain and email, generates the master key and settings, sets up nightly
# backups, and starts Any-SSH behind Caddy (automatic HTTPS) using the prebuilt image. Running it again on an installed
# server keeps the existing key and settings and just brings the files and containers up to date.
#
# Non-interactive use: set ANYSSH_DOMAIN and ANYSSH_EMAIL (and optionally ANYSSH_SMTP_HOST, _PORT, _USER, _PASS and
# ANYSSH_MAIL_FROM) in the environment, e.g. `curl … | sudo ANYSSH_DOMAIN=ssh.example.com ANYSSH_EMAIL=me@example.com bash`.
#
# Other settings: ANYSSH_DIR (default /opt/any-ssh), ANYSSH_REF (git branch or tag to install from, default main),
# ANYSSH_VERSION (image tag, default latest), ANYSSH_SKIP_START=1 (prepare everything but don't start).

# Everything is inside main(), so a partially downloaded script never runs.
main() {
  set -euo pipefail

  local dir="${ANYSSH_DIR:-/opt/any-ssh}"
  local ref="${ANYSSH_REF:-main}"
  local source="${ANYSSH_SOURCE:-https://raw.githubusercontent.com/Maffewem/Any-SSH/${ref}}"

  say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
  warn() { printf '\033[33mWarning:\033[0m %s\n' "$*" >&2; }
  die() { printf '\033[31mError:\033[0m %s\n' "$*" >&2; exit 1; }
  # Prompts read from the terminal, because stdin is this script when piped from curl.
  ask() {
    local prompt="$1" default="${2:-}" reply
    [ -r /dev/tty ] || die "No terminal to ask on. Set the settings as environment variables instead (see the top of this script)."
    if [ -n "$default" ]; then prompt="$prompt [$default]"; fi
    read -r -p "$prompt: " reply </dev/tty
    printf '%s' "${reply:-$default}"
  }
  ask_secret() {
    local reply
    [ -r /dev/tty ] || die "No terminal to ask on."
    read -r -s -p "$1: " reply </dev/tty
    printf '\n' >/dev/tty
    printf '%s' "$reply"
  }
  fetch() { curl -fsSL --proto '=https,file' "$source/$1" -o "$2"; }

  [ "$(uname -s)" = Linux ] || die "This installer is for Linux servers. See docs/DEPLOY.md for other setups."
  [ "$(id -u)" -eq 0 ] || die "Run it as root, e.g. 'curl -fsSL … | sudo bash'."
  command -v curl >/dev/null || die "curl is required."
  command -v openssl >/dev/null || die "openssl is required (apt install openssl)."

  # ---- Docker ----
  if ! command -v docker >/dev/null; then
    say "Installing Docker (get.docker.com)"
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker >/dev/null 2>&1 || true
  fi
  docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is missing. Install the docker-compose-plugin package and run this again."
  docker info >/dev/null 2>&1 || die "Docker is installed but not running. Start it (systemctl start docker) and run this again."

  # ---- Files ----
  say "Installing to $dir"
  install -d -m 755 "$dir" "$dir/deploy"
  install -d -m 700 "$dir/secrets" "$dir/backups"
  ANYSSH_TMP="$(mktemp -d)"
  trap 'rm -rf "$ANYSSH_TMP"' EXIT
  local tmp="$ANYSSH_TMP"
  fetch compose.yaml "$tmp/compose.yaml"
  fetch deploy/Caddyfile "$tmp/Caddyfile"
  fetch deploy/any-ssh "$tmp/any-ssh"
  install -m 644 "$tmp/compose.yaml" "$dir/compose.yaml"
  install -m 644 "$tmp/Caddyfile" "$dir/deploy/Caddyfile"
  install -m 755 "$tmp/any-ssh" /usr/local/bin/any-ssh

  # ---- Master key: generated once, never replaced ----
  if [ ! -s "$dir/secrets/master_key" ]; then
    say "Generating the master key"
    (umask 077 && openssl rand -base64 32 >"$dir/secrets/master_key")
  else
    say "Keeping the existing master key"
  fi
  # The app runs as uid 1000 inside the container and must be able to read it; nobody else can.
  chown 1000:1000 "$dir/secrets/master_key"
  chmod 600 "$dir/secrets/master_key"

  # ---- Settings ----
  if [ ! -s "$dir/.env" ]; then
    local domain="${ANYSSH_DOMAIN:-}" email="${ANYSSH_EMAIL:-}"
    local smtp_host="${ANYSSH_SMTP_HOST:-}" smtp_port="${ANYSSH_SMTP_PORT:-587}" smtp_user="${ANYSSH_SMTP_USER:-}"
    local smtp_pass="${ANYSSH_SMTP_PASS:-}" mail_from="${ANYSSH_MAIL_FROM:-}"

    if [ -z "$domain" ]; then
      echo
      echo "Any-SSH needs a domain name pointing at this server, e.g. ssh.example.com."
      echo "Ports 80 and 443 must be reachable so it can get an HTTPS certificate."
      domain="$(ask "Domain")"
    fi
    domain="${domain#http://}"; domain="${domain#https://}"; domain="${domain%%/*}"
    [[ "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ && "$domain" == *.* ]] || die "'$domain' doesn't look like a domain name."
    if [ -z "$email" ] && [ -z "${ANYSSH_DOMAIN:-}" ]; then
      email="$(ask "Your email (for certificate expiry notices)")"
    fi
    if [ -z "$smtp_host" ] && [ -z "${ANYSSH_DOMAIN:-}" ]; then
      echo
      echo "Email lets Any-SSH send invites and password reset links. Without it, you copy links to people yourself."
      if [[ "$(ask "Set up outgoing email (SMTP) now? (y/N)")" =~ ^[Yy] ]]; then
        smtp_host="$(ask "SMTP server")"
        smtp_port="$(ask "SMTP port (465 or 587)" 587)"
        smtp_user="$(ask "SMTP username" "$email")"
        smtp_pass="$(ask_secret "SMTP password")"
        mail_from="$(ask "Send from" "Any-SSH <${smtp_user:-noreply@$domain}>")"
      fi
    fi
    # Values are single-quoted so Compose reads them literally ($, # and spaces included).
    for v in "$domain" "$email" "$smtp_host" "$smtp_port" "$smtp_user" "$smtp_pass" "$mail_from"; do
      [[ "$v" != *$'\n'* && "$v" != *"'"* ]] || die "Settings can't contain line breaks or single quotes."
    done

    say "Writing settings to $dir/.env"
    (
      umask 077
      {
        echo "# Any-SSH settings. Change them with 'any-ssh config'. See .env.example in the repository for every option."
        echo "ANYSSH_DOMAIN=$domain"
        echo "ANYSSH_ORIGIN=https://$domain"
        echo "ANYSSH_ACME_EMAIL='$email'"
        echo "ANYSSH_VERSION=${ANYSSH_VERSION:-latest}"
        echo
        echo "# Outgoing email for invites, password resets and security notices."
        if [ -n "$smtp_host" ]; then
          echo "ANYSSH_SMTP_HOST='$smtp_host'"
          echo "ANYSSH_SMTP_PORT='$smtp_port'"
          [ -z "$smtp_user" ] || echo "ANYSSH_SMTP_USER='$smtp_user'"
          [ -z "$smtp_pass" ] || echo "ANYSSH_SMTP_PASS='$smtp_pass'"
          [ -z "$mail_from" ] || echo "ANYSSH_MAIL_FROM='$mail_from'"
        else
          echo "# ANYSSH_SMTP_HOST=smtp.example.com"
          echo "# ANYSSH_SMTP_PORT=587"
          echo "# ANYSSH_SMTP_USER="
          echo "# ANYSSH_SMTP_PASS="
          echo "# ANYSSH_MAIL_FROM=Any-SSH <any-ssh@$domain>"
        fi
      } >"$dir/.env"
    )

    if ! getent ahosts "$domain" >/dev/null 2>&1; then
      warn "$domain doesn't resolve yet. Point its DNS at this server; HTTPS starts working once it does."
    fi
  else
    say "Keeping the existing settings in $dir/.env"
  fi
  chmod 600 "$dir/.env"

  # ---- Nightly backups ----
  if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
    cat >/etc/systemd/system/any-ssh-backup.service <<'UNIT'
[Unit]
Description=Back up the Any-SSH database
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/any-ssh backup
UNIT
    cat >/etc/systemd/system/any-ssh-backup.timer <<'UNIT'
[Unit]
Description=Nightly Any-SSH database backup

[Timer]
OnCalendar=*-*-* 03:17:00
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
UNIT
    systemctl daemon-reload
    systemctl enable --now any-ssh-backup.timer >/dev/null
  else
    warn "systemd not found, so nightly backups were not scheduled. Run 'any-ssh backup' from cron instead."
  fi

  if [ "${ANYSSH_SKIP_START:-}" = 1 ]; then
    say "Ready. Start it with: any-ssh start"
    return
  fi

  # ---- Start ----
  say "Downloading and starting Any-SSH"
  ANYSSH_DIR="$dir" /usr/local/bin/any-ssh start

  local domain_now
  domain_now="$(sed -n 's/^ANYSSH_DOMAIN=//p' "$dir/.env")"
  echo
  say "Any-SSH is running."
  echo
  echo "  1. Open https://$domain_now/"
  local token
  token="$(ANYSSH_DIR="$dir" /usr/local/bin/any-ssh setup-token 2>/dev/null || true)"
  if [ -n "$token" ]; then
    echo "  2. Paste this one-time setup token and create your admin account:"
    echo
    echo "       $token"
    echo
    echo "  3. Turn on two-factor sign-in for it (Account page)."
  else
    echo "  2. Sign in with your existing account."
  fi
  echo
  echo "  Save a copy of the master key somewhere safe and separate from this server, such as your password manager."
  echo "  Without it, backups can't be restored. Show it with: sudo cat $dir/secrets/master_key"
  echo
  echo "  Manage it with the 'any-ssh' command: any-ssh update, any-ssh backup, any-ssh logs, any-ssh help"
}

main "$@"
