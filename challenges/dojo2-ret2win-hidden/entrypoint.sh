#!/usr/bin/env bash
set -euo pipefail

CHAL="/challenge/challenge"

fail() {
  echo "[!] $*" >&2
  exit 1
}

# Optional: disable ASLR inside container for simplicity (best-effort)
if [ -w /proc/sys/kernel/randomize_va_space ]; then
  echo 0 > /proc/sys/kernel/randomize_va_space || true
fi

# Write flag from environment (provided at runtime)
if [ -z "${FLAG:-}" ]; then
  fail "FLAG environment variable is missing."
fi

echo -n "$FLAG" > /flag
chown root:root /flag
chmod 0400 /flag

# Re-assert SUID on challenge (fail loudly if it doesn't stick)
[ -f "$CHAL" ] || fail "Challenge binary missing at $CHAL"

chown root:root "$CHAL"
chmod 4755 "$CHAL"

# Verify SUID is present
PERMS="$(stat -c '%A %U %G' "$CHAL" || true)"
echo "$PERMS" | grep -q "^-rws" || fail "SUID not present on $CHAL (got: $PERMS)"

# Remove FLAG from environment to prevent leakage
unset FLAG

# Start ttyd with a clean environment and drop to hacker user.
# Provide only minimal safe environment variables.
exec ttyd -p 7681 -W env -i \
  HOME=/home/hacker \
  USER=hacker \
  LOGNAME=hacker \
  SHELL=/bin/bash \
  TERM=xterm-256color \
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  su -s /bin/bash -l hacker