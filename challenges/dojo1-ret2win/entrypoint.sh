#!/bin/bash
set -e

# Create /flag from env; root-only
echo "${FLAG:-flag{default_flag_for_testing}}" > /flag
chown root:root /flag
chmod 0400 /flag

# PROFESSOR VERDICT: enforce SUID root on the challenge every start
chown root:root /challenge/challenge
chmod 4755 /challenge/challenge

echo "========================================="
echo "Mini-DOJO Workspace - Dojo 1: ret2win"
echo "========================================="
echo ""
echo "Flag perms:   $(ls -l /flag)"
echo "Binary perms: $(ls -l /challenge/challenge)"
echo ""

# Fail fast if SUID isn't set (prevents confusing labs)
if ! ls -l /challenge/challenge | grep -q '^-rws'; then
  echo "[FATAL] /challenge/challenge is not SUID. Fix image/build/runtime."
  exit 1
fi

# Start ttyd as hacker
exec /usr/local/bin/ttyd -W -p 7681 -i 0.0.0.0 su - hacker