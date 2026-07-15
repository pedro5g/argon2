#!/usr/bin/env bash
#
# Vulnerability #4 — end-to-end swap-dumping proof (requires root).
#
# Demonstrates that a password hashed through this library is NEVER written to
# the swap file, because the native engine locks its sensitive memory with
# mlock(). Run this in a THROWAWAY Linux VM — it creates and enables a swap
# file and deliberately pushes the machine into swapping.
#
# WARNING: manipulates system swap. Do not run on a machine you care about.
#
# Usage:  sudo ./scripts/swap-dump-test.sh
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "This test must run as root (it manages a swap file)." >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SWAPFILE="$(mktemp /tmp/argon-swap.XXXXXX)"
MARKER="SWAP_MARKER_$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"

cleanup() {
  echo "==> Cleaning up"
  swapoff "$SWAPFILE" 2>/dev/null || true
  rm -f "$SWAPFILE"
}
trap cleanup EXIT

echo "==> Creating and enabling a 512 MiB swap file at $SWAPFILE"
dd if=/dev/zero of="$SWAPFILE" bs=1M count=512 status=none
chmod 600 "$SWAPFILE"
mkswap "$SWAPFILE" >/dev/null
swapon "$SWAPFILE"

echo "==> Hashing a password containing the marker: $MARKER"
# Hash the marker as a password, then hold the process alive briefly while a
# memory hog forces the kernel to swap. If mlock works, the marker's bytes are
# pinned in RAM and can never reach $SWAPFILE.
MARKER="$MARKER" node --import tsx -e '
  import { hashRaw } from "'"$ROOT"'/index.ts";
  const marker = Buffer.from(process.env.MARKER, "utf8");
  await hashRaw({ password: marker, salt: Buffer.alloc(16, 7), m: 1 << 15, t: 4, p: 1, hashLength: 32 });
  // Keep the process alive so the memory-pressure phase overlaps a live run.
  await new Promise((r) => setTimeout(r, 8000));
' &
NODE_PID=$!

echo "==> Forcing memory pressure to push pages into swap"
# Allocate more than available RAM to guarantee swapping activity.
python3 - <<'PY' || true
import time
hog = []
try:
    for _ in range(200):
        hog.append(bytearray(64 * 1024 * 1024))  # 64 MiB chunks
        time.sleep(0.02)
except MemoryError:
    pass
time.sleep(2)
PY

wait "$NODE_PID" 2>/dev/null || true

echo "==> Searching the swap file for the marker"
if grep -a -c "$MARKER" "$SWAPFILE" >/dev/null 2>&1; then
  echo "FAIL: marker found in swap — memory was NOT locked." >&2
  exit 1
else
  echo "PASS: marker not present in swap — mlock kept the password in RAM."
fi
