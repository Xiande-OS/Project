#!/bin/bash
# Build a minimal EXT4 disk image with one busybox testcode script.
#
# Usage: mini-disk.sh <output.img> <testcode.sh body...>
#   The testcode body is read from stdin if no extra args given.
#
# The image is laid out exactly the way contest_runner expects:
#   /musl/busybox
#   /musl/busybox_testcode.sh   <- the script you pass in
# plus extra binaries from /home/user/testsuite-build/sdcard/riscv/musl/
# that you copy in by setting EXTRA_FILES="foo bar baz".

set -euo pipefail

OUT="$1"
SCRIPT_BODY="${2:-$(cat)}"
EXTRA=${EXTRA_FILES:-}

SDCARD=/home/user/testsuite-build/sdcard/riscv/musl
STAGE=$(mktemp -d)
mkdir -p "$STAGE/musl"

cp "$SDCARD/busybox" "$STAGE/musl/busybox"
chmod +x "$STAGE/musl/busybox"

# Optional extras (binaries the test invokes).
for f in $EXTRA; do
    if [ -f "$SDCARD/$f" ]; then
        cp -L "$SDCARD/$f" "$STAGE/musl/"
        chmod +x "$STAGE/musl/$f" 2>/dev/null || true
    else
        echo "warn: extra '$f' not found in $SDCARD" >&2
    fi
done

cat > "$STAGE/musl/busybox_testcode.sh" <<EOF
$SCRIPT_BODY
EOF

dd if=/dev/zero of="$OUT" bs=1M count=16 status=none
mke2fs -t ext4 -q -d "$STAGE" "$OUT" >/dev/null 2>&1
rm -rf "$STAGE"
echo "ok: $OUT"
