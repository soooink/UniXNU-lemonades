#!/bin/sh
# Build the attempt-15-style EFI diagnostic RAM payload: a 64 MiB FAT32 volume
# with EFI/UniXNU/unixnu.toml (menu: "Verify RAM payload" + Restart) and the
# LemonadesPayloadCheck.efi application from the firmware build. This is the
# stage-1 payload; the XNU payload replaces it once a kernel is built.
# Usage: make-diag-payload.sh <uefi-checkout> [output.img]
set -e
UEFI=${1:?uefi checkout}
OUT=${2:-/tmp/lemonades-payload.img}
APP=$(find "$UEFI/Build/lemonadesPkg" -name LemonadesPayloadCheck.efi -path "*OUTPUT*" | head -1)
[ -n "$APP" ] || { echo "build the firmware first"; exit 1; }
TOML=$(dirname "$0")/../package/unixnu.toml
mformat -C -F -T 131072 -v LEM9RXNU -N 53484e47 -i "$OUT" ::
mmd -i "$OUT" ::/EFI ::/EFI/UniXNU ::/EFI/UniXNU/Payloads
mcopy -i "$OUT" "$TOML" ::/EFI/UniXNU/unixnu.toml
mcopy -i "$OUT" "$APP" ::/EFI/UniXNU/Payloads/LemonadesPayloadCheck.efi
echo "$OUT"
