#!/bin/sh
# Build the local storage-profile boot image from a CI kernel artifact.
#
#   make_lemonades_storage_image.sh <run-id>
#   make_lemonades_storage_image.sh <downloaded-artifact-dir>
#
# Steps: emit_prelink (donor cache + APFS/storage closure roots) ->
# pinned-layout verification -> entry-probe patch -> payload -> bootimg.
set -e

DEV=$(cd "$(dirname "$0")/../.." && pwd)
U=$(dirname "$DEV")/UniXNU
[ -d "$U" ] || { echo "UniXNU checkout not found next to $DEV"; exit 1; }
cd "$U"

# Host toolchain: llvm tools for the probe patch, lld shared-library shim,
# and the user-level mtools for the FAT payload volume.
export PATH="$HOME/toolchain/LLVM-19.1.7-Linux-X64/bin:$HOME/toolchain/local/usr/bin:$PATH"
export LD_LIBRARY_PATH="$HOME/toolchain/compat"
export UNIXNU_UEFI="$HOME/ROm/uefi-lemonades"

if [ -d "$1" ]; then
  DL="$1"
else
  DL="out/lemonades-xnu/kernel-download-$1"
  rm -rf "$DL"; mkdir -p "$DL"
  gh run download "$1" -R soooink/UniXNU-lemonades -n lemonades-kernel -D "$DL"
fi
KERNEL=$(ls "$DL"/*entry-trace-kernel.macho "$DL"/*source-kernel.macho 2>/dev/null | head -1)
[ -n "$KERNEL" ] && [ -f "$KERNEL" ] || { echo "no kernel macho in $DL"; ls "$DL"; exit 1; }
echo "source kernel: $KERNEL"

OUT=out/lemonades/kernel-storage
rm -rf "$OUT"; mkdir -p "$OUT"
# Donor cache + storage-closure roots (APFS and the filesystem-compression
# kext the native UFS root mount pulls in; identical to the umi storage prelink).
python3 kits/NativePrelink/emit_prelink.py \
  --kernel "$KERNEL" \
  --prelinked out/ipsw/21H461/kernelcache.decompressed \
  --slide=-0x1000000 \
  --output "$OUT/kernel.macho" \
  --early-security-init "com.apple.driver.AppleMobileFileIntegrity=0xfffffff005ab4ae0" \
  --root com.apple.driver.AppleMobileFileIntegrity \
  --root com.apple.security.sandbox \
  --root com.apple.driver.ApplePMGR \
  --root com.apple.filesystems.apfs \
  --root com.apple.AppleFSCompression.AppleFSCompressionTypeZlib

# The pinned binding record must still describe this image's layout (and
# family: the storage root set, selected through LEMONADES_STORAGE_RECORD on
# the CI side so the archive's .set constants match this prelink).
python3 "$DEV/bringup/tools/verify_lemonades_storage_bindings.py" \
  "$OUT/kernel.macho" --record storage-bindings-storage.json

# Entry probe: stage bars + panic screen, no reset probe.
python3 "$DEV/scripts/patch-xnu-entry-probe.py" "$OUT/kernel.macho" --panic-screen --no-reset

# Payload (ADT + FAT volume) and the boot images. Two deliverables:
#   boot-storage.img           control: no UFS boot args
#   boot-storage-ufs-diag.img  UFS probe: native-ufs-root=1 plus
#                              native-ufs-diagnostics=1, so any UFS root
#                              failure panics with the full diagnostic table.
# (The cli module has no __main__ guard: import main() explicitly.)
# The stock three-DTB blob the 9R ABL accepts (kona v2.1 primary).
DTC="$HOME/ROm/uefi-lemonades/Resources/DTBs/lemonades-full.dtb"

# DarwinBoot validates the XNU trust cache bundle; the IPSW ships an IM4P.
python3 "$DEV/bringup/tools/make_lemonades_trustcache.py" \
  out/ipsw/21H461/044-76040-038.dmg.trustcache \
  out/lemonades/trustcache/lemonades-static.trustcache
build_payload() {
  local extra=""
  for spec in "$@"; do extra="$extra '--kernel-arg','$spec',"; done
  PYTHONPATH="$U/scripts" python3 -c "
import sys
sys.argv=['unixnu','build','payload','--kernel','$OUT/kernel.macho','--unique-chip-id','0x9E3779B97F4A7C15',
 '--trust-cache','out/lemonades/trustcache/lemonades-static.trustcache',$extra]
from unixnu.cli import main
main()"
}
bootimg_for() {
  PYTHONPATH="$U/scripts" python3 -c "
import sys
sys.argv=['unixnu','bootimg','--ramdisk','out/lemonades/payload/payload.img','--dtb','$DTC','-o','out/lemonades/boot/$1']
from unixnu.cli import main
main()"
}
build_payload
bootimg_for boot-storage.img
build_payload native-ufs-root=1 native-ufs-diagnostics=1
bootimg_for boot-storage-ufs-diag.img

echo "FLASH control  : fastboot flash boot_b $U/out/lemonades/boot/boot-storage.img"
echo "FLASH ufs-diag : fastboot flash boot_b $U/out/lemonades/boot/boot-storage-ufs-diag.img"
