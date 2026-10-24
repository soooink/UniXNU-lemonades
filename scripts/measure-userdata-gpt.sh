#!/bin/sh
# Read the lemonades userdata LBA range from the running phone and print the
# board.toml [userdata] block. Run from OrangeFox recovery (root adb) or any
# rooted shell. sda24 is userdata in the stage-0 partition dump; confirm with
# the by-name listing before trusting the device node.
set -e
DEV=${1:-/dev/block/sda}
command -v sgdisk >/dev/null || { echo "sgdisk missing"; exit 1; }
echo "# $DEV partition map:"
sgdisk -p "$DEV"
echo
echo "# Fill board.toml [userdata] with (4096-byte LBAs):"
sgdisk -p "$DEV" | awk '/^ *[0-9]+ .*userdata/ {print "first_lba = 0x"$2; print "last_lba  = 0x"$3}'
