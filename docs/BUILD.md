# Building and bringing up lemonades

The firmware and boot image build on Linux. The kernel build needs macOS
(Xcode) or the UniXNU GitHub Actions macOS workflow. Nothing here has been run
on hardware yet; the umi repository documents the proven attempt history that
this port follows.

## Linux host dependencies

```sh
# Debian/Ubuntu names; uefi-umi's setup_env.sh installs the same set
sudo apt install -y build-essential clang llvm lld nasm uuid-dev \
  device-tree-compiler python3 python3-venv git curl
```

## Firmware and boot image (Linux)

```sh
git clone https://github.com/UniXNU/UniXNU UniXNU
git -C UniXNU submodule update --init --recursive
git clone https://github.com/reAAAq/UniXNU-lemonades   # or a local checkout
git clone https://github.com/reAAAq/uefi-lemonades

cd UniXNU
./unixnu defconfig lemonades_defconfig -D ../UniXNU-lemonades
./unixnu status -D ../UniXNU-lemonades
./unixnu build firmware --uefi ../uefi-lemonades -D ../UniXNU-lemonades

# Boot image: BootShim + firmware volume + the kona v2.1 DTB (header v2)
./unixnu bootimg --uefi ../uefi-lemonades \
  --dtb ../uefi-lemonades/Resources/DTBs/lemonades.dtb -D ../UniXNU-lemonades
# -> out/lemonades/boot/boot.img
```

The umi fork's own packer also works and produces the same image with the
config-file knobs (`kernel_compression`, `dtb` field):

```sh
cd ../uefi-lemonades && python3 build_uefi.py -d lemonades
```

If the OnePlus ABL rejects the gzip'd kernel, `Resources/Configs/lemonades.toml`
already defaults to `kernel_compression = "none"`; the `unixnu bootimg` path
always gzips, so prefer the `build_uefi.py` path while compression support is
unverified.

## Flash and observe

```sh
adb reboot bootloader
fastboot flash boot_b out/lemonades/boot/boot.img
fastboot reboot
# restore at any time:
#   fastboot flash boot_b ~/ROm/hw/9r/backups/boot_b.img
```

Expected first milestone: the UniXNU menu drawn over the inherited splash
(1080x2400 at 0x9c000000), volume keys move the selection, short power press
confirms, "Restart" reboots back into Android. Logs: ramoops console at
0xB0000000, readable from OrangeFox adb at /sys/fs/pstore/console-ramoops*.

## Kernel (macOS or CI)

The kernel, prelink, payload and userdata steps call Xcode, hdiutil and
diskutil. Fork UniXNU and run its `macOS build` workflow with
`device_repository` = `<you>/UniXNU-lemonades`, `defconfig` = lemonades_defconfig,
and the secret `UNIXNU_UNIQUE_CHIP_ID` set (any nonzero 64-bit hex; the ADT
tool uses it as the platform seed). Download the workflow log artifacts; the
workflow intentionally publishes no images.

The full umi-style Hello profile (prelinked donor components, native UFS,
legacy display, Data seed) is assembled by the bring-up tools in
`bringup/tools/` inside a workspace created with
`bringup/setup-workspace.py`; read `UniXNU-umi/docs/BUILD.md` for the
attempt-80 reference flow and mirror it here once the UEFI stage boots.

## Before the storage stage

Measure this handset's userdata geometry (OrangeFox adb):

```sh
./scripts/measure-userdata-gpt.sh /dev/block/sda
# fill first_lba / last_lba in board.toml [userdata]
```

Everything on `userdata` is lost when the iOS payload is installed.
