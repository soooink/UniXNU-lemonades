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

`build_uefi.py -d lemonades` defaults to `kernel_compression = "none"`
(the stock boot_b kernel is uncompressed); it emits `Mu-lemonades-0.img` at the
checkout root. The `unixnu bootimg` path emits the gzip variant at
`out/lemonades/boot/boot.img` and validates the header by unpacking it. Try the
uncompressed image first; the gzip variant is the fallback if the ABL turns out
to require compression, and `os_version` (stock: 0x220001aa) can be added to
the config if the ABL checks it.

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

## If the phone is stuck at the boot splash

The splash persisting means nothing has written the framebuffer: the chain
stopped before UEFI SEC. Read the ramoops console from OrangeFox (root adb):

```sh
adb shell cat /sys/fs/pstore/console-ramoops-0   # or console-ramoops0
```

| Evidence in pstore | Meaning | Next step |
| --- | --- | --- |
| Last Android/recovery log only, no `LEM0`, no `UMI:` | The ABL never jumped to the BootShim | Flash the stock-identical full-DTB image (default now); try the gzip variant; compare `fastboot getvar` slot is `_b` |
| `LEM0`/`LEM1` markers, no `UMI: SEC start` | BootShim ran; the jump into UEFI SEC failed | Report back: shim/FD copy fault; check the FD region is untouched (0x9fc00000) |
| `UMI: SEC start` ... stops later | UEFI stopped at the named checkpoint | Send the log; extend MemoryMapLib/driver at that stage |

`LEM0`/`LEM1` are written by BootShim.S before/after copying the firmware
volume into 0x9fc00000; `UMI:` lines are the Silicium SEC/PEI checkpoints.
Always keep a restore path: `fastboot flash boot_b ~/ROm/hw/9r/backups/boot_b.img`.

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
