# UniXNU-lemonades

**UniXNU bring-up for the OnePlus 9R (`lemonades`, SM8250-AC / Snapdragon 870).**

This repository is derived from [reAAAq's Xiaomi Mi 10 port](https://github.com/reAAAq/UniXNU-umi)
(attempt 80: iPadOS 17.7.11 reaches Setup Assistant with working touch on the
same SM8250 SoC family). The OnePlus 9R uses the identical kona silicon, the
identical DRAM bank map and the identical XBL "UEFI FD" load region, so the
port reuses the umi board, kernel configuration, ADT generator and package
with 9R-specific deltas. **Nothing here has run on hardware yet.**

English | [简体中文](README.zh-CN.md)

## Repositories

| Repository | Contents |
| --- | --- |
| `UniXNU-lemonades` (this repo) | Board description, kernel defconfig, ADT generator, device package, bring-up tools |
| `uefi-lemonades` | Mu-Silicium UEFI port: `Platforms/OnePlus/lemonadesPkg`, inherited-framebuffer GOP, PON/TLMM buttons, RAM FAT payload |

Both clone alongside [UniXNU](https://github.com/UniXNU/UniXNU) and
[UniXNU-sheng](https://github.com/UniXNU/UniXNU-sheng), pinned in `source-lock.json`.

## Device deltas versus umi (Mi 10)

| Item | umi | lemonades (OnePlus 9R) |
| --- | --- | --- |
| SoC | SM8250 | SM8250-AC (Snapdragon 870), same kona MMIO, PSCI `0,0x100..0x700` |
| DRAM banks | 0x39900000@0x80000000, 0x140000000@0xc0000000, 0x180000000@0x200000000 | identical (sum 0x2f9900000) |
| UEFI FD region | 0x9fc00000 + 0x300000 | identical (xbl uefiplat.cfg) |
| TZApps / PIL reserved | 0x82400000+0x3a00000 / 0x86000000+0xd200000 | 0x82400000+0x0B400000 / 0x8DA00000+0x0AD00000 |
| Framebuffer (inherited) | 0x9c000000 1080x2340 | 0x9c000000 1080x2400 (Samsung AMB655X, DSC cmd mode) |
| Volume keys | PON bit1 / PMIC GPIO6 | TLMM GPIO 7 / GPIO 6 (SOUTH tile, active low) |
| UFS host / ICE | 0x1d84000 / 0x1d90000 | identical |
| GIC / timers | GICD 0x17a00000, GICR 0x17a60000, 19.2 MHz | identical |
| Touch | ST FTM5 (working under XNU at attempt 80) | **Synaptics S3908** — needs its own driver, not started |
| Boot image | header v1, `fastboot boot` works | **header v2, no vendor_boot, `fastboot boot` rejected** |
| Boot flow | `fastboot boot boot.img` | flash `boot_b` (keep `backups/boot_b.img` to restore) |
| ramoops console | 0xB0000000 | identical |
| Donor IPSW | iPad7,1 iPadOS 17.7.11 (21H461) | identical |

## Bring-up order

1. **UEFI menu on hardware.** Build the firmware and boot image on Linux
   (see `docs/BUILD.md`), flash to `boot_b`, observe the UniXNU menu on the
   inherited splash, navigate with volume keys, confirm with the power key.
   The ramoops console at 0xB0000000 records the UEFI log for recovery adb.
2. **Payload stage.** RAM FAT payload, `unixnu.toml`, `PayloadCheck` entry.
3. **Kernel entry.** Source-built XNU (macOS or GitHub Actions runner) with
   `lemonades_defconfig`; platform expert against the generated ADT.
4. **Storage and root.** Native UFS (same controller as umi), then the OS /
   SystemOS windows from the iPadOS donor, then launchd. Requires the
   measured `userdata` LBAs (`scripts/measure-userdata-gpt.sh`).
5. **Touch and the rest.** Synaptics S3908 driver (see
   `package/touch/README.lemonades`), then Wi-Fi, audio, GPU (Adreno 650),
   mirroring the umi attempt history.

## Flashing safety

The OnePlus ABL on this phone does not support `fastboot boot`; every test
flashes `boot_b` and reboots. Always keep the stock image:

```sh
# restore (from the stage-0 dump in ~/ROm/hw/9r/backups, SHA256SUMS verified)
fastboot flash boot_b backups/boot_b.img
```

`recovery_b` holds OrangeFox R12.0 OPKONA V34, which gives root adb for the
ramoops console (`/sys/fs/pstore`) and the partition measurements. Installing
the iOS payload replaces the `userdata` partition contents.

## Status

- [x] Board, defconfig, ADT generator, package scaffold (derived from umi)
- [x] `uefi-lemonades` platform scaffold (derived from umiPkg attempt-15 baseline)
- [x] kona v2.1 DTB extracted from the stock `boot_b`
- [x] Firmware builds on Linux: `build_uefi.py -d lemonades` produces the
      3 MiB `SILICIUM_UEFI.fd` (DEBUG_CLANGPDB, LLVM 19) and the packed
      `Mu-lemonades-0.img` boot image (header v2, uncompressed shim+FV kernel,
      DTB in the v2 section); `unixnu bootimg` produces the gzip variant
- [ ] Stage 1-2 on hardware: UEFI menu with inherited framebuffer
- [ ] Stage 3-7: kernel, storage, userland, touch
