# Mi 10 touch: native driver comparison and verified board-power fix

The device owner confirmed working physical touch under XNU after attempt 80.
That build enables the native always-on PM8150B GPIO5 board rail before FTS
startup. The preceding attempt recorded that pin output-low and no touch points.
Attempt 80's runtime coordinate/HID counters have not yet been collected; the
confirmation is a hardware interaction report, not inferred from initialization.

The initial comparison below describes attempt 76, when Hello worked but touch
did not. Later sections record the subsequent changes and results. Historical
zero-event measurements and hypotheses do not describe the current touch status.

## Source and runtime identity

Reference: [LineageOS SM8250 kernel at 71b13e62f057a649b77fe4062feb73ee72ad609c](https://github.com/LineageOS/android_kernel_xiaomi_sm8250/tree/71b13e62f057a649b77fe4062feb73ee72ad609c).
This commit matches the connected Recovery's release suffix:
`4.19.325-cip131-st15-perf-g71b13e62f057`. It is the kernel that currently operates
the handset's touch controller, rather than an arbitrary newer branch.

The sparse checkout is `sources/android-kernel-lemonades-reference` from the workspace
root. It includes the complete `fts_521` directory, board device trees, GENI I2C,
GPI DMA, regulator, pinctrl, clock, and panel implementation dependencies.
The captured running kernel configuration and SHA-256 source manifest are in
`out/lemonades/native-source-audit-20261023/`.

Running configuration selects `CONFIG_TOUCHSCREEN_ST_FTS_V521`,
`CONFIG_TOUCHSCREEN_FOD`, `CONFIG_TOUCHSCREEN_XIAOMI_TOUCHFEATURE`,
`CONFIG_I2C_QCOM_GENI`, and `CONFIG_QCOM_GPI_DMA`. The SPI alternative and secure
touch are disabled. `fts.h` additionally defines `PRE_SAVED_METHOD` and
`FW_UPDATE_ON_PROBE`. `CONFIG_I2C_BY_DMA` is not set; this FTS buffer-wrapper
option is separate from the enabled controller-level GPI DMA transport.

## Actual successful startup path

For the connected handset, the native path is:

1. `fts_probe` → `fts_get_reg` → `fts_enable_reg`: enable VDD, wait 15 ms,
   enable AVDD; select active pinctrl and request RESET/IRQ GPIOs.
2. `fts_init` → GPIO reset → fresh READY → `readSysInfo(0)`.
3. Read lockdown identity; select the matching firmware file.
4. `fts_fw_update` → `fts_crc_check`: read CRC register, perform a second GPIO
   reset, and inspect errors collected while waiting for READY.
5. Compare firmware versions. The captured Recovery log says the installed
   version is equal/newer, so no update is performed.
6. Perform a third GPIO reset, inspect CX/panel CRC errors, and compare AFE
   versions. For this device the AFE versions agree and the normal path uses
   `NO_INIT`.
7. Install the low-level IRQ handler; `fts_mode_handler(info, 0)` sends
   `A0 00 01`, then `A2 03 00 00 00 03`.
8. The FOD branch of `fts_init_sensing` sends `A0 00 00`, waits 50 ms, then
   `A0 00 01`. Enable the host IRQ.
9. Read touch-mode values (`C1 05`); register normal runtime callbacks.

The attempt-76 Recovery log confirms three reset calls at approximately
1.9523, 1.9965 and 2.0212 seconds, sensing at 2.0458 seconds, and IRQ enabling
at 2.0965 seconds. The startup timeline is saved separately beside the manifest.

## Comparison with the current XNU implementation

Line numbers below refer to the pinned native checkout. Local implementation
paths are relative to this device repository.

| Area | Native behavior and source | Current XNU behavior | Assessment |
|---|---|---|---|
| Device selection | `lemonades-sm8250.dtsi:222`: SE13, address 0x49, RESET38, IRQ39, VDD=L1C, AVDD=GPIO69 | Same controller, address and pins | No mismatch found in these identities. |
| Supply startup | `fts.c:6803`: VDD → 15 ms → AVDD. `fts_chip_powercycle:5234` is an error/recovery path | `LemonadesFtsBus.inc:145` enables VDD and additionally runs a full power cycle because `lemonades-fts-full-cycle=1` | Attempt 76 is not the native ordinary startup path. Remove this experiment from the comparison baseline. Digital rail state is verified; physical analog voltage is not measured. |
| Regulator vote | `kona-regulators.dtsi:578`, `rpmh-regulator.c:1585`: initialize L1C voltage to 1800 mV, request enable through regulator framework | `LemonadesRpmh.inc`, `FindTouchResource` votes enable only and requires existing physical voltage readback to be 1800 mV | A behavioral difference, but not a demonstrated voltage failure. DT provides no L1C supported/init modes; arbitrary mode changes are not justified. |
| Pin configuration | `kona-pinctrl.dtsi:541`: RESET38/IRQ39 pull-up, 8 mA; AVDD is regulator-fixed GPIO69 | `LemonadesFtsPinConfig.h`, `ConfigureIrq` match these fields | No known configuration mismatch after attempt 73. |
| Resets | `ftsCore.c:85`: GPIO reset when reset GPIO is defined; low for 10 ms. Successful normal flow has three reset sites | `LemonadesFtsTouch.cpp:485`: two READY events; second reset is software because `lemonades-fts-soft-reset=1` | Confirmed difference. Software reset is a native fallback for boards without RESET, not the path selected on lemonades. Previous GPIO/software attempts both failed; this difference alone is not a proven cause. |
| READY handling | `ftsCore.c:188`: 2 ms polling, 100 ms nominal window, error collection; three attempts on failure | 2 ms worker, 100 ms deadline, immediate stop for controller error | Basic window matches; retry/error handling is narrower. Attempt 76 received both READYs, so timeout recovery did not cause its failure. |
| Version/calibration decision | `fts.c:4906`: CRC/event checks, matching FW skip, matching AFE → NO_INIT | `LemonadesFtsSysInfo.h` reads identity/AFE and CRC; worker does not reproduce the complete native decision flow | Complete the decision/diagnostic checks, but no evidence calls for a firmware or persistent calibration write. |
| Scan commands | `fts.c:5302,5519`, `ftsCore.c:333` | `LemonadesFtsSensing.h`: identical four commands and 50 ms interval | Matched. `A2 03 ... 03` enables FOD gesture/long-press behavior; it is not a generic coordinate-report enable command. Native `setScanMode` writes directly, without `checkEcho`. |
| I2C/DMA framing | `ftsIO.c:201` combined write/read, no intervening STOP; `i2c-qcom-geni.c:432` GPI command sequence; 400 kHz map at line 166 | `LemonadesFtsGpiCore.h` / `LemonadesFtsGpi.inc`: write with stretch, then read, matching pack/timing and completion handling | Command framing/timing constants match the relevant native path. Many valid config and identity reads support transport operation, without proving every DMA condition. |
| FIFO service | `fts.c:4739`: level-low IRQ; read 8 bytes then bulk-read remaining events, up to 32 | Poll IRQ every ~2 ms; read up to eight separate 8-byte events per pass; 100 ms idle fallback | Confirmed implementation difference. Can affect throughput/latency, but does not explain a controller with no observed coordinate records and abnormal raw sampling. |
| Touch decoding | `fts.c:3690`: dispatch high nibble, same coordinate packing; accepts finger/glove/palm and handles hover/stylus; clamps to board max | `LemonadesFtsCore.h`: high nibble and packing match; accepts finger/glove, rejects out-of-range coordinates | Missing type/edge handling is real, but no coordinate event reached this decoder on attempt 76. Not the immediate blocker. |
| Panel-related GPIO | `dsi-panel-j2-mp-42-02-0b-dsc-cmd.dtsi:349` names GPIO50; `dsi_panel_mi.c:581` drives it high; line 2562 keeps it high for 60/90 Hz | No explicit GPIO50 ownership or observation in the current touch implementation | Concrete unverified board-state difference. Boot firmware may already set it. Capture actual state before treating it as a defect; its causal link to touch is unproven. |
| Display resume | `fts.c:6540`: resume resets IC and reapplies scan state, charger mode and delayed feature update | Startup once; no corresponding display suspend/resume lifecycle | Needed for later lifecycle parity. Current Hello failure occurs without evidence of a suspend/resume transition. |
| Charger/features | `fts.c:3030` charger commands on state change; `C1 05` read at end of probe | No charger notification path or `C1 05` diagnostic read | Add observable mode state before asslemonadesng it inhibits sensing. Native attempt-76 log sets charger mode 0; no evidence of mandatory missing mode programming. |

## What attempt 76 establishes

Across the 5-second and 30-second captures, all 52 recovered CRC32 block values
for A8 configuration offsets `0..0xcff` match the working Recovery reference.
Some trace pages are incomplete; the comparison uses separately validated
fields and combines the two captures. It is neither an atomic snapshot nor a
proof of byte-for-byte identity. See `out/lemonades/attempt-76-runtime/config-comparison.json`.

The latest complete touch snapshot, at 111 seconds, has 48,688 polls, 11 raw
nonzero events, zero coordinate events, zero HID reports, and no recorded
transport/controller error. The complete 5-second sensor sample remains flat:
mutual nodes `0xcb6a`, self nodes `0xadea`. This places the observed failure
before normal coordinate delivery; modifying the HID descriptor cannot explain
the absent controller output.

## Next implementation order

1. Establish the ordinary native startup baseline: GPIO resets at the native
   phases, complete read-only identity/CRC/AFE decisions, normal VDD→AVDD startup;
   disable the extra full-cycle/software-reset experiments for this comparison.
   Keep a distinct trace phase for each reset and each decision.
2. Capture the actual panel GPIO50 state and supply state at startup and after
   scanning begins. The kernel source justifies the expected GPIO50 output-high
   state, but present XNU state and its relevance to sensing remain unknown.
3. Read the native `C1 05` mode values and compare with Recovery. Preserve actual
   FIFO and raw-data logging. Avoid changing multiple unrelated modes together.
4. After real coordinate events appear, complete FIFO batching, touch-type
   handling and display suspend/resume parity, then validate HID/UI response.

This audit used source and existing/collected real-device evidence. It did not
run QEMU, rebuild/flash boot, or change controller firmware/calibration/Data.

## Attempt77 runtime and attempt78 follow-up

Attempt77 reaches Hello but has no touch response. Its complete startup record
proves three fresh READY events before sensing, identity/CRC/AFE check0 and no
extra supply cycle. GPIO50 is GPIO output-high at startup,60s and120s, including
input readback. At151s there are66407 polls,13 status events,0 coordinate events
and0 HID reports. MS/SS raw samples remain uniform at-13462/-21014. GPIO50 and
the missing third reset therefore do not explain this test's continued failure.
See the local attempt77 runtime result and hash-qualified decoded trace.

The connected Recovery's C1 05 modes are `00 00 64 0f 02 0e 01`, C1 08 grip
modes are `00 ff 00 00 00 00 00`. A controlled Recovery replay produced normal,
nonuniform sensor data before and after A2 02 00. Native `fts.c:3030` sends that
volatile touch charger/noise-mode command after startup (current boot at2.784s).
It does not operate the phone's charging hardware. The command's absence in XNU
is a confirmed behavior difference, not a demonstrated cause of flat sampling.

Attempt78 adds these seven-byte mode reads and one native default0 command after
500ms of sensing, with before/after mode and existing raw/FIFO/HID diagnostics.
It retains the attempt77 reset and power baseline. It does not implement charger
state detection, panel commands, firmware updates or calibration writes. A real
hardware outcome is required before any claim that touch is fixed.

## Attempt78 result and factory identity follow-up

Attempt78 still reaches Hello without touch:141s,62008 polls,0 points/HID.
Complete C1 05/C1 08 records match Recovery before/after the default charger0
command. FIFO echoes A2 02 00; raw MS/SS remainsCB6A/ADEA. That command did not
resolve sensing. The runtime result is archived locally.

Native `ftsCore.c:1267` loads read-only factory record0x70 between first reset/
SysInfo and the subsequent resets. XNU previously skipped this. Attempt79 adds
A6 header read → A4 06 70 →10ms → matching FIFO echo →28-byte A6 read, checking
fresh sequence and factory identity5342320174023201. It permits no NVM write
commands. The same helper succeeds in Recovery and subsequent sensing remains
normal; this alone does not prove it will fix XNU's sampling.

The native board's always-on vdd_boost_vreg uses PM8150B GPIO5. Recovery sysfs
reports enabled. Its electrical connection to FTS is unknown. Attempt79 only
reads SID2 GPIO5 type/mode/enable/output-source registers before touch startup
and5s after startup; it does not modify GPIO5, PMIC configuration or boost state.
A GPIO output value is not an analog voltage measurement.

## Attempt80: native always-on board boost

Attempt79 completed factory identity acquisition successfully, but at261s still
had97004 polls,12 status events and0 points/HID. Both complete board-rail
records show SID2 PM8150B GPIO5 enabled digital output-low, source=00. Native
`xiaomi-sm8250-common.dtsi:112` requires active-high, always-on vdd_boost_vreg
and4000us startup delay; Recovery regulator.93 reports enabled/one user.

Attempt80 guards the exact inherited PMIC/GPIO profile and EE0 APID ownership,
then writes only SID2/C444=80 and waits4000us before touch supply/reset. It
preserves source selection, pull, drive, voltage and arbiter ownership, verifies
the profile by reading it back, and retains the always-on rail on touch failure.
A pre-enabled rail is not rewritten. Unknown profiles and IO failures stop
explicitly, with no repeated write. New v27 records the attempt and readback;
v26 still captures the rail at5s. The redundant30s C1 capture is removed to
keep the trace budget unchanged. No controller NVM write or QEMU run.

This fixes a demonstrated native-board configuration omission. Neither a GPIO
latch readback nor the DT node proves analog voltage or the electrical path
to FTS; real coordinate/HID events and UI interaction remain required.

### Hardware outcome

Attempt 80 was built without QEMU, flashed and verified by full boot-partition
readback. The device owner then confirmed that touch works. The checked-in touch
package matches the installed build's archived source. The 42-command host
qualification suite passed with ASan/UBSan, including PMIC identity/configuration,
EE ownership, write/readback failure, timeout and trace-integrity checks.

This is the first confirmed usable physical input on the tested handset. No
claim is made here for measured analog voltage, multi-touch, suspend/resume,
UEFI menu touch or completing Setup Assistant. The new runtime counters remain
pending collection; see `validation.json` for the image hashes and evidence type.
