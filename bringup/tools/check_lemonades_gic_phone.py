#!/usr/bin/env python3
"""Check coherent real IRQ samples from one SHA-bound temporary phone boot."""
import argparse
import hashlib
import json
from pathlib import Path

from decode_lemonades_xnu_trace import decode

ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument("attempt", type=int)
a = p.parse_args()
r = decode(a.attempt)
runtime = ROOT / f"out/lemonades/attempt-{a.attempt:02d}-runtime"
archive = ROOT / f"out/lemonades/xnu-entry/attempt-{a.attempt:02d}"
boot = ROOT / f"out/lemonades/boot/attempt-{a.attempt:02d}"
session_file = ROOT / f"out/lemonades/attempt-{a.attempt:02d}-boot-session.json"
session = json.loads(session_file.read_text())
digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def require(value, why):
    if not value:
        raise SystemExit(why)


require(session["partition_flash"] is False
        and session["commands"][-1]["returncode"] == 0
        and "Booting" in session["commands"][-1]["output"]
        and "OKAY" in session["commands"][-1]["output"], "Temporary boot not confirmed")
require(digest(boot / "lemonades-uefi-menu.img") == session["image_sha256"], "Boot image changed")
require("uid=2000(shell)" in (runtime / "adbd-shell-id.txt").read_text(),
        "ADB was not restored to shell")
for name, expected in json.loads((archive / "sha256.json").read_text()).items():
    require(digest(archive / name) == expected, "Archived source or kernel changed: " + name)
events = r["armcpu"]["events"]
require(events and all(s["version"] == 1 for s in events), "Missing coherent v1 observations")
require(all(b["cntvct"] > x["cntvct"] for x, b in zip(events, events[1:])),
        "Snapshot counter order is not coherent")
samples = []
for count in (1, 2, 8):
    group = [s for s in events if s["phase"] in (12, 13, 14) and s["timer_entered"] == count]
    require([s["phase"] for s in group] == [12, 13, 14],
            "Missing coherent entry/return/EOI sequence")
    for s in group:
        require(s["registered"] == s["gic_ready"] == s["cpu_count"] == 1, "CPU0/GIC not ready")
        require(s["detail"] == s["irq_id"] == 27 and s["daif"] & 0x80, "Not a real PPI 27 IRQ context")
        require(s["cntfrq"] == 19200000, "Unexpected lemonades counter frequency")
        require(s["isenabler0"] & (1 << 27) and s["gicd_ctlr"] & 0x12 == 0x12
                and s["icc_igrpen1"] & 1 and s["icc_sre"] & 1
                and 0x80 < s["icc_pmr"] <= 0xff, "GIC enable readback mismatch")
        require(s["cntv_ctl"] & 3 == 1, "Timer disabled or masked")
        require(s["quiesce_calls"] == s["halt_calls"] == 0, "CPU quiesced or halted before sample")
        require(s["timer_returned"] == count - (s["phase"] == 12)
                and s["timer_completed"] == count - (s["phase"] != 14),
                "Counter does not match actual handler/EOI boundary")
        if s["phase"] == 12:
            require(s["cntv_ctl"] & 4 and s["cntvct"] >= s["cntv_cval"], "IRQ did not have an expired timer")
        else:
            require(not s["cntv_ctl"] & 4 and s["cntv_cval"] > s["cntvct"],
                    "Real handler did not rearm timer into the future")
    samples.extend(group)
last = samples[-1]
require(0 < last["first_irq_counter"] < last["last_irq_counter"] <= last["cntvct"],
        "IRQ counter did not advance")
panic = [m for m in r["markers"] if m["stage"] in ("a0", "a1", "a2", "b0", "b1", "b2", "b3")]
root_entry = any(m["stage"] == "d0" and int(m["value"], 16) == 1 for m in r["markers"])
result = dict(
    status="passed_scoped_hardware_gic_timer_checks", attempt=a.attempt,
    kernel_sha256=r["kernel_sha256"], runtime_log_sha256=r["runtime_log_sha256"],
    boot_image_sha256=session["image_sha256"], boot_session_sha256=digest(session_file),
    actual_timer_entered=last["timer_entered"], actual_rtclock_returns=last["timer_returned"],
    actual_eoi_completed=last["timer_completed"], frequency_hz=last["cntfrq"],
    observed_irq_span_seconds=(last["last_irq_counter"] - last["first_irq_counter"]) / last["cntfrq"],
    coherent_snapshot_count=len(events), incomplete_groups=r["armcpu"]["incomplete_groups"],
    discarded_records=r["armcpu"]["discarded_records"], sampled_irq_sequences=samples,
    gic_group_readback=last["igroupr0"],
    group_readback_note="Phone IGROUPR0 readback differs from QEMU; qualification uses actual ICC_IAR1 PPI 27 dispatch and completion, not an inferred security-state configuration.",
    root_lookup_entry_observed=root_entry, panic_or_assert_markers=panic,
    hardware_execution=True, cpu_count=1, ipi_or_smp_qualified=False,
    partition_flash=False, adb_restored_to_shell=True, root_mounted=False, userspace_booted=False,
    limits="Bounded sampled IRQ proof. Incomplete records excluded. Logging intentionally stops after IRQ 8; final marker is not a crash indicator.",
)
(runtime / "gic-checked.json").write_text(json.dumps(result, indent=2) + "\n")
print(f"PASS phone attempt {a.attempt}: CPU0, 8 real timer IRQ/rtclock/EOI completions, 19.2 MHz")
