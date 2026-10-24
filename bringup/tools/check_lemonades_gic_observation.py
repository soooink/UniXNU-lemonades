#!/usr/bin/env python3
"""Qualify real QEMU GIC/timer execution against immutable boot inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from lemonades_armcpu_trace import state

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sources/UniXNU/kits/NativePrelink"))
from native_prelink import exports, macho
sys.path.insert(0, str(ROOT / "devices/lemonades/scripts"))
from lemonades_adt import decode

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--kernel", required=True, type=Path)
p.add_argument("--observation", required=True, type=Path)
a = p.parse_args()
data = a.kernel.read_bytes()
names = {name: va for va, labels in exports(data, macho(data)).items() for name in labels}
r = json.loads(a.observation.read_text())
provenance = json.loads(a.observation.with_name("provenance.json").read_text())
digest = lambda b: hashlib.sha256(b).hexdigest()


def require(value, why):
    if not value:
        raise SystemExit(why)


require(r["kernel_sha256"] == provenance["kernel_sha256"] == digest(data),
        "Kernel identity mismatch")
esp = a.observation.parent / "esp"
for name, expected in provenance["esp_sha256"].items():
    require(digest((esp / name).read_bytes()) == expected, "Changed ESP input")
require((esp / "EFI/UniXNU/Payloads/kernel.macho").read_bytes() == data,
        "Different booted kernel")
adt = decode((esp / "EFI/UniXNU/Payloads/kernel.macho.adt").read_bytes())
require("vmm-present" not in adt.at("/defaults").properties
        and not provenance["vmm_property_declared"], "VM shortcut is forbidden")
require(r["qemu_accelerator"] == "tcg" and not r["bounded_timeout_interrupted"],
        "Must reach a real checkpoint under TCG")
require(int(r["pc"], 16) == names["_lemonades_armcpu_timer_checkpoint"],
        "Did not reach the eighth real timer completion")
require(not provenance["guest_memory_patched"], "Observation must not mutate guest state")
request = f"0x{names['_lemonades_armcpu_observation']:x}:100"
s = state(struct.unpack("<32Q", bytes.fromhex(r["memory"][request])))
require(s["version"] == 1 and s["phase"] == 14, "Wrong observer schema or phase")
require(s["registered"] == s["gic_ready"] == s["cpu_count"] == 1, "CPU0/GIC not ready")
require(s["timer_entered"] == s["timer_returned"] == s["timer_completed"] == 8,
        "Real rtclock return and EOI must complete for all eight IRQs")
require(s["irq_id"] == 27 and s["irq_phase"] == 6, "Not the architectural virtual timer IRQ")
require(s["cntfrq"] > 0 and 0 < s["first_irq_counter"] < s["last_irq_counter"] <= s["cntvct"],
        "Architectural counter did not advance")
require(s["igroupr0"] & (1 << 27) and s["isenabler0"] & (1 << 27),
        "PPI 27 is not enabled in Group 1")
require(s["gicd_ctlr"] & 0x12 == 0x12 and 0x80 < s["icc_pmr"] <= 0xff
        and s["icc_igrpen1"] & 1 and s["icc_sre"] & 1, "GIC readback mismatch")
require(s["cntv_ctl"] & 3 == 1, "Virtual timer disabled or masked")
require(s["daif"] & 0x80, "rtclock observation must be in IRQ context")
require(s["quiesce_calls"] == s["halt_calls"] == 0, "CPU was quiesced or halted")
for name, expected in (("_armcpu_timer_interrupts", 8), ("_lemonades_armcpu_timer_completed", 8)):
    value = struct.unpack("<Q", bytes.fromhex(r["memory"][f"0x{names[name]:x}:8"]))[0]
    require(value == expected, "Live counter disagrees with snapshot")
tcr = int(r["system_registers"]["TCR_EL1"], 16)
require(tcr >> 14 & 3 == 0 and tcr >> 30 & 3 == 2, "Not active 4 KiB translation")
result = dict(kernel_sha256=digest(data), actual_gic_timer_execution=True,
              observation_sha256=digest(a.observation.read_bytes()),
              state=s, tcr_el1=r["system_registers"]["TCR_EL1"],
              hardware_tested=False, root_mounted=False, userspace_booted=False)
a.observation.with_name("gic-checked.json").write_text(json.dumps(result, indent=2) + "\n")
print("PASS: 8 actual PPI 27 IRQs, rtclock returns and EOIs; active 4 KiB; CPU0 only")
