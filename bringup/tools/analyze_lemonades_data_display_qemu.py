#!/usr/bin/env python3
"""Report actual Data and Legacy display observations from an unmodified guest."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    run = args.run.resolve()
    output = run / "data-display-analysis.json"
    assert not output.exists(), "refusing to overwrite evidence"
    data = json.loads((run / "gdb-stop.json").read_text())
    provenance = json.loads((run / "provenance.json").read_text())
    kernel = Path(provenance["source_kernel"])
    digest = hashlib.file_digest(kernel.open("rb"), "sha256").hexdigest()
    assert digest == provenance["kernel_sha256"] == data["kernel_sha256"]
    assert not any(provenance[k] for k in ("physical_phone_access", "guest_memory_patched", "vmm_property_declared"))
    assert provenance["root_input"]["read_only"] and provenance["systemos_input"]["read_only"]
    source = json.loads(kernel.with_suffix(".source-build.json").read_text())
    seed = source["data_ramdisk"]
    assert source["profile"] == "qemu" and source["legacy_display"]
    assert all(seed[k] == v for k, v in provenance["data_input"].items())
    symbols = {}
    for line in subprocess.check_output(["xcrun", "nm", "-n", kernel], text=True).splitlines():
        row = line.split()
        if len(row) == 3:
            symbols[row[2]] = int(row[0], 16)

    def read(name, size=4):
        return bytes.fromhex(data["memory"][f"{symbols['_' + name]:#x}:{size:x}"])

    def value(name, size=4):
        return int.from_bytes(read(name, size), "little")

    metrics = {}
    for name in symbols:
        short = name.removeprefix("_")
        for size in (4, 8):
            if f"{symbols[name]:#x}:{size:x}" in data["memory"]:
                metrics[short] = value(short, size)
    actual_seed = read("native_owner_data_seed_sha256", 32).hex()
    assert actual_seed == read("native_ram_block_seed_sha256", 32).hex() == seed["sha256"]
    data_mounted = (metrics["native_owner_data_status"] == 0 and metrics["native_owner_data_stage"] == 4
                    and metrics["native_owner_data_readonly"] == 0 and metrics["native_ram_block_ready"] == 1)
    display_started = (metrics["native_legacy_stage"] == 10 and metrics["native_legacy_start_result"] == 1
                       and metrics["native_legacy_registration_calls"] > 0
                       and metrics["native_legacy_gop_virtual"] != 0 and metrics["native_legacy_guard_slot"] == 0)
    seen = metrics["lemonades_exec_trace_seen"]
    exits = read("exit_records", 2382)
    recent = [exits[12 + i*120:12 + (i+1)*120].split(b"\0", 1)[0].decode(errors="replace") for i in range(4)]
    failed = [exits[492 + i*120:492 + (i+1)*120].split(b"\0", 1)[0].decode(errors="replace") for i in range(3)]
    frames_retired = metrics["native_legacy_retirement_calls"]
    result = {
        "kernel_sha256": digest, "runtime": "qemu_tcg", "metrics": metrics,
        "boot_progress": next((a.split("=", 1)[1] for a in provenance["boot_args"].split()
                               if a.startswith("boot-progress=")), None),
        "process_exit_observer_enabled": any(a in ("boot-progress=1", "boot-progress=2")
                                              for a in provenance["boot_args"].split()),
        "data_seed_sha256": actual_seed, "data_volume_uuid": seed["volume_uuid"],
        "data_mounted_writable": data_mounted,
        "actual_ram_writes_observed": metrics["native_ram_block_writes"] > 0,
        "persistent_ufs_store": False,
        "legacy_service_started_and_framebuffer_mapped": display_started,
        "actual_frame_retirement_observed": frames_retired > 0,
        "launchd_main_observed": metrics["initproc_spawned"] == 1,
        "panic_recorded": bool(seen & (1 << 5)), "critical_exit_recorded": bool(seen & (1 << 8)),
        "execution_observation": list(struct.unpack("<20Q", read("lemonades_exec_trace_observation", 160))),
        "process_exit_counts": list(struct.unpack_from("<3I", exits)),
        "recent_process_exits": recent, "failed_process_exits": failed,
        "bounded_timeout_interrupted": data["bounded_timeout_interrupted"], "stop_pc": data["pc"],
        "ios_ui_observed": False, "phone_runtime_equivalence_proved": False,
        "screen": str(run / "screen.png"),
        "status": "data_and_display_initialization_observed" if data_mounted and display_started else "incomplete",
    }
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
