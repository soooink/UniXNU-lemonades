#!/usr/bin/env python3
"""Summarize read-only SystemOS experiments without treating a timeout as boot success."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    run = args.run.resolve()
    output = args.output.resolve() if args.output else run / "analysis.json"
    if output.exists():
        parser.error("refusing to overwrite an experiment analysis")
    data = json.loads((run / "gdb-stop.json").read_text())
    provenance = json.loads((run / "provenance.json").read_text())
    kernel = Path(provenance["source_kernel"])
    digest = hashlib.file_digest(kernel.open("rb"), "sha256").hexdigest()
    assert digest == provenance["kernel_sha256"] == data["kernel_sha256"]
    assert not provenance["physical_phone_access"] and not provenance["guest_memory_patched"]
    assert not provenance["vmm_property_declared"] and data["qemu_accelerator"] == "tcg"
    windows = [provenance["root_input"], provenance["systemos_input"]]
    assert all(w["read_only"] for w in windows)
    assert windows[0]["sha256"] == "e5634d04a8ac35f024845f583394e0a35deb26a04cb0c00286a8674e25a9a4f2"
    assert windows[1]["sha256"] == "b4908cde41d23e6bc05e6af51a2c9eeb00cf0f863a6a18b1600c96a3fd70414f"
    assert windows[0]["offset"] + windows[0]["bytes"] <= windows[1]["offset"]
    for field, window in zip(("virtio_block_input", "virtio_extra_block_input"), windows):
        observed = data[field]
        assert observed["read_only"] and observed["device_attached"]
        assert observed["offset"] == window["offset"] and observed["bytes"] == window["bytes"]
    symbols = {}
    for line in subprocess.check_output(["xcrun", "nm", "-n", kernel], text=True).splitlines():
        row = line.split()
        if len(row) == 3:
            symbols[row[2]] = int(row[0], 16)

    def read(name, size):
        value = data["memory"].get(f"{symbols[name]:#x}:{size:x}")
        return bytes.fromhex(value) if value is not None else None

    def scalar(name, size=4):
        raw = read(name, size)
        return int.from_bytes(raw, "little") if raw is not None else None

    root = struct.unpack("<18Q", read("_lemonades_owner_root_observation", 144))
    assert root[:6] == (2, 1, 80, 1, 1, 1) and root[6] == root[7] == root[8]
    status = scalar("_native_owner_cache_status")
    authorized = scalar("_native_owner_cache_authorized")
    union = scalar("_native_owner_cache_native_union")
    assert (status, authorized, union) == (0, 1, 1)
    seen = scalar("_lemonades_exec_trace_seen", 8)
    observation = struct.unpack("<20Q", read("_lemonades_exec_trace_observation", 160))
    assert observation[0] == 1
    exits = read("_exit_records", 2382)

    def rows(start, count, size):
        return [exits[start + i * size:start + (i + 1) * size].split(b"\0", 1)[0].decode(errors="replace")
                for i in range(count)]

    main_observed = scalar("_initproc_spawned") == 1
    known_exit_boundary = (digest == "767785a3b4bb31846722ee4e44a2a20dc3d3d35f95a3778a03a43b65564ffd30"
        and data["pc"] in ("0xfffffff00bcc8b98", "0xfffffff00bcc8c50", "0xfffffff00bcc8cbc")
        and not data["bounded_timeout_interrupted"])
    result = {
        "kernel_sha256": digest,
        "runtime": "qemu_tcg",
        "readonly_os_systemos_verified": True,
        "owner_root_accepted": True,
        "systemos_mount_status": status,
        "systemos_authorized": authorized,
        "systemos_native_union": union,
        "dyld_flags": scalar("_native_owner_cache_dyld_flags"),
        "launchd_main_observed": main_observed,
        "bounded_timeout_interrupted": data["bounded_timeout_interrupted"],
        "stop_pc": data["pc"],
        "panic_recorded": bool(seen & (1 << 5)),
        "critical_exit_recorded": bool(seen & (1 << 8)),
        "critical_exit_boundary_reached": known_exit_boundary,
        "last_execution_observation": observation,
        "native4k_signature_cache": {name: scalar("_cs_native4k_" + name, 8)
                                     for name in ("full_blocks", "page_checks", "ready_blobs")},
        "process_exit_counts": dict(zip(("total", "failed", "crashes"), struct.unpack_from("<3I", exits))),
        "recent_process_exits": rows(12, 4, 120),
        "failed_process_exits": rows(492, 3, 120),
        "process_crash_descriptions": rows(852, 3, 400),
        "screen": str(run / "screen.png"),
        "ios_ui_observed": False,
        "phone_runtime_equivalence_proved": False,
    }
    if observation[1] == 8:
        result["critical_exit"] = {"pid": observation[2], "wait_status": observation[3],
            "signal": observation[3] & 127, "exit_status": observation[3] >> 8 & 255,
            "namespace": observation[4], "code": observation[5],
            "description_bytes": observation[7] & 0xffffffff}
    if observation[1] == 9:
        result["critical_process_identity"] = {
            "initproc_spawned": observation[2], "is_initproc": bool(observation[3]),
            "name": struct.pack("<4Q", *observation[4:8]).split(b"\0", 1)[0].decode(errors="replace")}
    # This instruction follows the actual reason-string getter in the archived
    # native build. x0 is its kernel-owned return value, read by the observer.
    if known_exit_boundary and data["pc"] == "0xfffffff00bcc8b98":
        result["critical_exit_description"] = data["argument_memory"].get("x0")
    result["status"] = ("critical_process_exit_observed_after_launchd_main" if main_observed and known_exit_boundary
                        else "launchd_main_and_services_observed_within_bounded_run" if main_observed
                        else "critical_exit_before_launchd_main" if result["critical_exit_recorded"]
                        else "startup_not_yet_resolved")
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
