#!/usr/bin/env python3
"""Exercise sheng's Data and Legacy display configuration on lemonades's QEMU profile."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--stage", choices=("init", "runtime"), default="init")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--boot-progress", type=int, choices=(0, 2), default=2,
                        help="enable the original continuous diagnostic page, or disable its renderer for a control run")
    args = parser.parse_args()
    kernel = args.kernel.resolve()
    build = json.loads(kernel.with_suffix(".source-build.json").read_text())
    assert build["profile"] == "qemu" and not build["early_trace"]
    assert build["legacy_display"] and build["data_ramdisk"] and build["systemos"]
    original = tomllib.loads((ROOT / "sources/UniXNU-sheng/board.toml").read_text())["payload"]["kernel_args"]
    display_args = [a for a in original if a.startswith("offline-legacy-") or a == "offline-mobile-graphics-load=1"]
    boot_args = ["-v", "keepsyms=1", "kt_fixed_zones=120", "lemonades-pmgr=2", f"boot-progress={args.boot_progress}",
                 "native-ufs-root=1", "offline-apfs-load=1", "-apfs_shared_datavolume", *display_args]
    command = [sys.executable, str(ROOT / "tools/run_lemonades_qemu.py"), "--kernel", str(kernel),
               "--out", str(args.out.resolve()), "--root-volume", "--systemos-volume",
               "--data-ramdisk", build["data_ramdisk"]["path"], "--trust-cache",
               str(ROOT / "out/lemonades/trustcache/original-static-system.bundle"),
               "--owned-memory-mib", "320", "--accel", "tcg", "--no-vmm-property",
               "--stop", "_execve" if args.stage == "init" else "_ml_panic_trap_to_debugger",
               "--also-stop", "_native_legacy_backend_guard", "--capture-screen",
               "--timeout", str(args.timeout), "--args", " ".join(boot_args)]
    if args.stage == "init":
        command += ["--also-stop", "_ml_panic_trap_to_debugger"]
    symbols = {
        "native_mobile_graphics_load_status": 4,
        "native_owner_cache_status": 4, "native_owner_cache_authorized": 4,
        "native_owner_data_status": 4, "native_owner_data_stage": 4,
        "native_owner_data_readonly": 4, "native_owner_data_device": 4,
        "native_owner_data_seed_sha256": 32,
        "native_ram_block_ready": 4, "native_ram_block_bytes": 8,
        "native_ram_block_reads": 8, "native_ram_block_writes": 8,
        "native_ram_block_failures": 8, "native_ram_block_resident_bytes": 8,
        "native_ram_block_seed_sha256": 32,
        "native_legacy_stage": 4, "native_legacy_meta_status": 4,
        "native_legacy_object_size": 4, "native_legacy_parent_match": 4,
        "native_legacy_init_result": 4, "native_legacy_start_result": 4,
        "native_legacy_dt_attached": 4, "native_legacy_guard_slot": 4,
        "native_legacy_surface_status": 4, "native_legacy_surface_found": 4,
        "native_legacy_gop_physical": 8, "native_legacy_gop_virtual": 8,
        "native_legacy_gop_bytes": 8, "native_legacy_gop_width": 4,
        "native_legacy_gop_height": 4, "native_legacy_registration_calls": 4,
        "native_legacy_client_calls": 4, "native_legacy_client_pid": 4,
        "native_legacy_client_status": 4, "native_legacy_transfer_calls": 4,
        "native_legacy_transfer_status": 4, "native_legacy_retirement_calls": 4,
        "native_legacy_prepare_calls": 4, "native_legacy_prepare_reason": 4,
        "native_legacy_prepare_attempts": 4, "boot_progress_display_owned": 4,
        "initproc_spawned": 4, "lemonades_exec_trace_observation": 160,
        "lemonades_exec_trace_seen": 8, "exit_records": 2382,
    }
    for name, size in symbols.items():
        command += ["--read-symbol", f"_{name}:{size}"]
    subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
