#!/usr/bin/env python3
"""Build the board's minimal prelink from a verified prelinked-provider input."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sources/UniXNU/kits/NativePrelink"))
from native_prelink import macho


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--profile", choices=("phone", "qemu"), default="qemu")
    p.add_argument("--early-trace", action="store_true",
                   help="require phone-only RAM trace instrumentation in the source input")
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--storage", action="store_true",
                   help="include the official example's APFS and filesystem-compression roots")
    p.add_argument("--owned-memory-size", type=lambda v: int(v, 0),
                   help="explicit destination size; high-memory phone profiles require the board audit")
    a = p.parse_args()
    if a.early_trace and a.profile != "phone":
        p.error("physical RAM-console tracing is phone-only")
    out = a.output.resolve()
    if out.exists():
        p.error("refusing to overwrite a candidate")
    board_path = ROOT / "devices/lemonades/board.toml"
    spec = tomllib.loads(board_path.read_text())["kernel"]["prelink"]
    work = ROOT / "out/lemonades-xnu/lemonades"
    prefix = "qemu-" if a.profile == "qemu" else ""
    status_path = work / (prefix + "prelink-source-build-status.json")
    status = json.loads(status_path.read_text())
    full_storage = bool(status.get("native_ufs"))
    if full_storage and not a.storage:
        p.error("NativeUfsBlock requires the original APFS/storage closure")
    # DarwinBoot holds the ~120 MiB input while allocating the destination.
    # Leave input/UEFI headroom inside the actual 512 MiB conventional region.
    owned = a.owned_memory_size or (320 if full_storage else 256) * 1024**2
    high_memory = None
    if owned != (320 if full_storage else 256) * 1024**2:
        if a.profile != "phone" or owned != 0x130000000:
            p.error("only the audited 4.75 GiB phone profile is supported")
        from lemonades_memory_profile import audit_high_memory
        high_memory = audit_high_memory()
    # The handset's boot partition is 128 MiB including the UEFI/DTB/header.
    fat = (124 if full_storage else 64) * 1024**2
    if (not status.get("success") or bool(status.get("early_trace")) != a.early_trace or
            status.get("crypto_bootstrap") != "prelinked" or status["profile"] != a.profile):
        p.error("requires a matching successful --crypto-bootstrap prelinked source build")
    kernel = Path(status["kernel"])
    donor = ROOT / "out/lemonades-xnu/ipsw/21H461/kernelcache.decompressed"
    digest = lambda f: hashlib.sha256(f.read_bytes()).hexdigest()
    if digest(kernel) != status["sha256"]:
        p.error("source kernel no longer matches its build record")
    if digest(donor) != spec["kernelcache_sha256"]:
        p.error("donor hash differs from board.toml")
    command = [
        sys.executable, str(ROOT / "sources/UniXNU" / spec["tool"]),
        "--kernel", str(kernel), "--prelinked", str(donor),
        f'--slide={spec["slide"]}', "--output", str(out),
        "--early-security-init", spec["early_security_init"],
    ]
    roots = list(spec["roots"])
    if a.storage:
        roots += ["com.apple.filesystems.apfs",
                  "com.apple.AppleFSCompression.AppleFSCompressionTypeZlib"]
    if status.get("legacy_display"):
        roots += ["com.apple.iokit.IOMobileGraphicsFamily", "com.apple.iokit.IOSurface",
                  "com.apple.iokit.IOGPUFamily"]
    if status.get("fts_touch"):
        roots += ["com.apple.iokit.IOHIDFamily", "com.apple.iokit.IOHIDEventDriver"]
    for component in roots:
        command += ["--root", component]
    subprocess.run(command, check=True)
    report = json.loads(out.with_suffix(".json").read_text())
    if report["candidate_sha256"] != digest(out) or report["native_sha256"] != digest(kernel):
        raise ValueError("prelink output provenance mismatch")
    segments = [s for s in macho(out.read_bytes())["segments"]
                if s["size"] and s["name"] != "__PAGEZERO"]
    span = max(s["va"] + s["size"] for s in segments) - min(s["va"] for s in segments)
    policy_copies = status.get("root_policy_build", {}).get("manifest_bytes", 0)
    if span + policy_copies + 32 * 1024**2 > owned:
        raise ValueError("kernel plus read-only policy copies exceed the selected memory budget")
    data_bytes = (status.get("data_ramdisk") or {}).get("encoded_bytes", 0)
    if out.stat().st_size + max(4 * 1024**2, data_bytes + 1024**2) > fat:
        raise ValueError("kernel leaves less than 4 MiB in the selected FAT volume")
    provenance = {
        "command": command, "board_sha256": digest(board_path),
        "source_status_sha256": digest(status_path),
        "source_build": status, "kernel_sha256": digest(out),
        "donor_sha256": digest(donor), "component_count": len(report["components"]),
        "virtual_span_bytes": span, "owned_memory_bytes": owned,
        "fat_volume_bytes": fat, "policy_copy_bytes": policy_copies,
        "expanded_payload_hardware_verified": False,
        "source_code_checks_bypassed": False,
        "runtime_qualified": False, "hardware_tested": False,
        "high_memory_profile": high_memory,
        "storage_prelink": a.storage, "requested_roots": roots,
    }
    out.with_suffix(".board.toml").write_bytes(board_path.read_bytes())
    out.with_suffix(".source-build.json").write_bytes(status_path.read_bytes())
    out.with_suffix(".provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    print(f"Minimal prelink: {len(report['components'])} components; "
          f"{out.stat().st_size} file bytes; {span} mapped bytes")


if __name__ == "__main__":
    main()
