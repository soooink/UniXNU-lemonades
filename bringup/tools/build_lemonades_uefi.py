#!/usr/bin/env python3
"""Build/pack the lemonades UEFI candidate on the host. Never invokes adb/fastboot."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

from analyze_lemonades import boot_v2, dtbo_entries, fdt_nodes, reg_ranges
from prepare_lemonades_uefi import prepare
from make_lemonades_payload import make_payload

ROOT = Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verified(directory, name, metadata):
    data = (directory / name).read_bytes()
    if sha(data) != metadata["sha256"] or len(data) != metadata["bytes"]:
        raise ValueError(f"saved evidence hash/size mismatch: {name}")
    return data


def device_tree(evidence):
    report = json.loads((evidence / "report.json").read_text())
    identity = report["identity"]
    if identity["ro.product.device"] != "lemonades" or identity["ro.soc.model"] != "SM8250":
        raise ValueError("wrong device evidence")
    commandline = (evidence / "cmdline.txt").read_text()
    for field, expected in (("dtb_idx", "0"), ("dtbo_idx", "11")):
        found = re.search(rf"(?:^|\s)androidboot\.{field}=([^\s]+)", commandline)
        if not found or found[1] != expected:
            raise ValueError(f"unexpected observed {field}")
    boot = verified(evidence, "boot.img", report["artifacts"]["boot.img"])
    dtbo = verified(evidence, "dtbo.img", report["artifacts"]["dtbo.img"])
    live = verified(evidence, "running.dtb", report["artifacts"]["running.dtb"])
    segment = boot_v2(boot)["segments"]["dtb"]
    payload = boot[segment["file_offset"]:segment["file_offset"] + segment["bytes"]]
    size = struct.unpack_from(">I", payload, 4)[0]
    base = payload[:size]
    fdt_nodes(base)
    entry = dtbo_entries(dtbo)["entries"][11]
    overlay = dtbo[entry["file_offset"]:entry["file_offset"] + entry["bytes"]]
    out = ROOT / "out/lemonades/dtb"
    out.mkdir(parents=True, exist_ok=True)
    (out / "base0.dtb").write_bytes(base)
    (out / "overlay11.dtbo").write_bytes(overlay)
    merged = out / "lemonades-merged.dtb"
    subprocess.run(["fdtoverlay", "-i", str(out / "base0.dtb"), "-o", str(merged),
                    str(out / "overlay11.dtbo")], check=True)
    actual, running = fdt_nodes(merged.read_bytes()), fdt_nodes(live)
    if actual["/"]["qcom,msm-id"] != running["/"]["qcom,msm-id"]:
        raise ValueError("merged SoC ID differs from observed live DT")
    checked = {}
    for path in ("/reserved-memory/cont_splash_region@9c000000",
                 "/reserved-memory/dfps_data_region@9e300000",
                 "/soc/interrupt-controller@17a00000"):
        if reg_ranges(actual, path) != reg_ranges(running, path):
            raise ValueError(f"merged/live address mismatch: {path}")
        checked[path] = reg_ranges(actual, path)
    provenance = {
        "evidence": str(evidence), "boot_sha256": sha(boot), "dtbo_sha256": sha(dtbo),
        "base_index": 0, "overlay_index": 11, "base_sha256": sha(base),
        "overlay_sha256": sha(overlay), "merged_sha256": sha(merged.read_bytes()),
        "checked_against_live": checked,
        "note": "Source DT + selected overlay, not the live DT. ABL runtime fixups remain untested.",
    }
    (out / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    return merged


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firmware", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--pack-only", action="store_true", help="pack an already built FD")
    parser.add_argument("--display-profile", choices=("vendor", "inherited"), default="vendor")
    parser.add_argument("--input-profile", choices=("none", "buttons", "touch"), default="none")
    parser.add_argument("--payload-profile", choices=("none", "ram"), default="none")
    parser.add_argument("--ram-check", choices=("payload", "memory", "payload64", "xnu", "xnu-entry", "xnu-prelink"), default="payload")
    parser.add_argument("--loader-profile", choices=("none", "darwinboot"), default="none")
    parser.add_argument("-j", type=int, default=4)
    args = parser.parse_args()
    if args.ram_check != "payload" and args.payload_profile != "ram":
        raise ValueError("RAM diagnostic requires RAM payload profile")
    if args.ram_check in ("xnu", "xnu-entry", "xnu-prelink") and args.loader_profile != "darwinboot":
        raise ValueError("XNU payload requires DarwinBoot in the firmware")
    evidence = args.evidence.resolve(strict=True)
    if not args.pack_only:
        prepare(args.firmware.resolve(strict=True) / "uefi-binaries",
                args.display_profile, args.input_profile, args.payload_profile, args.loader_profile)
    dtb = device_tree(evidence)
    uefi = ROOT / "sources/uefi-lemonades"
    driver = ROOT / "sources/UniXNU/unixnu"
    edk2 = uefi / "Mu_Basecore"
    fd = uefi / "Build/lemonadesPkg/DEBUG_CLANGPDB/FV/SILICIUM_UEFI.fd"
    prepare_path = ROOT / "out/lemonades/prepare.json"
    prepared = json.loads(prepare_path.read_text())
    if prepared.get("display_profile") != args.display_profile:
        raise ValueError("prepared display profile differs from requested profile; rebuild firmware")
    if prepared.get("input_profile", "none") != args.input_profile:
        raise ValueError("prepared input profile differs from requested profile; rebuild firmware")
    if prepared.get("payload_profile", "none") != args.payload_profile:
        raise ValueError("prepared payload profile differs from requested profile; rebuild firmware")
    if prepared.get("loader_profile", "none") != args.loader_profile:
        raise ValueError("prepared loader profile differs from requested profile; rebuild firmware")
    for relative, digest in prepared.get("loader_sha256", {}).items():
        if sha((ROOT / "out/lemonades-menu-package" / relative).read_bytes()) != digest:
            raise ValueError("staged DarwinBoot source changed; rebuild firmware")
    build_record = ROOT / "out/lemonades/firmware-build.json"
    if args.pack_only:
        previous = json.loads(build_record.read_text())
        if (previous["display_profile"] != args.display_profile
                or previous.get("input_profile", "none") != args.input_profile
                or previous.get("payload_profile", "none") != args.payload_profile
                or previous.get("loader_profile", "none") != args.loader_profile
                or previous["prepare_sha256"] != sha(prepare_path.read_bytes())
                or previous["fd_sha256"] != sha(fd.read_bytes())):
            raise ValueError("built FD/profile/provenance mismatch; rebuild firmware")
    env = dict(os.environ)
    env["PATH"] = os.pathsep.join([str(ROOT / "out/venv-lemonades/bin"),
                                  "/opt/homebrew/opt/llvm/bin", "/opt/homebrew/opt/lld/bin", env["PATH"]])
    common = ["-D", str(ROOT / "devices/lemonades"), "--out", str(ROOT / "out/unixnu"),
              "--uefi", str(uefi), "--target", "DEBUG"]
    if not args.pack_only:
        subprocess.run([sys.executable, str(driver), "build", "firmware", *common,
                        "--edk2", str(edk2), "--local-module", f"refer:edk2={edk2}",
                        "--local-package", str(ROOT / "out/lemonades-menu-package"), "-j", str(args.j)],
                       cwd=ROOT, env=env, check=True)
        build_record.write_text(json.dumps({
            "display_profile": args.display_profile,
            "input_profile": args.input_profile,
            "payload_profile": args.payload_profile,
            "loader_profile": args.loader_profile,
            "prepare_sha256": sha(prepare_path.read_bytes()),
            "fd_sha256": sha(fd.read_bytes()),
        }, indent=2) + "\n")
    ramdisk = make_payload(diagnostic=args.ram_check) if args.payload_profile == "ram" else None
    subprocess.run([sys.executable, str(driver), "bootimg", *common, "--dtb", str(dtb),
                    "--ramdisk", str(ramdisk) if ramdisk else "none",
                    "-o", str(ROOT / "out/lemonades/boot/lemonades-uefi-menu.img")],
                   cwd=ROOT, env=env, check=True)
    if ramdisk:
        packed = (ROOT / "out/lemonades/boot/lemonades-uefi-menu.img").read_bytes()
        kernel_size, _, ramdisk_size = struct.unpack_from("<3I", packed, 8)
        page, version = struct.unpack_from("<2I", packed, 36)
        if packed[:8] != b"ANDROID!" or page != 4096 or version != 1:
            raise ValueError("unexpected lemonades payload boot header")
        offset = page + (kernel_size + page - 1) // page * page
        actual = packed[offset:offset + ramdisk_size]
        if actual != ramdisk.read_bytes():
            raise ValueError("packed ramdisk differs from verified FAT volume")
    subprocess.run([sys.executable, str(ROOT / "tools/verify_lemonades_fd.py"),
                    "--expected-fd-sha256", sha(fd.read_bytes())], cwd=ROOT, check=True)
    print("Host candidate built and round-trip verified; hardware boot and display remain unverified.")


if __name__ == "__main__":
    main()
