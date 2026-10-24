#!/usr/bin/env python3
"""Qualify real timed screen diagnostics in a stopped QEMU RAMFB boot."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run", required=True, type=Path)
    p.add_argument("--kernel", required=True, type=Path)
    a = p.parse_args()
    run, kernel = a.run.resolve(), a.kernel.resolve()
    report = json.loads((run / "gdb-stop.json").read_text())
    provenance = json.loads((run / "provenance.json").read_text())
    source = json.loads(kernel.with_suffix(".source-build.json").read_text())
    symbols = {}
    for line in subprocess.check_output(["xcrun", "nm", "-n", kernel], text=True).splitlines():
        fields = line.split()
        if len(fields) == 3:
            symbols[fields[2]] = int(fields[0], 16)
    def read(name, count):
        key = f"{symbols[name]:#x}:{count*8:x}"
        data = bytes.fromhex(report["memory"][key])
        assert len(data) == count*8, name
        return list(struct.unpack("<" + "Q"*count, data))
    assert report["kernel_sha256"] == provenance["kernel_sha256"] == sha(kernel)
    assert report["qemu_accelerator"] == "tcg" and not provenance["vmm_property_declared"]
    assert not report["bounded_timeout_interrupted"]
    assert int(report["pc"], 16) == symbols["_lemonades_boot_progress_checkpoint_eight"]
    assert source["screen_diagnostics"] and source["gic_diagnostics"] and source["pmgr"]
    build = source["screen_build"]
    assert build["actual_arm64_instructions_checked"] and not build["phone_trace"]
    samples = read("_lemonades_boot_progress_samples", 32)
    first, last = samples[:16], samples[16:]
    for row, phase, count in ((first, 5, 3), (last, 6, 8)):
        assert row[:2] == [1, phase] and row[3] == count
        assert row[4] == 0 and row[5] >= 0xffff000000000000
        assert 720 <= row[6] <= 4096 and 560 <= row[7] <= 4096
        assert row[8] >= row[6]*4 and row[8] <= 65536
        assert row[9] > 0 and row[10] > 0 and row[11] > 0
        providers = int(bool(source.get("native_ufs")))
        if source.get("owner_root", "off") != "off":
            providers |= 2 | 4
        assert row[12:15] == [2, 1, providers], \
            "pulse must run; provider mask must match the actually linked components"
    freq = read("_boot_progress_frequency", 1)[0]
    elapsed = (last[15]-first[15])/freq
    assert freq > 0 and elapsed >= 4 and last[2] > first[2]
    assert last[9] > first[9] and last[10] > first[10] and last[11] > first[11]
    rendered = read("_boot_progress_observation", 24)
    assert rendered[0:2] == [2, 1] and rendered[5] >= 3
    assert rendered[20:23] == last[6:9] and rendered[23] == last[5]
    assert int(report["system_registers"]["TCR_EL1"], 16) & (3 << 30) == 2 << 30
    screen = report["qemu_screen_capture"]
    assert screen["sha256"] == sha(run / screen["file"])
    assert screen["width"] == last[6] and screen["height"] == last[7]
    anchor = read("_lemonades_boot_progress_anchor", 3)
    assert 0 < anchor[0] < 0x1000000000000 and anchor[1] >= 0xffff000000000000
    assert anchor[2] == last[7]*last[8]
    archive = run.with_name(run.name + "-qualification-sources")
    archive.mkdir()
    tree = ROOT / "out/lemonades-xnu/lemonades/tree"
    shutil.copytree(ROOT / "devices/lemonades/package/boot-progress", archive / "package")
    shutil.copytree(tree / "build/boot-progress", archive / "build")
    for name, path in {
        "build_lemonades_xnu.py": ROOT / "tools/build_lemonades_xnu.py",
        "build-boot-progress.py": ROOT / "devices/lemonades/scripts/build-boot-progress.py",
        "assembled-build-xnu.sh": tree / "scripts/build-xnu-4k-baseline.sh",
        "check_lemonades_screen_qemu.py": Path(__file__),
    }.items():
        shutil.copyfile(path, archive / name)
    for name, expected in build["sources"].items():
        assert sha(archive / "package" / name) == expected, "source changed after compilation"
    for name, expected in build["objects"].items():
        assert sha(archive / "build" / name) == expected, "object changed"
    index = {str(f.relative_to(archive)): sha(f) for f in sorted(archive.rglob("*")) if f.is_file()}
    (archive / "sha256.json").write_text(json.dumps(index, indent=2) + "\n")
    result = {
        "status": "passed_real_timed_framebuffer_diagnostics",
        "kernel": str(kernel), "kernel_sha256": sha(kernel),
        "first_sample": first, "last_sample": last, "counter_frequency": freq,
        "last_rendered_observation": rendered,
        "retained_anchor": anchor,
        "elapsed_seconds_between_passes_3_and_8": elapsed,
        "source_archive": str(archive.relative_to(ROOT)),
        "source_archive_index_sha256": sha(archive / "sha256.json"),
        "evidence_files": {str(f.relative_to(ROOT)): sha(f) for f in sorted(run.iterdir()) if f.is_file()},
        "actual_qemu_scanout_captured": True, "phone_panel_verified": False,
        "root_mounted": False, "userspace_qualified": False,
    }
    (ROOT / "out/lemonades/screen-qemu-baseline.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
