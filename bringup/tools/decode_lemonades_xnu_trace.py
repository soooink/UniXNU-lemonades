#!/usr/bin/env python3
"""Resolve RAM trace addresses against the exact kernel archived for one boot."""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import subprocess

from verify_lemonades_xnu import macho
from native_prelink import backed_offset, unserialize_xml
from lemonades_armcpu_trace import FIELDS as ARMCPU_FIELDS, phone_events
from lemonades_screen_trace import FIELDS as SCREEN_FIELDS, phone_events as screen_events
from lemonades_ufs_trace import FIELDS as UFS_FIELDS, phone_events as ufs_events
from lemonades_root_trace import decode_root_trace
from lemonades_lock_trace import decode_lock_trace
from lemonades_exec_trace import decode_exec_trace
from lemonades_runtime_trace import decode_runtime_trace
from lemonades_userspace_trace import decode_userspace
from lemonades_touch_trace import decode_touch
from lemonades_wait_trace import decode_wait_trace

ROOT = Path(__file__).resolve().parents[1]
STRING_STAGES = {"43", "52", "53", "a0", "b0", "b2"}
SYMBOL_STAGES = {"06", "50", "51", "a1", "b3"}
RETURN_ADDRESS_STAGES = {"a1", "b3"}
PMGR_FIELDS = ("stage", "status", "parent_size", "own_size", "provider", "nub",
               "bound_provider", "read_before", "read_after", "own_before",
               "own_after", "nub_before", "nub_after", "attached", "registered", "mode")
RUNTIME_FIELDS = {"d0": "IOFindBSDRoot entry", "d1": "armcpu_registered",
                  "d2": "armcpu_gic_ready", "d3": "armcpu_timer_interrupts"}


def read_literal(data, sections, addr, allow_constant=False):
    for section in sections:
        names = {"__cstring", "__const"} if allow_constant else {"__cstring"}
        if section["name"] not in names or not (section["va"] <= addr < section["va"] + section["size"]):
            continue
        offset = section["fileoff"] + addr - section["va"]
        limit = min(offset + 1024, section["fileoff"] + section["size"], len(data))
        end = data.find(b"\0", offset, limit)
        if end >= 0:
            return data[offset:end].decode("utf-8", errors="replace")
    return None


def embedded_sections(data):
    """Return file-backed sections and ranges of genuine embedded components."""
    parent = macho(data)["segments"]
    sections = [s for segment in parent for s in segment["sections"]]
    ranges = []
    info = next((s for s in parent if s["name"] == "__PRELINK_INFO" and s["filesize"]), None)
    if info is None:
        return sections, ranges
    metadata = unserialize_xml(data[info["fileoff"]:info["fileoff"] + info["filesize"]])
    for entry in metadata["_PrelinkInfoDictionary"]:
        # KPI records describe interfaces supplied by the source kernel. They
        # are not the copied original component Mach-O images.
        if entry.get("OSKernelResource") is True:
            continue
        address = entry.get("_PrelinkExecutableLoadAddr")
        if not address:
            continue
        module = macho(data, backed_offset(parent, address, 32, len(data)))
        for segment in module["segments"]:
            if segment["filesize"] and segment["name"] != "__LINKEDIT":
                ranges.append((segment["va"], segment["va"] + segment["filesize"],
                               entry["CFBundleIdentifier"], segment["name"]))
                for section in segment["sections"]:
                    if section["size"] and section["name"] in ("__cstring", "__const"):
                        sections.append({**section, "fileoff": backed_offset(
                            parent, section["va"], section["size"], len(data))})
    return sections, ranges


def decode(attempt, runtime_directory=None):
    archive = ROOT / f"out/lemonades/xnu-entry/attempt-{attempt:02d}"
    runtime = (Path(runtime_directory).resolve(strict=True) if runtime_directory else
               ROOT / f"out/lemonades/attempt-{attempt:02d}-runtime")
    kernel = archive / "kernel.macho"
    data = kernel.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    index = json.loads((archive / "sha256.json").read_text())
    verification = json.loads((archive / "verification.json").read_text())
    payload = json.loads((ROOT / f"out/lemonades/boot/attempt-{attempt:02d}/payload/payload.json").read_text())
    if digest != index["kernel.macho"] or digest != payload["files"]["EFI/UniXNU/Payloads/kernel.macho"]:
        raise ValueError("Archived kernel does not match the actual boot payload")
    correction = None
    if digest != verification["sha256"] or digest != payload["xnu"]["kernel"]["sha256"]:
        # Preserve the historical archive. A report-only digest shadow must be
        # explained by an independently checked correction, never ignored.
        correction_path = runtime / "kernel-provenance-correction.json"
        correction = json.loads(correction_path.read_text())
        source_status = json.loads((archive / "source-build-status.json").read_text())
        original = json.loads((archive / "prelink/kernel.json").read_text())
        provenance = json.loads((archive / "prelink/kernel.provenance.json").read_text())
        bad = list(source_status["screen_build"]["generated_sources"].values())[-1]
        if not (correction["status"] == "verified_known_generated_source_digest_shadow"
                and correction["actual_kernel_sha256"] == digest == original["candidate_sha256"] == provenance["kernel_sha256"]
                and correction["historical_reported_sha256"] == bad == verification["sha256"] == payload["xnu"]["kernel"]["sha256"]
                and correction["current_corrected_audit_passed"]):
            raise ValueError("Unexplained historical kernel report mismatch")
        for name, expected in correction["proof_files"].items():
            if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected:
                raise ValueError("Kernel correction proof changed: " + name)
    logpath = runtime / "console-ramoops-0"
    log = logpath.read_bytes()
    collection = json.loads((runtime / "collection.json").read_text())
    if hashlib.sha256(log).hexdigest() != collection["files"][logpath.name]["sha256"]:
        raise ValueError("Runtime log changed after collection")
    sections, component_ranges = embedded_sections(data)
    symbols = []
    for line in subprocess.check_output(["xcrun", "nm", "-n", kernel], text=True).splitlines():
        match = re.fullmatch(r"([0-9a-fA-F]{16}) \S (.+)", line)
        if match:
            symbols.append((int(match[1], 16), match[2]))
    symbols.sort()
    addresses = [addr for addr, _ in symbols]
    version_addresses = {addr for addr, name in symbols if name == "_version"}

    records = []
    for stage, value in re.findall(rb"UMI XNU ([0-9a-f]{2}) ([0-9a-f]{16})", log):
        stage, addr = stage.decode(), int(value, 16)
        record = {"stage": stage, "value": f"0x{addr:016x}"}
        if 0x70 <= int(stage, 16) <= 0x7f:
            record["pmgr_field"] = PMGR_FIELDS[int(stage, 16) - 0x70]
        if stage in RUNTIME_FIELDS:
            record["runtime_field"] = RUNTIME_FIELDS[stage]
        if 0x80 <= int(stage, 16) <= 0x9f:
            record["armcpu_field"] = ARMCPU_FIELDS[int(stage, 16) - 0x80]
        if 0xc0 <= int(stage, 16) <= 0xcf:
            record["screen_field"] = SCREEN_FIELDS[int(stage, 16) - 0xc0]
        if 0xe0 <= int(stage, 16) <= 0xff:
            record["ufs_field"] = UFS_FIELDS[int(stage, 16) - 0xe0]
        if stage in STRING_STAGES:
            # Only strings in the file, plus the exact immutable version array.
            # Never dereference addresses in the live handset.
            record["literal_from_archived_kernel"] = read_literal(
                data, sections, addr, allow_constant=stage == "43" and addr in version_addresses)
        if stage in SYMBOL_STAGES:
            # ARM64 LR points after BL. A noreturn call can be the last
            # instruction of a symbol, so resolve the call instruction itself.
            lookup = addr - 4 if stage in RETURN_ADDRESS_STAGES and addr >= 4 else addr
            owners = [(name, segment) for start, end, name, segment in component_ranges
                      if start <= lookup < end]
            i = bisect.bisect_right(addresses, lookup) - 1
            if owners:
                record.update(component=owners[0][0], component_segment=owners[0][1],
                              symbol_lookup_address=f"0x{lookup:016x}")
            elif i >= 0:
                base, name = symbols[i]
                record.update(nearest_symbol=name, symbol_offset=lookup - base,
                              symbol_lookup_address=f"0x{lookup:016x}")
        records.append(record)
    lock = decode_lock_trace(log)
    if lock["event"]:
        frames = []
        for address in lock["event"]["return_addresses"]:
            lookup = address - 4
            frame = {"return_address":f"0x{address:016x}","call_address":f"0x{lookup:016x}"}
            owners = [(name, segment) for start,end,name,segment in component_ranges if start <= lookup < end]
            i = bisect.bisect_right(addresses,lookup)-1
            if owners:
                frame.update(component=owners[0][0],component_segment=owners[0][1])
            elif i >= 0:
                frame.update(nearest_symbol=symbols[i][1],symbol_offset=lookup-symbols[i][0])
            frames.append(frame)
        lock["event"]["frames"] = frames
    execution = decode_exec_trace(log)
    for event in execution["events"]:
        for field in ("path_address", "format_address"):
            if field in event:
                event[field.replace("_address", "_literal")] = read_literal(data, sections, event[field])
        event["frames"] = []
        for address in event["return_addresses"]:
            lookup = address - 4
            owners = [(name, segment) for start, end, name, segment in component_ranges if start <= lookup < end]
            i = bisect.bisect_right(addresses, lookup) - 1
            frame = {"return_address": f"0x{address:016x}"}
            if owners:
                frame.update(component=owners[0][0], component_segment=owners[0][1])
            elif i >= 0:
                frame.update(nearest_symbol=symbols[i][1], symbol_offset=lookup-symbols[i][0])
            event["frames"].append(frame)
    return {
        "execution": execution,
        "runtime_snapshots": decode_runtime_trace(log),
        "userspace_diagnostics": decode_userspace(log),
        "touch_diagnostics": decode_touch(log),
        "userspace_waits": decode_wait_trace(log),
        "lock_failure": lock,
        "owner_root": decode_root_trace(log),
        "attempt": attempt, "kernel": str(kernel), "kernel_sha256": digest,
        "runtime_log": str(logpath), "runtime_log_sha256": hashlib.sha256(log).hexdigest(),
        "kernel_provenance_correction": correction,
        "interpretation": "Strings are decoded from archived file bytes at recorded addresses; not proof of visible console output. Last marker alone does not prove a crash.",
        "markers": records,
        "armcpu": phone_events(records),
        "screen": screen_events(records),
        "ufs": ufs_events(records),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attempt", type=int)
    parser.add_argument("--runtime-dir", type=Path, help="separate logs from another boot of the same archived image")
    args = parser.parse_args()
    report = decode(args.attempt, args.runtime_dir)
    output = Path(report["runtime_log"]).parent / "trace-decoded.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"report": str(output), "markers": report["markers"]}, indent=2))


if __name__ == "__main__":
    main()
