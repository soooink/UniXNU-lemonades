#!/usr/bin/env python3
"""Import verified, local lemonades XBL modules without executing vendor binaries.

The INF layout follows UniXNU-sheng/scripts/import-sheng-uefi.py. This importer
also re-extracts the verified image with a caller-pinned host UEFIExtract and
compares the complete dump before using it. Debug paths only suggest filenames.
Generated vendor bytes remain in out/, outside version control.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import subprocess
import tempfile
import uuid


ROOT = Path(__file__).resolve().parents[1]
MODULE_TYPES = {
    "DXE driver": "DXE_DRIVER", "Application": "UEFI_APPLICATION",
    "UEFI application": "UEFI_APPLICATION", "DXE core": "DXE_CORE",
    "SEC core": "SEC", "PEI core": "PEI_CORE", "PEI module": "PEIM",
    "Combined SMM/DXE": "DXE_SMM_DRIVER",
}
SECTION_TYPES = {"PE32 image", "TE image", "DXE dependency", "Raw"}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_file(path: Path, root: Path) -> bytes:
    """Refuse symlinks anywhere below a caller-selected input root."""
    if root.is_symlink() or not path.is_relative_to(root):
        raise ValueError(f"Input outside root: {path}")
    current = path
    while current != root:
        if current.is_symlink():
            raise ValueError(f"Symlink input refused: {current}")
        current = current.parent
    if not path.is_file():
        raise ValueError(f"Missing regular input: {path}")
    return path.read_bytes()


def fields(data: bytes) -> dict[str, str]:
    """UEFIExtract repeats Type: keep the first, human-readable occurrence."""
    result = {}
    for line in data.decode("utf-8", errors="strict").splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            result.setdefault(key, value)
    return result


def safe_relative(value: str) -> Path:
    normalized = value.replace("\\", "/")
    pieces = normalized.split("/")
    if (not normalized or PurePosixPath(normalized).is_absolute()
            or any(part in ("", ".", "..") for part in pieces)
            or any(not re.fullmatch(r"[A-Za-z0-9_. -]+", part) for part in pieces)):
        raise ValueError(f"Unsafe output path: {value!r}")
    return Path(*pieces)


def image_machine(code: bytes, kind: str) -> int:
    if kind == "TE image":
        if len(code) < 40 or code[:2] != b"VZ":
            raise ValueError("Invalid TE image")
        return struct.unpack_from("<H", code, 2)[0]
    if len(code) < 64 or code[:2] != b"MZ":
        raise ValueError("Invalid PE DOS header")
    offset = struct.unpack_from("<I", code, 0x3C)[0]
    if offset > len(code) - 24 or code[offset:offset + 4] != b"PE\0\0":
        raise ValueError("Invalid PE header offset or signature")
    return struct.unpack_from("<H", code, offset + 4)[0]


def section_bytes(section: Path, dump: Path) -> bytes:
    body = section / "body.bin"
    if body.exists() or body.is_symlink():
        return read_file(body, dump)
    # UEFIExtract omits body.bin for a genuinely empty section.
    entry = fields(read_file(section / "info.txt", dump))
    sizes = [re.match(r"^([0-9a-fA-F]+)h(?: |$)", entry.get(key, ""))
             for key in ("Full size", "Header size")]
    if all(sizes) and int(sizes[0][1], 16) == int(sizes[1][1], 16):
        return b""
    raise ValueError(f"Missing nonempty section body: {section}")


def module_destination(code: bytes, ui: str, guid: str) -> tuple[Path, str, list[str]]:
    paths = re.findall(rb"[A-Za-z0-9_/\\.:-]+\.(?:dll|pdb)\b", code)
    hints = sorted({p.decode("ascii").replace("\\", "/") for p in paths})
    candidates = set()
    for hint in hints:
        if "/AARCH64/" not in hint:
            continue
        tail = hint.split("/AARCH64/", 1)[1]
        parts = safe_relative(tail).parts
        if len(parts) >= 3 and parts[-2].upper() in ("DEBUG", "RELEASE"):
            module = parts[-3]
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", module):
                raise ValueError(f"Invalid module basename: {module}")
            candidates.add((str(Path(*parts[:-3])), module))
    if len(candidates) > 1:
        raise ValueError(f"Conflicting debug-path hints for {ui}: {candidates}")
    if candidates:
        relative, module = candidates.pop()
        return Path(relative), module, hints
    module = re.sub(r"[^A-Za-z0-9_]", "_", ui)
    if not module or module[0].isdigit():
        module = "Module_" + guid.replace("-", "_")
    return Path("Modules") / guid, module, hints


def dump_inventory(dump: Path) -> dict[str, str]:
    result = {}
    for path in sorted(dump.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"Symlink inside extraction: {path}")
        if path.is_file():
            result[path.relative_to(dump).as_posix()] = sha256(read_file(path, dump))
    if not result:
        raise ValueError("Empty extraction dump")
    return result


def output_plan(dump: Path, source_hash: str) -> tuple[dict[Path, bytes], list, list, list]:
    metadata = {p.parent: fields(read_file(p, dump)) for p in sorted(dump.rglob("info.txt"))}
    owned_sections: dict[Path, dict[str, Path]] = {}
    for directory, entry in metadata.items():
        if entry.get("Type") != "Section" or entry.get("Subtype") not in SECTION_TYPES:
            continue
        parent = directory.parent
        while parent != dump and metadata.get(parent, {}).get("Type") != "File":
            parent = parent.parent
        if parent == dump:
            continue
        kind = entry["Subtype"]
        found = owned_sections.setdefault(parent, {})
        if kind in found:
            raise ValueError(f"Duplicate {kind} sections in {parent.relative_to(dump)}: "
                             f"{found[kind].relative_to(dump)}, {directory.relative_to(dump)}")
        found[kind] = directory

    plan: dict[Path, bytes] = {}
    modules, raw_files, skipped = [], [], []

    def add(relative: Path, data: bytes) -> None:
        safe_relative(relative.as_posix())
        if relative in plan:
            raise ValueError(f"Duplicate output path, even if bytes match: {relative}")
        plan[relative] = data

    def provenance(directory: Path, section: Path) -> dict:
        return {
            "source_sha256": source_hash,
            "source_file_path": directory.relative_to(dump).as_posix(),
            "source_file_body_sha256": sha256(read_file(directory / "body.bin", dump)),
            "section_path": section.relative_to(dump).as_posix(),
            "section_info_sha256": sha256(read_file(section / "info.txt", dump)),
        }

    for directory, entry in metadata.items():
        if entry.get("Type") != "File":
            continue
        subtype = entry.get("Subtype")
        guid = str(uuid.UUID(entry["File GUID"])).upper()
        ui = entry.get("Text", guid)
        sections = owned_sections.get(directory, {})
        code_types = set(sections) & {"PE32 image", "TE image"}
        if len(code_types) > 1:
            raise ValueError(f"Both PE32 and TE present in {ui}; selection would be ambiguous")
        if code_types and subtype in MODULE_TYPES:
            kind = code_types.pop()
            section = sections[kind]
            code = section_bytes(section, dump)
            if image_machine(code, kind) != 0xAA64:
                raise ValueError(f"Non-AArch64 executable in {ui}")
            relative, module, hints = module_destination(code, ui, guid)
            add(relative / f"{module}.efi", code)
            inf = ("# Generated from this lemonades device's verified XBL; vendor bytes stay outside Git.\n"
                   "[Defines]\n  INF_VERSION = 0x0001001B\n"
                   f"  BASE_NAME = {module}\n  FILE_GUID = {guid}\n"
                   f"  MODULE_TYPE = {MODULE_TYPES[subtype]}\n  VERSION_STRING = 1.0\n\n"
                   f"[Binaries.AARCH64]\n  {'PE32' if kind == 'PE32 image' else 'TE'}|{module}.efi|*\n")
            depex_record = None
            if "DXE dependency" in sections:
                dependency = sections["DXE dependency"]
                depex = section_bytes(dependency, dump)
                add(relative / f"{module}.depex", depex)
                inf += f"  DXE_DEPEX|{module}.depex|*\n"
                depex_record = {**provenance(directory, dependency),
                                "sha256": sha256(depex), "bytes": len(depex),
                                "original_hex": depex.hex(),
                                "file": (relative / f"{module}.depex").as_posix()}
            add(relative / f"{module}.inf", inf.encode("utf-8"))
            modules.append({**provenance(directory, section), "ui": ui, "guid": guid,
                            "module_type": MODULE_TYPES[subtype], "binary_type": kind,
                            "machine": "0xAA64", "bytes": len(code), "pe_sha256": sha256(code),
                            "efi": (relative / f"{module}.efi").as_posix(),
                            "inf": (relative / f"{module}.inf").as_posix(),
                            "debug_path_hints": hints,
                            "debug_path_hint_is_behavior_evidence": False,
                            "depex": depex_record})
        elif subtype == "Freeform" and "Raw" in sections:
            section = sections["Raw"]
            data = section_bytes(section, dump)
            relative = Path("RawFiles") / safe_relative(ui.replace(" ", "_"))
            add(relative, data)
            raw_files.append({**provenance(directory, section), "ui": ui, "guid": guid,
                              "file": relative.as_posix(), "sha256": sha256(data), "bytes": len(data)})
        else:
            skipped.append({"ui": ui, "guid": guid, "subtype": subtype,
                            "source_file_path": directory.relative_to(dump).as_posix(),
                            "reason": "No supported executable or freeform raw section owned by this file"})
    return plan, modules, raw_files, skipped


def configuration_plan(plan: dict[Path, bytes]) -> dict[Path, bytes]:
    """Parse stock map rows without interpreting their runtime compatibility."""
    raw = plan.get(Path("RawFiles/uefiplat.cfg"))
    if raw is None:
        raise ValueError("Verified lemonades XBL contains no uefiplat.cfg raw resource")
    maps, parameters, section = [], {}, ""
    for number, line in enumerate(raw.decode("utf-8-sig").splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if section in ("MemoryMap", "RegisterMap"):
            values = next(csv.reader([line], skipinitialspace=True))
            if len(values) != 8:
                raise ValueError(f"Expected 8 stock memory columns on line {number}")
            address, size = int(values[0], 0), int(values[1], 0)
            maps.append({"section": section, "line": number, "address": hex(address),
                         "size": hex(size), "end_exclusive": hex(address + size),
                         **dict(zip(("name", "hob_option", "resource_type", "resource_attribute",
                                     "memory_type", "arm_attribute"), values[2:]))})
        elif "=" in line:
            key, value = (part.strip() for part in line.split("=", 1))
            if key in parameters.setdefault(section, {}):
                raise ValueError(f"Duplicate stock parameter {section}.{key}")
            try:
                parsed = int(value, 0)
            except ValueError:
                parsed = value.strip('"')
            parameters[section][key] = parsed
    parsed = {"source": "RawFiles/uefiplat.cfg", "source_sha256": sha256(raw),
              "evidence_type": "stock firmware configuration, not a runtime memory map",
              "regions": maps, "parameters": parameters}
    table = io.StringIO()
    writer = csv.DictWriter(table, fieldnames=list(maps[0]))
    writer.writeheader()
    writer.writerows(maps)
    return {Path("uefiplat-memory-map.json"): (json.dumps(parsed, indent=2) + "\n").encode(),
            Path("uefiplat-memory-map.csv"): table.getvalue().encode()}


def decode_depex(data: bytes) -> list[dict]:
    operations, offset, depth = [], 0, 0
    names = {0: "BEFORE", 1: "AFTER", 2: "PUSH", 3: "AND", 4: "OR", 5: "NOT",
             6: "TRUE", 7: "FALSE", 8: "END", 9: "SOR"}
    while offset < len(data):
        start, opcode = offset, data[offset]
        offset += 1
        if opcode not in names:
            raise ValueError(f"Unknown dependency opcode {opcode:#x} at {start}")
        operation = {"offset": start, "opcode": names[opcode]}
        if opcode in (0, 1, 2):
            if offset + 16 > len(data):
                raise ValueError("Truncated dependency GUID")
            operation["guid"] = str(uuid.UUID(bytes_le=data[offset:offset + 16])).upper()
            offset += 16
            depth += opcode == 2
        elif opcode in (3, 4):
            if depth < 2:
                raise ValueError("Invalid dependency expression stack")
            depth -= 1
        elif opcode == 5 and depth < 1:
            raise ValueError("Invalid NOT dependency expression stack")
        elif opcode in (6, 7):
            depth += 1
        operations.append(operation)
        if opcode == 8:
            if depth != 1 and not (operations and operations[0]["opcode"] in ("BEFORE", "AFTER")):
                raise ValueError("Invalid dependency stack depth at END")
            if offset != len(data):
                raise ValueError("Trailing bytes after dependency END")
            return operations
    raise ValueError("Dependency expression has no END opcode")


def display_dependencies(plan: dict[Path, bytes], modules: list[dict]) -> dict:
    selected = [module for module in modules if module["ui"] == "DisplayDxe"]
    if len(selected) != 1 or selected[0]["depex"] is None:
        raise ValueError("Expected exactly one stock DisplayDxe with original DXE dependencies")
    display = selected[0]
    depex = plan[Path(display["depex"]["file"])]
    operations = decode_depex(depex)
    dependencies = []
    for guid in sorted({operation["guid"] for operation in operations if "guid" in operation}):
        needle = uuid.UUID(guid).bytes_le
        candidates = []
        for module in modules:
            if module is display:
                continue
            code = plan[Path(module["efi"])]
            offsets, start = [], 0
            while (found := code.find(needle, start)) >= 0:
                offsets.append(found)
                start = found + 1
            if offsets:
                candidates.append({"ui": module["ui"], "file_guid": module["guid"],
                                   "efi": module["efi"], "offsets": offsets})
        dependencies.append({"guid": guid, "byte_occurrence_candidates": candidates,
                             "confirmed_protocol_provider": None,
                             "status": "candidate byte occurrences only" if candidates
                             else "no occurrence in other imported stock executables"})
    return {"display": {key: display[key] for key in ("ui", "guid", "efi", "inf", "pe_sha256")},
            "original_depex": display["depex"], "operations": operations, "dependencies": dependencies,
            "runtime_dependency_satisfaction": "unverified",
            "limitations": ["GUID byte matches do not prove InstallProtocolInterface or a protocol provider.",
                            "Zero matches do not exclude a provider in another image or generated at runtime.",
                            "No synthetic protocols or DEPEX changes have been introduced."]}


def write_plan(output: Path, plan: dict[Path, bytes]) -> None:
    """Preflight all conflicts before producing output; never follow symlinks."""
    if output.is_symlink():
        raise ValueError(f"Symlink output root refused: {output}")
    for relative, data in plan.items():
        safe_relative(relative.as_posix())
        path = output / relative
        current = path
        while current != output.parent:
            if current.is_symlink():
                raise ValueError(f"Symlink output refused: {current}")
            current = current.parent
        if path.exists() and (not path.is_file() or path.read_bytes() != data):
            raise ValueError(f"Conflicting existing output: {path}")
    output.mkdir(parents=True, exist_ok=True)
    for relative, data in plan.items():
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            with path.open("xb") as stream:
                stream.write(data)


def import_firmware(firmware: Path, extractor: Path, expected_tool_hash: str) -> dict:
    firmware = firmware.resolve(strict=True)
    extractor = extractor.resolve(strict=True)
    source_manifest = json.loads(read_file(firmware / "manifest.json", firmware))
    record = source_manifest["artifacts"]["xbl_5"]
    if not record.get("device_sha256_verified"):
        raise ValueError("XBL collection did not verify the source partition hash")
    source = firmware / safe_relative(record["file"])
    copied = firmware / "extract/xbl_5.img"
    raw = read_file(source, firmware)
    source_hash = sha256(raw)
    if source_hash != record["sha256"] or len(raw) != record["bytes"]:
        raise ValueError("Raw XBL does not match the device collection manifest")
    if sha256(read_file(copied, firmware)) != source_hash:
        raise ValueError("Extraction input copy differs from verified raw XBL")
    tool_hash = sha256(extractor.read_bytes())
    if not re.fullmatch(r"[a-f0-9]{64}", expected_tool_hash) or tool_hash != expected_tool_hash:
        raise ValueError("UEFIExtract executable hash differs from the caller-pinned hash")
    dump = firmware / "extract/xbl_5.img.dump"
    current = dump
    while current != firmware:
        if current.is_symlink():
            raise ValueError(f"Symlink extraction root refused: {current}")
        current = current.parent
    original_inventory = dump_inventory(dump)
    with tempfile.TemporaryDirectory(prefix="verify-uefiextract-", dir=firmware) as temporary:
        fresh_source = Path(temporary) / "xbl_5.img"
        fresh_source.write_bytes(raw)
        command = [str(extractor), str(fresh_source), "all"]
        completed = subprocess.run(command, cwd=temporary, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, check=False, timeout=120)
        if completed.returncode != 0:
            raise ValueError(f"UEFIExtract verification failed with exit {completed.returncode}: "
                             + completed.stdout.decode(errors="replace"))
        fresh_inventory = dump_inventory(fresh_source.with_name("xbl_5.img.dump"))
        if original_inventory != fresh_inventory:
            raise ValueError("Existing extraction differs from fresh extraction of verified XBL")
        extraction_log = completed.stdout
    if sha256(extractor.read_bytes()) != tool_hash:
        raise ValueError("UEFIExtract changed during extraction verification")
    plan, modules, raw_files, skipped = output_plan(dump, source_hash)
    plan.update(configuration_plan(plan))
    plan[Path("display-dependencies.json")] = (json.dumps(display_dependencies(plan, modules), indent=2) + "\n").encode()
    inventory_hash = sha256(json.dumps(original_inventory, sort_keys=True).encode())
    warnings = extraction_log.decode("utf-8", errors="replace").splitlines()
    manifest = {
        "format_version": 1, "device": "lemonades", "source_sha256": source_hash,
        "source_partition": record["source"], "source_bytes": len(raw),
        "collection_manifest_sha256": sha256(read_file(firmware / "manifest.json", firmware)),
        "extraction_copy_sha256": sha256(read_file(copied, firmware)),
        "extraction": {"method": "local UEFIExtract shell process; no target execution",
                       "tool": str(extractor), "tool_sha256": tool_hash, "verified_exit_code": 0,
                       "complete_dump_compared_against_fresh_extraction": True,
                       "dump_file_count": len(original_inventory), "dump_inventory_sha256": inventory_hash,
                       "warnings": warnings, "verification_log_sha256": sha256(extraction_log)},
        "modules": modules, "raw_files": raw_files, "skipped_files": skipped,
        "hardware_boot_demonstrated": False, "targets_executed": False,
        "limitations": ["Extraction warnings are retained; absence of a VTF or unaligned FV is not resolved here.",
                        "AArch64 PE headers, filenames and debug paths do not prove driver behavior or compatibility.",
                        "Original executable and DXE dependency bytes are unchanged; no driver is selected for boot."]}
    plan[Path("verification-extraction.log")] = extraction_log
    plan[Path("dump-inventory.json")] = (json.dumps(original_inventory, indent=2, sort_keys=True) + "\n").encode()
    plan[Path("manifest.json")] = (json.dumps(manifest, indent=2) + "\n").encode()
    write_plan(firmware / "uefi-binaries", plan)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", type=Path, help="Local verified lemonades firmware collection directory")
    parser.add_argument("--extractor", type=Path, default=ROOT / "out/tools/uefiextract/uefiextract")
    parser.add_argument("--extractor-sha256", required=True, help="Pinned hash of the host extraction executable")
    args = parser.parse_args()
    try:
        manifest = import_firmware(args.firmware, args.extractor, args.extractor_sha256)
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        parser.exit(1, f"Import refused: {exc}\n")
    print(f"Imported {len(manifest['modules'])} AArch64 modules and {len(manifest['raw_files'])} raw resources")
    print(f"Output: {args.firmware.resolve() / 'uefi-binaries'}")
    print("Original DEPEX preserved; vendor binaries were not executed; hardware boot is unverified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
