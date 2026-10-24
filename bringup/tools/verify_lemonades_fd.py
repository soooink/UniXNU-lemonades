#!/usr/bin/env python3
"""Inspect the assembled lemonades FD with UEFIExtract; never execute firmware."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import uuid

from import_lemonades_uefi import fields, image_machine, section_bytes


ROOT = Path(__file__).resolve().parents[1]
APRIORI_GUID = "FC510EE7-FFDC-11D4-BD41-0080C73C8881"
GUID_RE = r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"
RAM_STORAGE_INFS = {
    "MdeModulePkg/Universal/Disk/DiskIoDxe/DiskIoDxe.inf",
    "FatPkg/EnhancedFatDxe/Fat.inf",
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inf_paths(text: str) -> list[str]:
    text = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
    return re.findall(r"(?m)^\s*INF\s+([^\s{]+\.inf)\s*$", text)


def guid_array(data: bytes) -> list[str]:
    if not data or len(data) % 16:
        raise ValueError("APRIORI RAW is not a nonempty complete EFI GUID array")
    result = [str(uuid.UUID(bytes_le=data[i:i + 16])).upper() for i in range(0, len(data), 16)]
    if len(set(result)) != len(result):
        raise ValueError("Duplicate GUID in APRIORI")
    return result


def inf_identity(path: Path) -> tuple[str, str]:
    text = path.read_text()
    guid = re.search(rf"(?m)^\s*FILE_GUID\s*=\s*({GUID_RE})\s*$", text)
    name = re.search(r"(?m)^\s*BASE_NAME\s*=\s*(\w+)\s*$", text)
    if not guid or not name:
        raise ValueError(f"Cannot resolve literal INF identity: {path}")
    return guid[1].upper(), name[1]


def storage_name(name: str) -> bool:
    # Source VariableRuntimeDxe is deliberately allowed: its backing store is
    # volatile. This rule targets packaged executables, not repository files.
    return bool(re.search(r"(?:ufs|sdcc|sdhci|usb|diskio|partition|fat(?:dxe)?$|pil|"
                          r"filesystem|rammanager|verifiedboot|^variabledxe$|firmwareupdate)",
                          name, re.IGNORECASE))


def actual_files(dump: Path) -> dict[str, dict]:
    metadata = {p.parent: fields(p.read_bytes()) for p in sorted(dump.rglob("info.txt"))}
    files = {}
    for path, entry in metadata.items():
        if entry.get("Type") != "File":
            continue
        guid = str(uuid.UUID(entry["File GUID"])).upper()
        if guid in files:
            raise ValueError(f"Duplicate file GUID in actual FD: {guid}")
        files[guid] = {"guid": guid, "ui": entry.get("Text"), "subtype": entry.get("Subtype"),
                       "path": path.relative_to(dump).as_posix(), "sections": {}}
    for path, entry in metadata.items():
        if entry.get("Type") != "Section" or entry.get("Subtype") not in (
                "PE32 image", "TE image", "DXE dependency", "Raw"):
            continue
        parent = path.parent
        while parent != dump and metadata.get(parent, {}).get("Type") != "File":
            parent = parent.parent
        if parent == dump:
            continue
        guid = str(uuid.UUID(metadata[parent]["File GUID"])).upper()
        kind = entry["Subtype"]
        if kind in files[guid]["sections"]:
            raise ValueError(f"Ambiguous duplicate {kind} in actual FD {guid}")
        files[guid]["sections"][kind] = section_bytes(path, dump)
    return files


def check_contents(files: dict, manifest: dict, vendor_paths: set[str], raw_paths: set[str],
                   local_guids: dict[str, dict], expected_apriori: list[str], binaries: Path,
                   payload_profile: str = "none") -> dict:
    by_inf = {m["inf"]: m for m in manifest["modules"]}
    unknown = vendor_paths - set(by_inf)
    if unknown:
        raise ValueError(f"Selected vendor INF absent from import manifest: {sorted(unknown)}")
    selected = {by_inf[path]["guid"]: by_inf[path] for path in vendor_paths}
    module_results = []
    actual_executables = {}
    for guid, entry in files.items():
        kinds = set(entry["sections"]) & {"PE32 image", "TE image"}
        if len(kinds) > 1:
            raise ValueError(f"Actual file has both PE and TE payloads: {guid}")
        if kinds:
            kind = kinds.pop()
            code = entry["sections"][kind]
            if image_machine(code, kind) != 0xAA64:
                raise ValueError(f"Non-AArch64 executable packaged: {guid}")
            actual_executables[guid] = (entry, kind, code)
    for guid, module in sorted(selected.items()):
        if guid not in actual_executables:
            raise ValueError(f"Selected vendor executable missing from FD: {module['inf']}")
        entry, kind, code = actual_executables[guid]
        if sha(code) != module["pe_sha256"] or kind != module["binary_type"]:
            raise ValueError(f"Vendor executable changed in FD: {module['inf']}")
        expected = module["depex"]
        dependency = entry["sections"].get("DXE dependency")
        if expected is None and dependency is not None:
            raise ValueError(f"New vendor DEPEX introduced: {module['inf']}")
        if expected is not None and (dependency is None or sha(dependency) != expected["sha256"]):
            raise ValueError(f"Vendor original DEPEX missing or changed: {module['inf']}")
        module_results.append({"guid": guid, "ui": module["ui"], "inf": module["inf"],
                               "pe_sha256": sha(code), "pe_bytes_match": True,
                               "depex_sha256": sha(dependency) if dependency is not None else None,
                               "original_depex_match": True, "actual_file": entry["path"]})
    stock_by_guid = {m["guid"]: m for m in manifest["modules"]}
    local_results = []
    for guid, (entry, kind, code) in actual_executables.items():
        if guid in selected:
            continue
        if guid not in local_guids:
            module = stock_by_guid.get(guid)
            raise ValueError(f"Unexpected executable in actual FD: {guid}, {entry['ui']}, "
                             f"stock={module['inf'] if module else None}")
        identity = local_guids[guid]
        is_storage = storage_name(identity["name"]) or storage_name(entry["ui"] or "")
        allowed_ram = payload_profile == "ram" and identity["inf"] in RAM_STORAGE_INFS
        if is_storage and not allowed_ram:
            raise ValueError(f"Local storage/device executable packaged: {identity}")
        if guid in stock_by_guid and sha(code) == stock_by_guid[guid]["pe_sha256"]:
            raise ValueError(f"Unselected vendor bytes used in place of source equivalent: {guid}")
        local_results.append({"guid": guid, "ui": entry["ui"], "source_inf": identity["inf"],
                              "pe_sha256": sha(code), "not_storage_class": not is_storage,
                              "ram_filesystem_service": allowed_ram})
    missing_local = set(local_guids) - set(actual_executables)
    if missing_local:
        raise ValueError(f"Expected source executable missing from actual FD: {sorted(missing_local)}")
    raw_by_file = {r["file"]: r for r in manifest["raw_files"]}
    resource_results = []
    for path in sorted(raw_paths):
        if path not in raw_by_file:
            raise ValueError(f"Selected raw file absent from imported manifest: {path}")
        resource = raw_by_file[path]
        data = files.get(resource["guid"], {}).get("sections", {}).get("Raw")
        if data is None or sha(data) != resource["sha256"]:
            raise ValueError(f"Original raw resource missing or changed: {path}")
        resource_results.append({"guid": resource["guid"], "file": path,
                                 "sha256": sha(data), "bytes_match": True})
    # All other stock modules/resources are forbidden unless the file GUID is
    # an explicitly selected source replacement (whose code was checked above).
    allowed_stock_guids = set(selected) | set(local_guids)
    forbidden_modules = (set(files) & set(stock_by_guid)) - allowed_stock_guids
    forbidden_raw = {r["guid"] for r in manifest["raw_files"]
                     if r["file"] not in raw_paths and r["guid"] != APRIORI_GUID} & set(files)
    if forbidden_modules or forbidden_raw:
        raise ValueError(f"Unselected stock files packaged: {sorted(forbidden_modules | forbidden_raw)}")
    actual_apriori = guid_array(files.get(APRIORI_GUID, {}).get("sections", {}).get("Raw", b""))
    if actual_apriori != expected_apriori:
        raise ValueError("Actual APRIORI GUID array differs from board selection/order")
    missing_apriori = set(actual_apriori) - set(files)
    if missing_apriori:
        raise ValueError(f"APRIORI contains dangling file GUIDs: {sorted(missing_apriori)}")
    stock_record = next(r for r in manifest["raw_files"] if r["guid"] == APRIORI_GUID)
    stock_bytes = (binaries / stock_record["file"]).read_bytes()
    if sha(stock_bytes) != stock_record["sha256"]:
        raise ValueError("Imported stock APRIORI changed")
    stock_apriori = guid_array(stock_bytes)
    actual_vendor_order = [g for g in actual_apriori if g in selected]
    expected_vendor_order = [g for g in stock_apriori if g in selected]
    if set(actual_vendor_order) != set(selected) or actual_vendor_order != expected_vendor_order:
        raise ValueError("Actual selected vendor APRIORI does not preserve relative stock order")
    return {"vendor_modules": module_results, "local_executables": local_results,
            "resources": resource_results, "apriori": {"actual_guids": actual_apriori,
            "stock_count": len(stock_apriori), "selected_vendor_guids": actual_vendor_order,
            "selected_vendor_stock_indices": [stock_apriori.index(g) for g in actual_vendor_order],
            "stock_relative_order_match": True, "no_dangling_guids": True},
            "no_unselected_vendor_modules": True,
            "no_local_storage_executables": not any(e["ram_filesystem_service"] for e in local_results),
            "no_persistent_storage_executables": True,
            "payload_profile": payload_profile}


def find_source_inf(uefi: Path, relative: str) -> Path:
    if relative.startswith(("UniXNUPkg/", "DarwinBootPkg/")):
        candidate = ROOT / "out/lemonades-menu-package" / relative
        if candidate.is_file():
            return candidate
    candidates = [uefi / relative]
    candidates.extend(uefi.glob("*/" + relative))
    candidates.extend(uefi.glob("*/*/" + relative))
    candidates.extend(uefi.glob("*/*/*/" + relative))
    candidates = list({p.resolve() for p in candidates if p.is_file()
                       and "Binaries" not in p.relative_to(uefi).parts
                       and "Build" not in p.relative_to(uefi).parts})
    if len(candidates) != 1:
        raise ValueError(f"Ambiguous or missing selected source INF {relative}: {candidates}")
    return candidates[0]


def verify(args: argparse.Namespace) -> dict:
    uefi = args.uefi.resolve(strict=True)
    board = uefi / "Platforms/OnePlus/lemonadesPkg"
    prepare = json.loads((ROOT / "out/lemonades/prepare.json").read_text())
    manifest_path = Path(prepare["import_manifest"])
    manifest_bytes = manifest_path.read_bytes()
    if sha(manifest_bytes) != prepare["import_manifest_sha256"]:
        raise ValueError("Imported firmware manifest differs from staged build provenance")
    manifest = json.loads(manifest_bytes)
    binaries = manifest_path.parent
    extractor = args.extractor.resolve(strict=True)
    tool_hash = sha(extractor.read_bytes())
    if tool_hash != manifest["extraction"]["tool_sha256"]:
        raise ValueError("Host UEFIExtract differs from import-pinned tool")
    sources = {name: (board / name).read_text() for name in
               ("lemonades.fdf", "Include/DXE.inc", "Include/APRIORI.inc", "Include/RAW.inc")}
    dxe_vendor = {p.removeprefix("Binaries/lemonades/") for p in inf_paths(sources["Include/DXE.inc"])
                  if p.startswith("Binaries/lemonades/")}
    apriori_paths = inf_paths(sources["Include/APRIORI.inc"])
    apriori_vendor = {p.removeprefix("Binaries/lemonades/") for p in apriori_paths if p.startswith("Binaries/lemonades/")}
    if dxe_vendor != apriori_vendor:
        raise ValueError("DXE and APRIORI vendor selections differ")
    vendor_by_inf = {m["inf"]: m for m in manifest["modules"]}
    all_inf_paths = {p for text in sources.values() for p in inf_paths(text)}
    local_guids, local_by_inf = {}, {}
    for relative in sorted(all_inf_paths):
        if relative.startswith("Binaries/lemonades/"):
            continue
        path = find_source_inf(uefi, relative)
        guid, name = inf_identity(path)
        if guid in local_guids:
            raise ValueError(f"Two selected source INFs share a file GUID: {guid}")
        local_guids[guid] = {"inf": relative, "name": name, "inf_sha256": sha(path.read_bytes())}
        local_by_inf[relative] = guid
    expected_apriori = [vendor_by_inf[p.removeprefix("Binaries/lemonades/")]["guid"]
                        if p.startswith("Binaries/lemonades/") else local_by_inf[p] for p in apriori_paths]
    raw_paths = set(re.findall(r"SECTION\s+RAW\s*=\s*Binaries/lemonades/([^\s}]+)", sources["Include/RAW.inc"]))
    fd_bytes = args.fd.read_bytes()
    fd_hash = sha(fd_bytes)
    if args.expected_fd_sha256 and fd_hash != args.expected_fd_sha256:
        raise ValueError("FD differs from caller-pinned final build hash")
    args.output.mkdir(parents=True, exist_ok=True)
    extraction = Path(tempfile.mkdtemp(prefix=f"fd-{fd_hash[:12]}-", dir=args.output))
    copied_fd = extraction / "SILICIUM_UEFI.fd"
    copied_fd.write_bytes(fd_bytes)
    completed = subprocess.run([str(extractor), str(copied_fd), "all"], cwd=extraction,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    (extraction / "uefiextract.log").write_bytes(completed.stdout)
    if completed.returncode:
        raise ValueError(f"Host UEFIExtract failed: exit {completed.returncode}, see {extraction}")
    if sha(extractor.read_bytes()) != tool_hash or sha(args.fd.read_bytes()) != fd_hash:
        raise ValueError("FD or extraction executable changed during verification")
    files = actual_files(copied_fd.with_name(copied_fd.name + ".dump"))
    profile = prepare.get("payload_profile", "none")
    if profile not in ("none", "ram"):
        raise ValueError("Unknown payload profile")
    # The test app must be loaded from FAT; embedding it would invalidate proof.
    if profile == "ram" and "E84F2A4F-8C0E-49AE-B5F3-B9FC591DA252" in files:
        raise ValueError("External payload check was incorrectly embedded in FD")
    results = check_contents(files, manifest, dxe_vendor, raw_paths, local_guids, expected_apriori, binaries, profile)
    return {"format_version": 1, "device": "lemonades", "status": "passed", "hardware_tested": False,
            "firmware_executed": False, "fd": {"path": str(args.fd.resolve()), "sha256": fd_hash,
            "bytes": len(fd_bytes)}, "tool": {"path": str(extractor), "sha256": tool_hash},
            "import_manifest": {"path": str(manifest_path), "sha256": sha(manifest_bytes)},
            "board_inputs_sha256": {name: sha(text.encode()) for name, text in sources.items()},
            "extraction": {"directory": str(extraction.resolve()), "exit_code": completed.returncode,
                           "warnings": completed.stdout.decode(errors="replace").splitlines()},
            "actual_file_count": len(files),
            "actual_files": [{key: value for key, value in entry.items() if key != "sections"}
                             for entry in files.values()],
            **results,
            "limitations": ["This validates packaged bytes and dispatch metadata, not hardware initialization.",
                            "APRIORI order bypasses original DEPEX; preserving it does not prove protocol availability."]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uefi", type=Path, default=ROOT / "sources/uefi-lemonades")
    parser.add_argument("--fd", type=Path, default=ROOT / "sources/uefi-lemonades/Build/lemonadesPkg/DEBUG_CLANGPDB/FV/SILICIUM_UEFI.fd")
    parser.add_argument("--expected-fd-sha256")
    parser.add_argument("--extractor", type=Path, default=ROOT / "out/tools/uefiextract/uefiextract")
    parser.add_argument("--output", type=Path, default=ROOT / "out/lemonades/validation")
    args = parser.parse_args()
    try:
        report = verify(args)
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "fd-validation.json").write_text(json.dumps({"status": "failed", "error": str(exc),
                                                               "hardware_tested": False}, indent=2) + "\n")
        parser.exit(1, f"FD verification failed: {exc}\n")
    destination = args.output / "fd-validation.json"
    destination.write_text(json.dumps(report, indent=2) + "\n")
    print(f"FD verified: {report['actual_file_count']} actual files; "
          f"{len(report['vendor_modules'])} unchanged vendor executables/DEPEX; "
          f"{len(report['resources'])} original raw resources")
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
