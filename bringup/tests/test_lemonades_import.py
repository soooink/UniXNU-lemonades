"""Regression coverage for binary provenance and safe local firmware import."""

import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
import uuid
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "import_lemonades_uefi", Path(__file__).resolve().parents[1] / "tools/import_lemonades_uefi.py")
IMPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMPORT)
GUID = "4138022F-06C7-4F79-9C94-7E33B511A4E7"


def pe_image():
    result = bytearray(128)
    result[:2] = b"MZ"
    struct.pack_into("<I", result, 0x3C, 64)
    result[64:68] = b"PE\0\0"
    struct.pack_into("<H", result, 68, 0xAA64)
    result.extend(b"/build/AARCH64/QcomPkg/Drivers/DisplayDxe/DisplayDxe/DEBUG/DisplayDxe.dll\0")
    return bytes(result)


def put(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def file_entry(directory, subtype="DXE driver", text="DisplayDxe", guid=GUID):
    put(directory / "info.txt", (f"Type: File\nSubtype: {subtype}\nText: {text}\n"
                                 f"File GUID: {guid}\nType: 07h\n").encode())
    put(directory / "body.bin", b"original file body")


def section_entry(directory, subtype, body):
    put(directory / "info.txt", f"Type: Section\nSubtype: {subtype}\nType: 10h\n".encode())
    put(directory / "body.bin", body)


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.dump = self.root / "extract/xbl_5.img.dump"
        self.module = self.dump / "volume/DisplayDxe"
        file_entry(self.module)
        section_entry(self.module / "pe", "PE32 image", pe_image())
        section_entry(self.module / "depex", "DXE dependency", b"\x06\x08")

    def test_metadata_keeps_first_type(self):
        self.assertEqual(IMPORT.fields(b"Type: File\nType: 07h\n")["Type"], "File")

    def test_rejects_absolute_traversal_and_inf_delimiters(self):
        for value in ("../escape", "/tmp/escape", "C:\\bad", "ok/../bad", "ok//bad", "bad|PE32", "bad\nraw"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                IMPORT.safe_relative(value)

    def test_nested_file_sections_are_not_owned_by_ancestor(self):
        ancestor = self.dump / "volume"
        file_entry(ancestor, "Freeform", "container")
        plan, modules, raw, skipped = IMPORT.output_plan(self.dump, "f" * 64)
        self.assertEqual(len(modules), 1)
        self.assertEqual(len(raw), 0)
        self.assertEqual(len(skipped), 1)
        self.assertIn(Path("QcomPkg/Drivers/DisplayDxe/DisplayDxe.efi"), plan)
        self.assertEqual(modules[0]["depex"]["original_hex"], "0608")

    def test_duplicate_code_section_is_rejected(self):
        section_entry(self.module / "pe2", "PE32 image", pe_image())
        with self.assertRaisesRegex(ValueError, "Duplicate PE32"):
            IMPORT.output_plan(self.dump, "f" * 64)

    def test_bad_pe_offset_and_non_arm_machine_are_rejected(self):
        malformed = bytearray(pe_image())
        struct.pack_into("<I", malformed, 0x3C, 0xFFFFFFFF)
        with self.assertRaisesRegex(ValueError, "Invalid PE"):
            IMPORT.image_machine(malformed, "PE32 image")
        malformed = bytearray(pe_image())
        struct.pack_into("<H", malformed, 68, 0x8664)
        put(self.module / "pe/body.bin", malformed)
        with self.assertRaisesRegex(ValueError, "Non-AArch64"):
            IMPORT.output_plan(self.dump, "f" * 64)

    def test_existing_conflict_prevents_all_writes(self):
        output = self.root / "output"
        put(output / "conflict", b"old")
        with self.assertRaisesRegex(ValueError, "Conflicting existing"):
            IMPORT.write_plan(output, {Path("new"): b"new", Path("conflict"): b"changed"})
        self.assertFalse((output / "new").exists())
        self.assertEqual((output / "conflict").read_bytes(), b"old")

    def test_symlink_input_and_output_refused(self):
        (self.module / "bad").symlink_to(self.module / "pe/body.bin")
        with self.assertRaisesRegex(ValueError, "Symlink"):
            IMPORT.dump_inventory(self.dump)
        output = self.root / "output"
        output.mkdir()
        (output / "escape").symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "Symlink"):
            IMPORT.write_plan(output, {Path("escape/new"): b"new"})

    def setup_manifest(self):
        raw = b"verified raw firmware fixture"
        put(self.root / "xbl_5.img", raw)
        put(self.root / "extract/xbl_5.img", raw)
        put(self.root / "extractor", b"host tool fixture")
        manifest = {"artifacts": {"xbl_5": {"file": "xbl_5.img", "bytes": len(raw),
                    "sha256": IMPORT.sha256(raw), "device_sha256_verified": True,
                    "source": "/dev/block/by-name/xbl_5"}}}
        put(self.root / "manifest.json", json.dumps(manifest).encode())
        config = self.dump / "config"
        file_entry(config, "Freeform", "uefiplat.cfg", "DDE58710-41CD-4306-DBFB-3FA90BB1D2DD")
        section_entry(config / "raw", "Raw",
                      b'[MemoryMap]\n0x9FC00000, 0x300000, "UEFI FD", AddMem, SYS_MEM, SYS_MEM_CAP, BsData, WRITE_BACK\n'
                      b'[ConfigParameters]\nNumCpus = 8\n')
        return IMPORT.sha256(b"host tool fixture")

    def test_empty_raw_section_and_truncated_depex(self):
        section = self.dump / "empty"
        put(section / "info.txt", b"Type: Section\nSubtype: Raw\nFull size: 4h (4)\nHeader size: 4h (4)\n")
        self.assertEqual(IMPORT.section_bytes(section, self.dump), b"")
        with self.assertRaisesRegex(ValueError, "Truncated"):
            IMPORT.decode_depex(b"\x02\x00")
        guid = uuid.UUID(GUID).bytes_le
        decoded = IMPORT.decode_depex(b"\x02" + guid + b"\x08")
        self.assertEqual(decoded[0]["guid"], GUID)

    def test_config_table_retains_memory_and_mmio_distinction(self):
        raw = (b'[MemoryMap]\n0x9FC00000, 0x300000, "UEFI FD", AddMem, SYS_MEM, SYS_MEM_CAP, BsData, WRITE_BACK\n'
               b'[RegisterMap]\n0x15000000, 0xD0000, "SMMU", AddDev, MMAP_IO, UNCACHEABLE, MmIO, NS_DEVICE\n')
        result = IMPORT.configuration_plan({Path("RawFiles/uefiplat.cfg"): raw})
        maps = json.loads(result[Path("uefiplat-memory-map.json")])["regions"]
        self.assertEqual(maps[0]["end_exclusive"], "0x9ff00000")
        self.assertEqual(maps[1]["section"], "RegisterMap")

    def test_source_copy_and_tool_hash_are_checked_before_execution(self):
        tool_hash = self.setup_manifest()
        with patch.object(IMPORT.subprocess, "run") as run:
            put(self.root / "extract/xbl_5.img", b"different")
            with self.assertRaisesRegex(ValueError, "input copy differs"):
                IMPORT.import_firmware(self.root, self.root / "extractor", tool_hash)
            run.assert_not_called()
        put(self.root / "extract/xbl_5.img", (self.root / "xbl_5.img").read_bytes())
        with patch.object(IMPORT.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "caller-pinned"):
                IMPORT.import_firmware(self.root, self.root / "extractor", "0" * 64)
            run.assert_not_called()

    def test_verified_import_preserves_code_depex_and_is_repeatable(self):
        tool_hash = self.setup_manifest()

        def extract(command, **kwargs):
            copied_image = Path(command[1])
            shutil.copytree(self.dump, copied_image.with_name("xbl_5.img.dump"))
            return subprocess.CompletedProcess(command, 0, b"parseVolumeHeader: unaligned volume\n")

        with patch.object(IMPORT.subprocess, "run", side_effect=extract):
            manifest = IMPORT.import_firmware(self.root, self.root / "extractor", tool_hash)
            IMPORT.import_firmware(self.root, self.root / "extractor", tool_hash)
        module = manifest["modules"][0]
        output = self.root / "uefi-binaries"
        self.assertEqual((output / module["efi"]).read_bytes(), pe_image())
        self.assertEqual((output / module["depex"]["file"]).read_bytes(), b"\x06\x08")
        self.assertFalse(manifest["hardware_boot_demonstrated"])
        self.assertFalse(manifest["targets_executed"])
        self.assertTrue(manifest["extraction"]["warnings"])


if __name__ == "__main__":
    unittest.main()
