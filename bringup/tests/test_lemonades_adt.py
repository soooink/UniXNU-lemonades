#!/usr/bin/env python3
"""Validate lemonades ADT against pinned FDT evidence and the actual DarwinBoot parser."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
DEVICE = ROOT / "devices/lemonades"
sys.path.insert(0, str(DEVICE / "scripts"))
sys.path.insert(0, str(ROOT / "tools"))
from lemonades_adt import Node, build_tree, decode, load_hardware, summary, u64, apply_smp_profile
from analyze_lemonades import fdt_nodes, reg_ranges
from test_lemonades_payload import function

HARDWARE = load_hardware()
DRAM = 0x2F9900000
SOURCE = ROOT / "sources/UniXNU/drivers/DarwinBoot/DarwinBootPkg/Driver/DarwinBoot.c"


def tree(**options):
    return build_tree(HARDWARE, dram_size=DRAM, **options)


class LemonadesAdtTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="lemonades-adt-check-")
        cls.work = Path(cls.tmp.name)
        cls.exe = cls.work / "darwin-adt"
        prelude = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define STATIC static
#define BOOLEAN int
#define CONST const
#define VOID void
#define CHAR8 char
#define UINT8 uint8_t
#define UINT32 uint32_t
#define UINT64 uint64_t
#define UINTN size_t
#define TRUE 1
#define FALSE 0
#define MAX_UINTN SIZE_MAX
#define ALIGN_VALUE(n,a) (((n)+(a)-1)&~((a)-1))
#define ScanMem8(buffer,length,value) memchr(buffer,value,length)
#define AsciiStrCmp strcmp
#define CompareMem memcmp
static uint32_t U32(const void *p) { uint32_t x; memcpy(&x,p,4); return x; }
static uint64_t U64(const void *p) { uint64_t x; memcpy(&x,p,8); return x; }
'''
        window = SOURCE.with_name("WindowSize.h").read_text()
        # Extract the real consumer, so a Python encoder/decoder cannot agree
        # on the same wrong wire format unnoticed.
        parser = function(SOURCE.read_text(), "AdtNode")
        main = r'''
int main(int argc, char **argv) {
  assert(argc==7);
  FILE *f=fopen(argv[1],"rb"); assert(f);
  assert(fseek(f,0,SEEK_END)==0);
  long length=ftell(f); assert(length>=0 && length<16*1024*1024);
  rewind(f);
  size_t size=(size_t)length, off=0, r=MAX_UINTN, t=MAX_UINTN;
  uint8_t *bytes=malloc(size?size:1); assert(bytes);
  assert(fread(bytes,1,size,f)==size); fclose(f);
  uint64_t window=0; int packed=0;
  int valid=AdtNode(bytes,size,&off,0,3,&r,&t,&window,&packed) && off==size;
  if (valid && atoi(argv[2])) {
    assert((r!=MAX_UINTN)==atoi(argv[3]));
    assert((t!=MAX_UINTN)==atoi(argv[4]));
    assert(packed==atoi(argv[5]));
    assert(window==strtoull(argv[6],NULL,0));
    if (r!=MAX_UINTN) assert(U64(bytes+r)==0 && U64(bytes+r+8)==0);
    if (t!=MAX_UINTN) assert(U64(bytes+t)==0 && U64(bytes+t+8)==0);
  }
  assert(valid==atoi(argv[2]));
  free(bytes); return 0;
}
'''
        source = cls.work / "darwin-adt.c"
        source.write_text(prelude + window + parser + main)
        subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", str(source), "-o", str(cls.exe)],
                       check=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def native(self, blob, valid=True, ram=False, trust=False, packed=False, window=0):
        path = self.work / "fixture.adt"
        path.write_bytes(blob)
        subprocess.run([str(self.exe), str(path), str(int(valid)), str(int(ram)),
                        str(int(trust)), str(int(packed)), str(window)], check=True)

    def test_minimal_native_tree(self):
        blob = tree().encode()
        parsed = decode(blob)
        self.assertEqual(parsed.encode(), blob)
        for path in ("/chosen", "/chosen/memory-map", "/cpus/cpu0", "/arm-io/intc",
                     "/defaults", "/options", "/product", "/buttons"):
            parsed.at(path)
        self.assertEqual(len(parsed.at("/cpus").children), 1)
        self.assertEqual(parsed.at("/cpus/cpu0").properties["compatible"], b"qcom,kryo\0")
        self.assertEqual(parsed.at("/defaults").properties["sleep-disabled"], struct.pack("<I", 1))
        self.assertNotIn(b"iPad", blob)
        self.assertNotIn(b"certificate-production-status", blob)
        self.assertNotIn("root-matching", parsed.at("/chosen").properties)
        self.assertEqual([n.name for n in parsed.at("/arm-io").children], ["intc"])
        self.native(blob)

    def test_smp_expansion_preserves_qualified_identity_and_hardware(self):
        profile = tree(ipad_identity=True, unique_chip_id=0x12345678, chip_id=0x164,
                       owned_memory_size=0x130000000, packed_data_ramdisk=True, trust_cache=True)
        before = profile.encode()
        self.assertEqual(apply_smp_profile(profile, HARDWARE), [i << 8 for i in range(8)])
        expanded = profile.encode()
        self.assertEqual(apply_smp_profile(profile, HARDWARE), [i << 8 for i in range(8)])
        self.assertEqual(profile.encode(), expanded)
        self.assertEqual(profile.at("/psci").properties["method"], b"smc\0")
        self.native(expanded, ram=True, trust=True, packed=True, window=0x130000000)
        restored = decode(expanded)
        restored.at("/cpus").children = restored.at("/cpus").children[:1]
        restored.children = [node for node in restored.children if node.name != "psci"]
        self.assertEqual(restored.encode(), before)

    def test_smp_rejects_foreign_gic_geometry(self):
        profile = tree()
        profile.at("/arm-io/intc").properties["redistributor-stride"] = u64(0x40000)
        before = profile.encode()
        with self.assertRaisesRegex(ValueError, "GIC"):
            apply_smp_profile(profile, HARDWARE)
        self.assertEqual(profile.encode(), before)

    def test_smp_rejects_unobserved_affinities_without_mutation(self):
        hardware = json.loads(json.dumps(HARDWARE))
        hardware["cpus"][-1]["affinity"] = 7
        profile = tree()
        before = profile.encode()
        with self.assertRaisesRegex(ValueError, "observed"):
            apply_smp_profile(profile, hardware)
        self.assertEqual(profile.encode(), before)

    def test_retained_boot_payload(self):
        path = ROOT / "out/lemonades/payload/files/EFI/UniXNU/Payloads/kernel.macho.adt"
        if not path.is_file():
            self.skipTest("XNU payload is not staged")
        metadata = json.loads((ROOT / "out/lemonades/payload/payload.json").read_text())["xnu"]
        blob = path.read_bytes()
        self.assertEqual(hashlib.sha256(blob).hexdigest(), metadata["adt_sha256"])
        seed = metadata.get("data_ramdisk")
        self.native(blob, ram=bool(seed), trust=metadata.get("trustcache", False),
                    packed=bool(seed and seed["packed"]),
                    window=metadata["owned_memory_bytes"] if metadata["kernel"].get("native_ufs") else 0)

    def test_ipad_userspace_profile_preserves_native_hardware(self):
        native = tree()
        profile = tree(ipad_identity=True, owned_memory_size=0x130000000)
        self.assertEqual(profile.properties["model"], b"iPad7,1\0")
        self.assertEqual(profile.properties["target-type"], b"J120\0")
        self.assertEqual(profile.properties["compatible"], native.properties["compatible"])
        self.assertEqual(profile.at("/arm-io").encode(), native.at("/arm-io").encode())
        self.assertEqual(profile.at("/cpus").encode(), native.at("/cpus").encode())
        self.assertEqual(profile.at("/product").properties["model"], native.at("/product").properties["model"])
        self.assertEqual(profile.at("/product").properties["artwork-device-idiom"], b"pad\0")
        self.assertEqual(profile.at("/product").properties["artwork-scale-factor"], struct.pack("<I", 2))
        self.native(profile.encode(), window=0x130000000)

    def test_hardware_against_verified_fdt(self):
        snapshot = HARDWARE["sources"]["evidence_snapshot"]
        path = ROOT / "out/device/lemonades" / snapshot / "running.dtb"
        raw = path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), HARDWARE["sources"]["running_dtb_sha256"])
        nodes = fdt_nodes(raw)
        banks = [{"base": int(b["address"], 16), "size": b["size_bytes"]}
                 for b in reg_ranges(nodes, "/memory")]
        self.assertEqual(banks, HARDWARE["memory_banks"])
        self.assertEqual(sum(b["size"] for b in banks), DRAM)
        for cpu in HARDWARE["cpus"]:
            actual = nodes[f'/cpus/cpu@{cpu["affinity"]:x}']
            self.assertEqual(int.from_bytes(actual["reg"], "big"), cpu["affinity"])
            self.assertEqual(actual["compatible"], b"qcom,kryo\0")
        parsed = decode(tree().encode())
        result = summary(parsed)
        gic = reg_ranges(nodes, "/soc/interrupt-controller@17a00000")
        self.assertEqual(int(result["gic_distributor"], 16), int(gic[0]["address"], 16))
        self.assertEqual(int(result["gic_redistributor"], 16), int(gic[1]["address"], 16))
        regions = struct.unpack("<4Q", parsed.at("/arm-io/intc").properties["reg"])
        self.assertEqual((regions[1], regions[3]), (gic[0]["size_bytes"], gic[1]["size_bytes"]))
        self.assertEqual(int(result["gic_redistributor_stride"], 16),
                         int.from_bytes(nodes["/soc/interrupt-controller@17a00000"]["redistributor-stride"], "big"))
        self.assertEqual(result["timebase_hz"], int.from_bytes(nodes["/soc/timer"]["clock-frequency"], "big"))
        self.assertEqual(nodes["/psci"]["method"], b"smc\0")
        self.assertEqual(struct.unpack_from(">I", nodes["/"]["qcom,msm-id"])[0],
                         HARDWARE["platform_chip_id"])

    def test_fresh_entropy(self):
        first, second = tree().at("/chosen").properties, tree().at("/chosen").properties
        self.assertEqual(len(first["random-seed"]), 64)
        self.assertNotEqual(first["random-seed"], second["random-seed"])

    def test_chrp_nvram(self):
        props = decode(tree().encode()).at("/chosen").properties
        image = props["nvram-proxy-data"]
        self.assertEqual(len(image), 8192)
        self.assertEqual(struct.unpack("<I", props["nvram-bank-size"])[0], len(image))
        self.assertEqual(struct.unpack_from("<I", image, 16)[0], zlib.adler32(image[20:]))
        for offset, name, blocks in ((0, b"nvram", 2), (32, b"common", 129),
                                     (2096, b"free", 381)):
            sig, checksum, actual_blocks, actual_name = struct.unpack_from("<BBH12s", image, offset)
            self.assertEqual((sig, actual_blocks, actual_name.rstrip(b"\0")), (0x70, blocks, name))
            raw = bytearray(image[offset:offset + 16])
            raw[1] = 0
            expected = sum(raw)
            while expected > 255:
                expected = (expected & 255) + (expected >> 8)
            self.assertEqual(checksum, expected)
        self.assertEqual(image[48:2096], bytes(2048))

    def test_all_sidecar_combinations_and_window(self):
        for mode in ("none", "dense", "packed"):
            for trust in (False, True):
                for window in (None, 0x10000000, 0x200000000):
                    with self.subTest(mode=mode, trust=trust, window=window):
                        parsed = tree(data_ramdisk=mode == "dense",
                                      packed_data_ramdisk=mode == "packed",
                                      trust_cache=trust, owned_memory_size=window)
                        self.native(parsed.encode(), ram=mode != "none", trust=trust,
                                    packed=mode == "packed", window=window or 0)
                        self.assertEqual("ephemeral-storage" in parsed.at("/chosen").properties, mode != "none")

    def test_identity_uuid_and_multi_cpu(self):
        value = tree(unique_chip_id=0x1122334455667788, chip_id=0x164,
                     root_match_volume_uuid="12345678-1234-5678-9012-123456789abc",
                     cpu_regs=tuple(range(0, 0x800, 0x100)))
        props = decode(value.encode()).at("/chosen").properties
        self.assertEqual(props["unique-chip-id"], bytes.fromhex("8877665544332211"))
        self.assertIn(b"12345678-1234-5678-9012-123456789ABC", props["root-matching"])
        self.assertEqual(value.at("/psci").properties["method"], b"smc\0")
        self.assertEqual(value.at("/cpus/cpu7").properties["state"], b"waiting\0")
        self.native(value.encode())

    def test_rejected_inputs(self):
        cases = [
            {"cpu_regs": ()}, {"cpu_regs": (0, 0)}, {"cpu_regs": (0x100, 0)},
            {"cpu_regs": (0, 1)}, {"cpu_regs": (0, 0x800)}, {"psci_method": "hvc"},
            {"owned_memory_size": 0}, {"owned_memory_size": 0x10001000},
            {"owned_memory_size": 0x200200000}, {"unique_chip_id": 1},
            {"unique_chip_id": 0, "chip_id": 0x164},
            {"unique_chip_id": 1 << 64, "chip_id": 1},
            {"unique_chip_id": 1, "chip_id": 1 << 32},
            {"root_match_volume_uuid": "<string>bad</string>"},
            {"root_match_volume_uuid": "00000000-0000-0000-0000-000000000000"},
            {"data_ramdisk": True, "packed_data_ramdisk": True},
        ]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                tree(**case)
        with self.assertRaises(ValueError):
            build_tree(HARDWARE, dram_size=0x300000000)

    def test_malformed_consumer_inputs(self):
        blob = tree().encode()
        malformed = [blob[:7], blob[:-1], blob + b"\0", struct.pack("<I", 0xFFFFFFFF) + blob[4:]]
        oversized = bytearray(blob)
        struct.pack_into("<I", oversized, 40, 0xFFFFFFFF)
        malformed.append(bytes(oversized))
        misplaced = tree()
        misplaced.properties["darwinboot-memory-size"] = u64(0x10000000)
        malformed.append(misplaced.encode())
        for size in (0, 0x10001000, 0x200200000):
            bad_window = tree()
            bad_window.at("/chosen").properties["darwinboot-memory-size"] = u64(size)
            malformed.append(bad_window.encode())
        bad_slot = tree()
        bad_slot.at("/chosen/memory-map").properties["TrustCache"] = bytes(8)
        malformed.append(bad_slot.encode())
        for index, item in enumerate(malformed):
            with self.subTest(index=index):
                self.native(item, valid=False)
        for item in malformed[:5]:
            with self.assertRaises(ValueError):
                decode(item)


if __name__ == "__main__":
    unittest.main(verbosity=2)
