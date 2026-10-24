#!/usr/bin/env python3
"""Build the official AES and verified VirtIO providers for lemonades root binding."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys

from build_lemonades_native_ufs import compile_from
ROOT = Path(__file__).resolve().parents[1]
UP = ROOT / "sources/UniXNU"
sys.path.insert(0, str(UP / "kits/NativePrelink"))
from native_prelink import macho, backed_offset, exports
TREE = ROOT / "out/lemonades-xnu/lemonades/tree"
OUT = TREE / "build/lemonades-storage-providers"
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path)
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    record = json.loads((TREE / "build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json").read_text().strip().rstrip(","))
    include = ["-I", str(TREE / ".cache/xnu-work/osfmk")]
    aes = OUT / "NativeAES.o"
    compile_from(record, UP / "drivers/NativeAES/NativeAES.cpp", aes, include)
    obj = aes.read_bytes()
    parsed = macho(obj)
    sy = next(at for cmd, at, _ in parsed["commands"] if cmd == 2)
    so, count, st, _ = struct.unpack_from("<4I", obj, sy + 8)
    symbols = []
    for i in range(count):
        ix, kind, _, _, value = struct.unpack_from("<IBBHQ", obj, so + 16*i)
        symbols.append((obj[st+ix:obj.index(b"\0", st+ix)].decode(), value, kind))
    table = next(v for n, v, _ in symbols if n == "__ZTV9NativeAES")
    reloc = {}
    for seg in parsed["segments"]:
        for sec in seg["sections"]:
            if sec["va"] <= table < sec["va"] + sec["size"]:
                at, n = struct.unpack_from("<II", obj, sec["command_offset"] + 56)
                for i in range(n):
                    address, word = struct.unpack_from("<II", obj, at + i*8)
                    if word >> 27 & 1 and word >> 28 == 0 and word >> 25 & 3 == 3:
                        reloc[sec["va"] + address] = symbols[word & 0xffffff][0]
    names = [reloc.get(table + 16 + 8*i) for i in range(181)]
    assert all(names) and table + 16 + 181*8 not in reloc
    # The pinned upstream header describes ordinary iOS slots. Map only this
    # subclass's reviewed overrides back to their declared original methods.
    overrides = {0, 1, 7, 86, 111, 117, 168, 169, 170, 171, 172}
    assert {i for i, n in enumerate(names) if "9NativeAES" in n} == overrides
    names = [n.replace("9NativeAES", "16IOAESAccelerator") if i in overrides else n
             for i, n in enumerate(names)]
    candidate = ROOT / "out/lemonades-xnu/lemonades/kernel/qemu-native-ufs-trace.macho"
    data = candidate.read_bytes()
    plan = json.loads(candidate.with_suffix(".json").read_text())
    assert sha(candidate) == plan["candidate_sha256"]
    assert plan["original_sha256"] == "f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7"
    image = macho(data)
    byname = {n: a for a, ns in exports(data, image).items() for n in ns}
    sections = [e for e in plan["extents"] if e["module"] == "com.apple.iokit.IOCryptoAcceleratorFamily"]
    text = next(e for e in sections if e["segment"] == "__TEXT_EXEC")
    const = next(e for e in sections if e["segment"] == "__DATA_CONST")
    def read(a, n):
        at = backed_offset(image["segments"], a, n, len(data))
        return data[at:at+n]
    def address_returned(a):
        adrp, add, ret = struct.unpack("<3I", read(a, 12))
        if adrp & 0x9f00001f != 0x90000000 or add & 0xffc003ff != 0x91000000 or ret != 0xd65f03c0:
            return None
        imm = (adrp >> 5 & 0x7ffff) << 2 | (adrp >> 29 & 3)
        if imm & 0x100000: imm -= 0x200000
        return (a & ~4095) + imm*4096 + (add >> 10 & 4095)
    assert hashlib.sha256(read(text["va"], text["size"])).hexdigest() == plan["original_executable_sha256"]["com.apple.iokit.IOCryptoAcceleratorFamily"]
    inherited = [i for i, n in enumerate(names) if n in byname]
    assert len(inherited) == 162
    blob = read(const["va"], const["size"])
    found = []
    for offset in range(0, len(blob) - 183*8 + 1, 8):
        if blob[offset:offset+16] != bytes(16): continue
        pointers = struct.unpack_from("<181Q", blob, offset+16)
        if not all(pointers[i] == byname[names[i]] for i in inherited): continue
        if not all(text["va"] <= pointers[i] < text["va"]+text["size"] for i in range(181) if i not in inherited): continue
        algorithm = address_returned(pointers[168])
        if algorithm is not None and read(algorithm, 8) == b"AES-CBC\0":
            found.append((const["va"]+offset, pointers))
    assert len(found) == 1, "Original AES dispatch is not uniquely identified"
    table, pointers = found[0]
    meta = address_returned(pointers[7])
    service = byname["__ZN9IOService10gMetaClassE"]
    static = {"candidate_sha256": sha(candidate), "original_sha256": plan["original_sha256"],
              "vtable": hex(table), "aes_metaclass": hex(meta), "service_metaclass": hex(service),
              "method_slots": 181, "inherited_kernel_matches": 162,
              "annotation_source": str(UP/"drivers/NativeAES/OriginalAESABI.h"),
              "annotation_sha256": sha(UP/"drivers/NativeAES/OriginalAESABI.h"),
              "methods": [{"slot":i, "reference_names":[n], "candidate_target":hex(pointers[i]),
                           "kernel_names":[n] if i in inherited else []} for i,n in enumerate(names)]}
    (OUT/"aes-static.json").write_text(json.dumps(static,indent=2)+"\n")
    if not args.snapshot:
        print(json.dumps({k:v for k,v in static.items() if k != "methods"},indent=2))
        return
    snapshot = json.loads(args.snapshot.read_text())
    assert snapshot["kernel_sha256"] == sha(candidate) and not snapshot["bounded_timeout_interrupted"]
    native_symbols = subprocess.check_output(["xcrun","nm","-n",candidate],text=True)
    bsd_init = next(int(line.split()[0],16) for line in native_symbols.splitlines()
                    if line.split()[-1:] == ["_bsd_init"])
    assert int(snapshot["pc"],16) == bsd_init
    def observed(a):
        for key, value in snapshot["memory"].items():
            start, length = (int(v,16) for v in key.split(":"))
            if start == a and length >= 40: return bytes.fromhex(value)
        raise ValueError(f"Need live class metadata at {a:#x}")
    actual, base = observed(meta), observed(service)
    parent = struct.unpack_from("<Q",actual,16)[0]
    intermediate = observed(parent)
    assert struct.unpack_from("<Q",intermediate,16)[0] == service
    assert [struct.unpack_from("<I",v,32)[0] for v in (actual,intermediate,base)] == [0x120,0x88,0x88]
    regs={k:int(v,16) for k,v in snapshot["system_registers"].items()}
    assert regs["TCR_EL1"]>>14&3 == 0 and regs["TCR_EL1"]>>30&3 == 2
    assert regs["SCTLR_EL1"]&1 and regs["TTBR0_EL1"] and regs["TTBR1_EL1"]
    audit={**static,"live_native_4k":True,"live_metaclasses":{"IOAESAccelerator":hex(meta)},
           "snapshot_sha256":sha(args.snapshot)}
    (OUT/"aes-interface-audit.json").write_text(json.dumps(audit,indent=2)+"\n")
    binding=(UP/"scripts/build-native-aes-bindings.py").read_text()
    binding=binding.replace("ROOT = Path(__file__).resolve().parents[1]",f"ROOT = Path({str(UP)!r})")
    binding=binding.replace("ROOT / 'build/image4-ignition/aes-interface-audit.json'",f"Path({str(OUT/'aes-interface-audit.json')!r})")
    binding=binding.replace("ROOT / 'build/native-prelink/native-defaults-candidate.macho'",f"Path({str(candidate)!r})")
    binding=binding.replace("ROOT / 'build/native-prelink/native-defaults-candidate.json'",f"Path({str(candidate.with_suffix('.json'))!r})")
    script=OUT/"bind-aes.py";script.write_text(binding)
    subprocess.run([sys.executable,script,"--objects-dir",OUT],check=True)
    shutil.copyfile(OUT/"bindings.json",OUT/"aes-bindings.json")
    for suffix in (".S", ".o"):
        shutil.copyfile(OUT/("original-bindings"+suffix),OUT/("aes-original-bindings"+suffix))
    virtio=OUT/"NativeVirtioBlock.o"
    compile_from(record,UP/"drivers/NativeVirtioBlock/NativeVirtioBlock.cpp",virtio,
                 include+["-I",str(ROOT/"out/lemonades/storage-abi/include"),"-I",str(UP/"kits/VerifiedRoot/include"),
                          "-DNATIVE_VERIFIED_BLOCK=1","-DNATIVE_VERIFIED_BLOCK_MULTI_POLICY=1"])
    binding=(UP/"scripts/build-native-virtio-bindings.py").read_text()
    binding=binding.replace("ROOT = Path(__file__).resolve().parents[1]",f"ROOT = Path({str(UP)!r})")
    binding=binding.replace("ROOT / 'build/storage-abi/interface-audit.json'",f"Path({str(ROOT/'out/lemonades/storage-abi/interface-audit.json')!r})")
    binding=binding.replace("['xcrun', 'c++filt']","['xcrun', 'c++filt', '-n']")
    binding=binding.replace("ROOT / 'build/native-prelink/native-apfs-load-positive.macho'",f"Path({str(ROOT/'out/lemonades-xnu/lemonades/kernel/qemu-storage-apfs.macho')!r})")
    binding=binding.replace("if kernel_path.exists() and","if not kernel_path.exists() or")
    script=OUT/"bind-virtio.py";script.write_text(binding)
    subprocess.run([sys.executable,script,"--directory",OUT],check=True)
    shutil.copyfile(OUT/"bindings.json",OUT/"virtio-bindings.json")
    # Like upstream's RAM/VirtIO co-link, share one exact original class alias
    # set. The complete VirtIO object remains linked and runtime exercised.
    ufs = json.loads((TREE/"build/native-ufs/bindings.json").read_text())["bindings"]
    virtio_bindings = json.loads((OUT/"virtio-bindings.json").read_text())["bindings"]
    assert virtio_bindings == ufs, "Storage transports disagree on original class imports"
    subprocess.run(["xcrun","ar","d",OUT/"libNativeVirtioBlock.a","original-bindings.o"],check=True)
    inputs=[Path(__file__),UP/"drivers/NativeAES/NativeAES.cpp",UP/"drivers/NativeAES/OriginalAESABI.h",
            UP/"drivers/NativeVirtioBlock/NativeVirtioBlock.cpp",UP/"drivers/NativeVirtioBlock/VerifiedBlockPolicy.h",
            UP/"scripts/build-native-aes-bindings.py",UP/"scripts/build-native-virtio-bindings.py"]
    report={"sources":{str(p.relative_to(ROOT)):sha(p) for p in inputs},
            "aes_archive_sha256":sha(OUT/"libNativeAES.a"),
            "virtio_archive_sha256":sha(OUT/"libNativeVirtioBlock.a"),
            "original_storage_aliases_shared_with_native_ufs": ufs,
            "aes_abi":audit,"aes_bindings":json.loads((OUT/"aes-bindings.json").read_text()),
            "virtio_bindings":json.loads((OUT/"virtio-bindings.json").read_text()),
            "aes_runtime_tested":False,"root_binding_runtime_tested":False}
    (OUT/"build-report.json").write_text(json.dumps(report,indent=2)+"\n")
    print("Built complete upstream NativeAES and signed-policy NativeVirtioBlock")


if __name__=="__main__":
    main()
