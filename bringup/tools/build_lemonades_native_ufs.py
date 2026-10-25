#!/usr/bin/env python3
"""Adapt the official complete read-only UFS block provider, preserving its ABI."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
TREE=ROOT/"out/lemonades-xnu/lemonades/tree"
UP=ROOT/"sources/UniXNU"
OUT=TREE/"build/native-ufs"

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()

def compile_from(record,source,obj,extra):
    command=[]; arguments=record["arguments"]; i=0
    while i<len(arguments):
        v=arguments[i]
        if v==record["file"]: command.append(str(source))
        elif v=="-o": command+=["-o",str(obj)]; i+=1
        elif v in ("-MF","-MJ"): i+=1
        elif v=="-Xclang" and arguments[i+1].startswith("-W"): i+=1
        elif not v.startswith("-W") and v not in ("-MD","-MP"): command.append(v)
        i+=1
    command+=["-Wall","-Wextra","-Werror","-Wno-unused-parameter",
        "-Wno-c99-designator","-Wno-reorder-init-list","-Wno-deprecated-enum-enum-conversion",
        "-mgeneral-regs-only",*extra]
    obj.with_suffix(".command.json").write_text(json.dumps(command,indent=2)+"\n")
    result=subprocess.run(command,cwd=record["directory"],text=True,capture_output=True)
    obj.with_suffix(".log").write_text(result.stdout+result.stderr)
    if result.returncode: raise SystemExit(result.stdout+result.stderr)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile",choices=("qemu","phone"),required=True)
    args=parser.parse_args()
    OUT.mkdir(parents=True,exist_ok=True)
    source=(UP/"drivers/NativeUfs/NativeUfs.cpp").read_text()
    # Keep the qualified root path and add the separately pinned Data store.
    header=source[:source.index("static uint32_t read32")]
    for line in ("  void inspect (void);\n","  void adoptAndRead (unsigned level);\n",
                 "  void dumpFirmwareList (void);\n","  void inspectSmmu (void);\n",
                 "  void inspectContextBanks (void);\n",
                 "  static bool waitSet (uintptr_t base, unsigned offset, uint32_t mask, unsigned loops);\n"):
        assert line in header; header=header.replace(line,"")
    header=header.replace('#include "GccUfs.h"','#include <IOKit/IODeviceTreeSupport.h>')
    header=header.replace('#include "SmmuTakeover.h"','#include "LemonadesSmmuTakeover.h"')
    header+='extern "C" void umi_native_ufs_checkpoint(void);\n'
    header+='extern "C" unsigned long gPhysBase, gPhysSize;\n'
    probe=(ROOT/"devices/lemonades/package/LemonadesUfsProbe.cpp").read_text()
    helpers=probe[probe.index("static uint32_t umi_mmio_upper_seen;"):probe.index('#include "UmiUfsRead.inc"')]
    helpers=helpers.replace("static uintptr_t map(","static uintptr_t mapPhys(")
    helpers+="""
static void write32(uintptr_t base,unsigned offset,uint32_t value)
{
  __asm__ volatile("dsb sy\\n\\tstr %w0,[%1]\\n\\tdsb sy" ::
    "r"(value),"r"(base+offset) : "memory");
}
"""
    match=source[source.index("static bool contains"):source.index("bool NativeUfs::waitSet")]
    match=match.replace("qcom,sm8550-ufshc","qcom,sm8250-ufshc")
    transport=source[source.index("namespace {\n#include \"RootTransportLayout.h\""):
                     source.index("// Bring the live controller up for reading:")]
    transport+='#include "LemonadesNativeUfsHost.inc"\n}\n'
    layout=source[source.index("namespace {\nstatic uint32_t be32w"):source.index("// ---- Persistent Data store window")]
    # be32w is only used by the excluded legacy panic probe.
    layout=layout[layout.index('#include "RootLayout.h"'):]
    layout="namespace {\n"+layout
    block=source[source.index("// One read-only window"):source.index("// Memory snapshot (native-ufs-probe=13)")]
    block=block.replace("  native_ufs_root_failure = reason;",
                        "  native_ufs_root_failure = reason;\n  umi_native_ufs_checkpoint();")
    block=block.replace("  gPendingProvider->release ();",
                        "  umi_native_ufs_checkpoint();\n  gPendingProvider->release ();")
    block+='#include "LemonadesNativeUfsTrace.inc"\n'
    start=r'''
bool NativeUfs::start(IOService *provider)
{
  unsigned rootMode=0, diagnostic=0;
  PE_parse_boot_argn("native-ufs-root",&rootMode,sizeof(rootMode));
  PE_parse_boot_argn("native-ufs-diagnostics",&diagnostic,sizeof(diagnostic));
  native_ufs_probe_requested=rootMode;
  if (rootMode!=1 || !OSDynamicCast(IOPlatformExpertDevice,provider)) return false;
  if (!UMI_UFS_PHONE) {
    IOLog("NativeUfs: QEMU hardware access skipped\n");
    umi_native_ufs_checkpoint();
    return false;
  }
  gRootDiagnosticEnabled=diagnostic==1;
  return startRoot(provider);
}
'''
    root=source[source.index("// Boot the root image's windows as block devices."):]
    first=root.index("  gStoreGeometry ="); last=root.index("  const char *names",first)
    # Use the GPT/root geometry already validated by findRootLayout.
    for step in (1,2,3):
        needle=f"  native_ufs_root_step = {step};\n"
        root=root.replace(needle,needle+"  umi_native_ufs_checkpoint();\n")
    needle="  native_ufs_root_step = 3;\n"
    # The baseline geometry is this device's measured userdata, not the
    # upstream sample's: the source constant pair is the umi baseline.
    import tomllib
    board_path=None
    for candidate in (ROOT/"devices/lemonades/board.toml", ROOT/"board.toml"):
        if candidate.is_file():
            board_path=candidate; break
    assert board_path, "board.toml not found"
    board_userdata=tomllib.loads(board_path.read_text())["userdata"]
    userdata_first=int(board_userdata["first_lba"]); userdata_last=int(board_userdata["last_lba"])
    root=root.replace(needle,needle+'''  if (layout->userdataFirst!=0x2c0000 || layout->userdataLast!=0x3b51ffa) {
    rootDiagnosticFailure("userdata differs from lemonades baseline");
    IOFree(layout,sizeof(RootLayout));
    return false;
  }
''').replace("0x2c0000",hex(userdata_first)).replace("0x3b51ffa",hex(userdata_last))
    generated=OUT/"NativeUfs.cpp"
    store_source=ROOT/"devices/lemonades/package/data-store/UfsStore.inc"
    store=store_source.read_text()
    for declaration in ("constexpr uint64_t kLogReserveBlocks = 8192;\n", "constexpr uint64_t kExportBlocks = 65536;\n", "uint64_t gLogRegionFirst, gLogRegionBlocks;\n"):
        assert store.count(declaration)==1
        store=store.replace(declaration,"")
    (OUT/"LemonadesUfsStore.inc").write_text(store)
    generated.write_text(header+helpers+match+transport+layout+'#include "LemonadesUfsStore.inc"\n'+block+start+root)
    for p in (UP/"drivers/NativeUfs").glob("*.h"): shutil.copyfile(p,OUT/p.name)
    commands=(OUT/"RootCommands.h").read_text()
    old_signature="uint32_t blocks, const void *src)\n"
    assert commands.count(old_signature)==1
    commands=commands.replace(old_signature,"uint32_t blocks, const void *src, bool fua = false)\n")
    assert commands.count("uint8_t cdb[10] = { 0x2a, 0,")==1
    commands=commands.replace("uint8_t cdb[10] = { 0x2a, 0,", "uint8_t cdb[10] = { 0x2a, uint8_t (fua ? 8 : 0),")
    (OUT/"RootCommands.h").write_text(commands)
    for name in ("LemonadesNativeUfsHost.inc","LemonadesNativeUfsTrace.inc","LemonadesSmmuTakeover.h"):
        data=(ROOT/"devices/lemonades/package"/name).read_text()
        data=data.replace('#include "Umi','#include "Lemonades').replace('#include "UmiUfsRead.inc"','#include "LemonadesUfsRead.inc"')
        (OUT/name).write_text(data)
    shutil.copyfile(UP/"drivers/NativeVirtioBlock/VerifiedBlockPolicy.h",OUT/"VerifiedBlockPolicy.h")
    shutil.copyfile(UP/"drivers/NativeUfs/LICENSE",OUT/"LICENSE")
    # Populate the storage ABI headers from the IOStorageFamily feed (the
    # umi flow prepared out/.../storage-abi by hand once).
    abi = ROOT/"out/lemonades/storage-abi/include"
    fam = ROOT/"out/lemonades-xnu/IOStorageFamily"
    if not (fam/"IOBlockStorageDevice.h").is_file():
        fam.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git","clone","-q","https://github.com/apple-oss-distributions/IOStorageFamily.git",str(fam)],check=True)
        subprocess.run(["git","-C",str(fam),"checkout","-q","e45fbe30a7879e0b16e26dddb78538f1b00e0bff"],check=True)
    headers = abi/"IOKit/storage"
    headers.mkdir(parents=True, exist_ok=True)
    for path in fam.glob("*.h"):
        shutil.copyfile(path, headers/path.name)
    sdk = Path(subprocess.check_output(["xcrun","--sdk","macosx","--show-sdk-path"],text=True).strip())
    shutil.copyfile(sdk/"usr/include/TargetConditionals.h", abi/"TargetConditionals.h")
    rec=TREE/"build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json"
    record=json.loads(rec.read_text().strip().rstrip(","))
    compile_from(record,generated,OUT/"NativeUfs.o",[
        "-I",str(ROOT/"out/lemonades/storage-abi/include"),
        "-I",str(TREE/".cache/xnu-work/osfmk"),
        "-I",str(UP/"kits/VerifiedRoot/include"),
        "-DNATIVE_VERIFIED_BLOCK=1","-DNATIVE_VERIFIED_BLOCK_MULTI_POLICY=1",
        "-DUMI_UFS_PHONE="+str(int(args.profile=="phone")),
        # Xcode 26 promotes IOStorageFamily macro-diagnostics (keyword macro
        # parameters) to errors; the umi-qualified source builds clean on the
        # umi-era toolchain.
        "-Wno-error"])
    if not __import__('os').environ.get('LEMONADES_SKIP_STORAGE_BINDING'):
        # The upstream relocation audit checks every slot of the compiled subclass.
        binding=(UP/"scripts/build-native-virtio-bindings.py").read_text()
        binding=binding.replace("ROOT = Path(__file__).resolve().parents[1]",f"ROOT = Path({str(UP)!r})")
        binding=binding.replace("['NativeVirtioBlock', 'NativeRamBlock']","['NativeUfsBlock']")
        binding=binding.replace("default='NativeVirtioBlock'","default='NativeUfsBlock'")
        binding=binding.replace("ROOT / 'build/storage-abi/interface-audit.json'",repr(str(ROOT/"out/lemonades/storage-abi/interface-audit.json")))
        binding=binding.replace("("+repr(str(ROOT/"out/lemonades/storage-abi/interface-audit.json"))+").read_text()",
                                "Path("+repr(str(ROOT/"out/lemonades/storage-abi/interface-audit.json"))+").read_text()")
        binding=binding.replace("out / (component + '.o')","out / 'NativeUfs.o'")
        # Apple's c++filt otherwise strips the Mach-O underscore a second time.
        binding=binding.replace("['xcrun', 'c++filt']","['xcrun', 'c++filt', '-n']")
        binding=binding.replace("ROOT / 'build/native-prelink/native-apfs-load-positive.macho'",
                                f"Path({str(ROOT/'out/lemonades-xnu/lemonades/kernel/qemu-storage-apfs.macho')!r})")
        # Require the referenced qualification artifact, unlike the upstream's optional cache.
        binding=binding.replace("if kernel_path.exists() and","if not kernel_path.exists() or")
        binding=binding.replace("out / ('lib' + component + '.a')","out / 'libNativeUfs.a'")
        script=OUT/"bind-storage.py"; script.write_text(binding)
        subprocess.run([sys.executable,str(script),"--directory",str(OUT)],check=True)
    else:
        # No QEMU qualification on this path. The base-class imports bind to
        # the pinned addresses recovered from the hardware-proven prelinked
        # kernel (bringup/storage-bindings.json: same donor kernelcache, same
        # slide, same pinned emit_prelink, so the donor layout is identical
        # for every profile). The freshly compiled public-source reference
        # object proves the pinned record's dispatch identity slot by slot.
        sys.path.insert(0, str(UP / "kits/NativePrelink"))
        import native_prelink as np
        reference = OUT / "IOBlockStorageDevice-reference.o"
        # Annotation instrument only; never linked or executed, so warnings
        # stay non-fatal on newer toolchains.
        compile_from(record, fam / "IOBlockStorageDevice.cpp", reference, [
            "-I", str(ROOT / "out/lemonades/storage-abi/include"),
            "-I", str(TREE / ".cache/xnu-work/osfmk"),
            "-Wno-deprecated-declarations", "-Wno-unnecessary-virtual-specifier",
            "-Wno-error"])
        blob = reference.read_bytes()
        rimg = np.macho(blob)
        roff = next(at for cmd, at, size in rimg['commands'] if cmd == 2)
        rsy, rcount, rst, _ = struct.unpack_from('<4I', blob, roff + 8)
        rsymbols = []
        for i in range(rcount):
            ix, kind, _, _, value = struct.unpack_from('<IBBHQ', blob, rsy + i * 16)
            rsymbols.append((blob[rst + ix:blob.index(b'\0', rst + ix)].decode(), value, kind))
        rvtable = next(v for name, v, kind in rsymbols if name == '__ZTV20IOBlockStorageDevice')
        rloc = {}
        for segment in rimg['segments']:
            for section in segment['sections']:
                if section['va'] <= rvtable < section['va'] + section['size']:
                    rlo, rlc = struct.unpack_from('<II', blob, section['command_offset'] + 56)
                    for i in range(rlc):
                        address, word = struct.unpack_from('<II', blob, rlo + i * 8)
                        if word >> 27 & 1 and word >> 28 == 0 and word >> 25 & 3 == 3:
                            rloc[section['va'] + address] = rsymbols[word & 0xffffff][0]
        methods = []
        at = rvtable + 16
        while at in rloc:
            methods.append(rloc[at]); at += 8
        if len(methods) != 190 or methods.count('___cxa_pure_virtual') != 14:
            raise SystemExit('public IOBlockStorageDevice dispatch shape changed: %d slots' % len(methods))
        # The CI workspace only carries tools/tests plus the device repository
        # (a symlink at devices/lemonades), so the record lives device-side.
        # The record must match the image family that will be flashed: the
        # storage prelink adds the APFS/compression roots and moves the
        # exported method addresses, so LEMONADES_STORAGE_RECORD selects it.
        record_name=__import__('os').environ.get('LEMONADES_STORAGE_RECORD') or 'storage-bindings.json'
        record_path=None
        for candidate in (ROOT/"devices/lemonades/bringup"/record_name, ROOT/"bringup"/record_name):
            if candidate.is_file():
                record_path=candidate; break
        assert record_path, f"storage binding record {record_name} not found"
        pinned = json.loads(record_path.read_text())
        if pinned['donor_kernelcache_sha256'] != 'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7':
            raise SystemExit('pinned storage record provenance mismatch')
        for i, name in enumerate(methods):
            expect = pinned['slot_names_from_merged_kernel_exports'][i]
            if expect is None:
                continue
            if name != expect and not (isinstance(expect, list) and name in expect):
                raise SystemExit(f'reference dispatch slot {i} disagrees with the pinned storage record')
        nu = (OUT / "NativeUfs.o").read_bytes()
        nimg = np.macho(nu)
        noff = next(at for cmd, at, size in nimg['commands'] if cmd == 2)
        nsy, ncount, nst, _ = struct.unpack_from('<4I', nu, noff + 8)
        undefined = []
        for i in range(ncount):
            ix, kind, _, _, value = struct.unpack_from('<IBBHQ', nu, nsy + i * 16)
            if kind == 1:
                undefined.append(nu[nst + ix:nu.index(b'\0', nst + ix)].decode())
        base = [n for n in undefined if 'IOBlockStorageDevice' in n]
        special = {'__ZTV20IOBlockStorageDevice': int(pinned['vtable'], 16),
                   '__ZN20IOBlockStorageDevice10gMetaClassE': int(pinned['original_metaclass'], 16),
                   '__ZN20IOBlockStorageDeviceC2EPK11OSMetaClass': int(pinned['original_protected_constructor'], 16),
                   '__ZN20IOBlockStorageDeviceD2Ev': int(pinned['original_base_destructor'], 16)}
        bindings = {}
        for name in base:
            if re.search(r'IOBlockStorageDeviceD[01]Ev$', name):
                raise SystemExit('concrete driver must not invoke abstract destruction: ' + name)
            if name in special:
                bindings[name] = special[name]; continue
            if name not in methods:
                raise SystemExit('unqualified original storage import: ' + name)
            bindings[name] = int(pinned['slot_targets'][methods.index(name)], 16)
        asm = OUT / "original-bindings.S"
        asm.write_text(''.join(f'.globl {n}\n.set {n}, {v:#x}\n' for n, v in sorted(bindings.items())))
        subprocess.run(["xcrun", "clang", "-target", "arm64-apple-ios17.0", "-c", str(asm),
                        "-o", str(OUT / "original-bindings.o")], check=True)
        (OUT / "bindings.json").write_text(json.dumps(dict(
            mode='pinned static bindings (no QEMU audit)', donor=pinned['donor_kernelcache_sha256'],
            slide=pinned['slide'], vtable=pinned['vtable'], methods_checked=190,
            dispatch_slots_verified=sum(n is not None for n in pinned['slot_names_from_merged_kernel_exports']),
            bindings={n: hex(v) for n, v in sorted(bindings.items())},
            hardware_tested=False, actual_io_qualified=False), indent=2) + '\n')
        # Empty owner-root policy stub: vr_* always refuses and the policy
        # table is empty, so configureVerification() takes its "no policies"
        # path. vr_xnu_crypto stays null; nothing dereferences it then.
        stub=OUT/"owner-root-stub.c"
        stub.write_text(
          '#include <stddef.h>\n'
          '#include <stdint.h>\n'
          '#include "verified_root.h"\n'
          '#include "VerifiedBlockPolicy.h"\n'
          'extern const struct vr_crypto vr_xnu_crypto = { NULL, NULL };\n'
          'extern const uint8_t verified_root_key[395] = { 0 };\n'
          'extern const NativeVerifiedBlockPolicy verified_root_policies[1] = { { NULL, 0 } };\n'
          'extern const uint64_t verified_root_policy_count = 0;\n'
          'int vr_open(const uint8_t *e, size_t n, const uint8_t k[395], uint64_t g,'
          ' const struct vr_crypto *c, struct vr_view *v) { (void)e;(void)n;(void)k;(void)g;(void)c;(void)v; return VR_KEY; }\n'
          'int vr_verify_block(const struct vr_view *v, uint64_t b, const void *p, size_t s,'
          ' const struct vr_crypto *c) { (void)v;(void)b;(void)p;(void)s;(void)c; return VR_SIGNATURE; }\n'
          '// weak-declared in NativeUfs.cpp; Apple ld wants a definition in the final image\n'
          'extern "C" void boot_progress_poll(void) {}\n')
        sdk=subprocess.check_output(["xcrun","--sdk","iphoneos","--show-sdk-path"],text=True).strip()
        result=subprocess.run(["xcrun","clang","-x","c++","-target","arm64-apple-ios17.0","-isysroot",sdk,
                        "-I",str(abi),"-I",str(UP/"kits/VerifiedRoot/include"),"-I",str(OUT),
                        "-Wno-error",
                        "-c",str(stub),"-o",str(OUT/"owner-root-stub.o")],capture_output=True,text=True)
        if result.returncode:
            print(result.stdout[-2000:],end=''); print(result.stderr[-2000:],file=sys.stderr,end='')
            raise SystemExit(result.returncode)
        archive=OUT/"libNativeUfs.a"
        archive.unlink(missing_ok=True)
        subprocess.run(["xcrun","ar","rcs",str(archive),str(OUT/"NativeUfs.o"),
                        str(OUT/"original-bindings.o"),str(OUT/"owner-root-stub.o")],check=True)
    report={"profile":args.profile,"disk_write_path":True,"verified_block_policies":True,
        "data_store_source_sha256":sha(store_source),"data_store_generated_sha256":sha(OUT/"LemonadesUfsStore.inc"),
        "commands_sha256":sha(OUT/"RootCommands.h"),
        "generated_source_sha256":sha(generated),"object_sha256":sha(OUT/"NativeUfs.o"),
        "archive_sha256":sha(OUT/"libNativeUfs.a"),
        "upstream_sources":{str(p.relative_to(UP)):sha(p) for p in
            [UP/"drivers/NativeUfs/NativeUfs.cpp",UP/"scripts/build-native-virtio-bindings.py",
             *sorted((UP/"drivers/NativeUfs").glob("*.h"))]},
        "device_sources":{str(p.relative_to(ROOT)):sha(p) for p in
            [Path(__file__),store_source,*(ROOT/"devices/lemonades/package"/n for n in
             ("LemonadesNativeUfsHost.inc","LemonadesNativeUfsTrace.inc","LemonadesSmmuTakeover.h","LemonadesUfsProbe.cpp"))]},
        "bindings":json.loads((OUT/"bindings.json").read_text()) if (OUT/"bindings.json").exists() else
                 {"note":"binding skipped (LEMONADES_SKIP_STORAGE_BINDING); base symbols resolve at the kernel link"},
        "hardware_tested":False,"root_mounted":False}
    (OUT/"build-report.json").write_text(json.dumps(report,indent=2)+"\n")
    print("Built official NativeUfsBlock with lemonades host adapter and qualified original storage bindings")

if __name__=="__main__": main()
