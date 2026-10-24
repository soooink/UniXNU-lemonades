#!/usr/bin/env python3
"""Build sheng's original Data/display implementations in the lemonades build tree."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys

from build_lemonades_native_ufs import compile_from

ROOT = Path(__file__).resolve().parents[1]
UP = ROOT / "sources/UniXNU"
SHENG = ROOT / "sources/UniXNU-sheng"
TREE = ROOT / "out/lemonades-xnu/lemonades/tree"
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()


def run(command):
    subprocess.run([str(v) for v in command], check=True)


def ram():
    out = TREE / "build/native-ram-block"
    out.mkdir(parents=True, exist_ok=True)
    record = json.loads((TREE / "build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json").read_text().strip().rstrip(","))
    source = ROOT / "devices/lemonades/package/data-store/NativeRamBlock/NativeRamBlock.cpp"
    generated = out / "NativeRamBlock.cpp"
    missing = []
    def absent_store(match):
        declaration = match.group()
        name = re.search(r"\b(native_ufs_store_\w+)\s*\(", declaration).group(1)
        missing.append(name)
        # Same typed-null treatment as the diagnostic's optional imports.
        # This build has the genuine RAM writer, but no physical store provider.
        return declaration + f"\n#define {name} (*(__typeof__(&{name}))0)\n"
    # Original direct-on-UFS path: keep all six genuine provider imports.
    generated.write_bytes(source.read_bytes())
    compile_from(record, generated, out / "NativeRamBlock.o", [
        "-I", str(source.parent),
        "-I", str(ROOT / "out/lemonades/storage-abi/include"),
        "-I", str(TREE / ".cache/xnu-work/osfmk")])
    undefined = subprocess.check_output(["xcrun", "nm", "-u", out / "NativeRamBlock.o"], text=True)
    assert all(name in undefined for name in ("native_ufs_store_mode", "native_ufs_store_open", "native_ufs_store_read", "native_ufs_store_write", "native_ufs_store_sync", "native_ufs_store_gpt_check"))
    original = UP / "scripts/build-native-virtio-bindings.py"
    script = original.read_text().replace("ROOT = Path(__file__).resolve().parents[1]", f"ROOT = Path({str(UP)!r})")
    script = script.replace("ROOT / 'build/storage-abi/interface-audit.json'", f"Path({str(ROOT / 'out/lemonades/storage-abi/interface-audit.json')!r})")
    script = script.replace("['xcrun', 'c++filt']", "['xcrun', 'c++filt', '-n']")
    script = script.replace("ROOT / 'build/native-prelink/native-apfs-load-positive.macho'", f"Path({str(ROOT / 'out/lemonades-xnu/lemonades/kernel/qemu-storage-apfs.macho')!r})")
    script = script.replace("if kernel_path.exists() and", "if not kernel_path.exists() or")
    (out / "bind-original.py").write_text(script)
    run([sys.executable, out / "bind-original.py", "--component", "NativeRamBlock", "--directory", out])
    report = {"source_sha256": sha(source), "upstream_binding_script_sha256": sha(original),
              "object_sha256": sha(out / "NativeRamBlock.o"),
              "archive_sha256": sha(out / "libNativeRamBlock.a"),
              "bindings": json.loads((out / "bindings.json").read_text()),
              "generated_source_sha256": sha(generated), "absent_optional_store_imports": missing,
              "upstream_source_modified": False, "persistent_ufs_store": True, "runtime_qualified": False,
              "pinned_current_source": str(source),
              "source_files": {str(p.relative_to(ROOT)):sha(p) for p in sorted(source.parent.iterdir()) if p.is_file()}}
    (out / "build-report.json").write_text(json.dumps(report, indent=2) + "\n")


def display():
    out = TREE / "build/native-legacy-display"
    out.mkdir(parents=True, exist_ok=True)
    reference = ROOT / "out/lemonades-xnu/lemonades/kernel/display-reference.macho"
    spec = json.loads(reference.with_suffix(".json").read_text())
    assert sha(reference) == spec["candidate_sha256"]
    assert spec["original_sha256"] == "f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7"
    refs = TREE / "build/native-prelink"
    refs.mkdir(exist_ok=True)
    for suffix in (".macho", ".json"):
        target = refs / ("native-owner-mobile-graphics-candidate" + suffix)
        source = reference if suffix == ".macho" else reference.with_suffix(suffix)
        if target.is_symlink():
            assert target.resolve() == source.resolve()
        else:
            assert not target.exists()
            target.symlink_to(source)
    # Reuse the original static ABI checks. The upstream historical runtime
    # checkpoint was pruned and is not ours: leave it unqualified until QEMU.
    original_audit = UP / "scripts/audit-mobile-graphics-legacy.py"
    audit = original_audit.read_text()
    start = audit.index("runtime=ROOT/'build/darwinboot-owner-hvf-mobile-graphics-legacy-class/gdb-stop.json'")
    end = audit.index("out.write_text", start)
    audit = audit[:start] + "out=ROOT/'build/display-analysis/mobile-graphics-legacy-abi.json'\nout.parent.mkdir(parents=True,exist_ok=True)\nruntime_sha=None\n" + audit[end:]
    (TREE / "scripts/audit-mobile-graphics-legacy.py").write_text(audit)
    arm_builder = (SHENG / "scripts/build-arm-driver.py").read_text()
    arm_builder = arm_builder.replace("'-Wno-unnecessary-virtual-specifier', ", "")
    (TREE / "scripts/build-arm-driver.py").write_text(arm_builder)
    original_builder = SHENG / "scripts/build-native-legacy-display.py"
    builder = original_builder.read_text()
    builder = builder.replace("'-Wno-unnecessary-virtual-specifier',", "")
    # Keep the complete ABI/header, original imports and actual display probe.
    # BootProcess/BootUiTrace already belong to the full diagnostic archive.
    builder = builder[:builder.index("\nhid_source=ROOT/")]
    if os.environ.get("LEMONADES_FTS_TOUCH") == "1":
        needle = "run(cmd,cwd=r['directory'])"
        assert builder.count(needle) == 1
        builder = builder.replace(needle, "cmd += ['-DLEMONADES_FTS_TOUCH=1']\n" + needle)
    builder = builder.replace("source=ROOT/'kits/sheng/LegacyDisplayProbe.cpp'", "source=ROOT/'kits/lemonades/legacy-display/LegacyDisplayProbe.cpp'")
    builder += '''
keystore_source=ROOT/'kits/lemonades/legacy-display/KeyStoreProbe.cpp'
keystore_obj=OUT/'KeyStoreProbe.o'
keystore_cmd=[str(keystore_source) if str(arg)==str(source) else str(keystore_obj) if str(arg)==str(OUT/'LegacyDisplayProbe.o') else arg for arg in cmd]
run(keystore_cmd,cwd=r['directory'])
print(run(['python3',ROOT/'scripts/build-arm-driver.py','NativeKeyStoreEvents'],text=True),end='')
keyevents=ROOT/'build/native-keystore-events'
keyevents_late=keyevents/'NativeKeyStoreEvents.late.o'
run([llvm/'llvm-objcopy','--remove-section=__DATA,__mod_init_func','--globalize-symbol=__GLOBAL__sub_I_NativeKeyStoreEvents.cpp',keyevents/'NativeKeyStoreEvents.o',keyevents_late])
require(code((keyevents/'NativeKeyStoreEvents.o').read_bytes(),macho((keyevents/'NativeKeyStoreEvents.o').read_bytes()))==code(keyevents_late.read_bytes(),macho(keyevents_late.read_bytes())),'Original KeyStore instructions unchanged by late initializer staging')
print(run(['python3',ROOT/'scripts/build-arm-driver.py','NativeGOPPresenter'],text=True),end='')
gop=ROOT/'build/native-gop-presenter';gop_late=gop/'NativeGOPPresenter.late.o'
run([llvm/'llvm-objcopy','--remove-section=__DATA,__mod_init_func','--globalize-symbol=__GLOBAL__sub_I_NativeGOPPresenter.cpp',gop/'NativeGOPPresenter.o',gop_late])
require(code((gop/'NativeGOPPresenter.o').read_bytes(),macho((gop/'NativeGOPPresenter.o').read_bytes()))==code(gop_late.read_bytes(),macho(gop_late.read_bytes())),'Owned presenter code unchanged by late init staging')
archive=OUT/'libNativeLegacyDisplay.late.a';archive.unlink(missing_ok=True)
run(['xcrun','ar','rcs',archive,late,OUT/'original-bindings.o',OUT/'LegacyDisplayProbe.o',gop_late,keystore_obj,keyevents_late])
sources=[ROOT/'drivers/NativeMobileDisplay/NativeLegacyDisplay.cpp',ROOT/'drivers/NativeMobileDisplay/NativeLegacyRequest.h',source,ROOT/'drivers/NativeMobileDisplay/NativeGOPPresenter.cpp',ROOT/'drivers/NativeMobileDisplay/NativeGOPWire.h',keystore_source,ROOT/'drivers/NativeKeyStoreEvents/NativeKeyStoreEvents.cpp']
(OUT/'build-report.json').write_text(json.dumps(dict(source_sha256={str(p.relative_to(ROOT)):sha(p) for p in sources},generated_abi_sha256=sha(OUT/'OriginalLegacyFramebufferABI.h'),original_candidate_sha256=sha(candidate),original_audit_sha256=sha(ROOT/'build/display-analysis/mobile-graphics-legacy-abi.json'),compiled_object_sha256=sha(obj),late_object_sha256=sha(late),archive_sha256=sha(archive),bindings={n:hex(v) for n,v in bindings.items()},virtual_entries=358,owned_entries=owned,inherited_native_entries=native,original_instructions_modified=False,runtime_qualified=False),indent=2)+'\\n')
'''
    (out / "build-from-sheng.py").write_text(builder.replace("ROOT=Path(__file__).resolve().parents[1]", f"ROOT=Path({str(TREE)!r})"))
    run([sys.executable, out / "build-from-sheng.py"])
    report = json.loads((out / "build-report.json").read_text())
    report.update(upstream_builder_sha256=sha(original_builder), upstream_audit_sha256=sha(original_audit),
                  generated_builder_sha256=sha(out / "build-from-sheng.py"),
                  reference_candidate=str(reference), reference_component_hashes=spec["original_executable_sha256"],
                  auxiliary_sheng_hardware_selected=False,
                  keystore_state_service=True,
                  keystore_probe_original_sha256=sha(SHENG / "package/KeyStoreProbe.cpp"))
    assert sha(TREE / "kits/lemonades/legacy-display/KeyStoreProbe.cpp") == report["keystore_probe_original_sha256"]
    (out / "build-report.json").write_text(json.dumps(report, indent=2) + "\n")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--component", choices=("ram", "display", "all"), default="all")
    args = p.parse_args()
    if args.component in ("ram", "all"):
        ram()
    if args.component in ("display", "all"):
        display()


if __name__ == "__main__":
    main()
