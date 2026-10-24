#!/usr/bin/env python3
"""Boot an untraced lemonades kernel through generic UEFI using upstream QEMU tools.

The synthetic device tree describes QEMU, never Xiaomi hardware. The supplied
kernel is copied unchanged; breakpoints only observe execution.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / "sources/UniXNU"


def verify_window(disk, window, cache_path):
    st = disk.stat()
    offset, size = window["offset"], window["size"]
    if not disk.is_file() or not 0 <= offset < offset + size <= st.st_size or offset % 512 or size % 512:
        raise ValueError("Expected a bounded sector-aligned regular-file volume window")
    identity = {"path": str(disk), "device": st.st_dev, "inode": st.st_ino,
                "size": st.st_size, "mtime_ns": st.st_mtime_ns, "ctime_ns": st.st_ctime_ns,
                "offset": offset, "window_bytes": size}
    cached = json.loads(cache_path.read_text()) if cache_path.exists() else {}
    if cached.get("identity") != identity or cached.get("sha256") != window["sha256"]:
        digest = hashlib.sha256()
        with disk.open("rb") as stream:
            stream.seek(offset)
            left = size
            while left:
                data = stream.read(min(left, 4 << 20))
                if not data:
                    raise ValueError("Incomplete volume window")
                digest.update(data)
                left -= len(data)
        if digest.hexdigest() != window["sha256"]:
            raise ValueError("Volume window SHA-256 mismatch")
        now = disk.stat()
        if (now.st_mtime_ns, now.st_ctime_ns, now.st_size) != (st.st_mtime_ns, st.st_ctime_ns, st.st_size):
            raise ValueError("Backing file changed during hashing")
        cache_path.write_text(json.dumps({"identity": identity, "sha256": window["sha256"]}, indent=2) + "\n")
    return {"backing_file": str(disk), "offset": offset, "bytes": size,
            "sha256": window["sha256"], "read_only": True, "file_identity": identity}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--kernel", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--stop", default="_Assert")
    p.add_argument("--trace", action="append", default=[])
    p.add_argument("--also-stop", action="append", default=[])
    p.add_argument("--read-symbol", action="append", default=[], metavar="SYMBOL:BYTES")
    p.add_argument("--read-address", action="append", default=[], metavar="HEX_ADDRESS:HEX_BYTES",
                   help="observe exact addresses derived by a component ABI audit")
    p.add_argument("--args", default="-v keepsyms=1")
    p.add_argument("--accel", choices=("hvf", "tcg"), default="hvf")
    p.add_argument("--no-vmm-property", action="store_true",
                   help="exercise the unchanged AMFI physical-platform branch under TCG")
    p.add_argument("--timeout", type=int, default=45)
    p.add_argument("--owned-memory-mib", choices=(256,320,512), type=int, default=256)
    p.add_argument("--root-volume", action="store_true",
                   help="attach only the SHA-verified OS window as a read-only VirtIO disk")
    p.add_argument("--systemos-volume", action="store_true",
                   help="also attach the disjoint SHA-verified SystemOS window read-only")
    p.add_argument("--data-ramdisk", type=Path,
                   help="the same original packed APFS Data input used by the source build")
    p.add_argument("--trust-cache", type=Path,
                   help="load the exact original static/System trust-cache bundle")
    p.add_argument("--finish", action="store_true")
    p.add_argument("--entry-register-equals",
                   help="observe a real finished call selected by ARG:HEX_VALUE")
    p.add_argument("--inspect-user-state", action="store_true",
                   help="read ABI-qualified saved user registers at a real kernel entry")
    p.add_argument("--skip-target-hits", type=int, default=0,
                   help="observe a later genuine call, without modifying guest state")
    p.add_argument("--capture-screen", action="store_true",
                   help="attach actual QEMU RAMFB and capture its scanout at the breakpoint")
    p.add_argument("--stop-address", help="explicit component instruction address instead of a native symbol")
    a = p.parse_args()
    if a.systemos_volume and not a.root_volume:
        p.error("SystemOS requires the original OS root volume")
    if a.no_vmm_property and a.accel != "tcg":
        p.error("no-VMM PMGR controls require TCG")
    if not re.fullmatch(r"[A-Za-z0-9_=., +\-]*", a.args):
        p.error("unsupported boot argument characters")
    kernel, out = a.kernel.resolve(), a.out.resolve()
    if out.exists():
        p.error("refusing to overwrite an existing QEMU run")
    symbols = {}
    for line in subprocess.check_output(["xcrun", "nm", "-n", kernel], text=True).splitlines():
        fields = line.split()
        if len(fields) == 3:
            symbols[fields[2]] = int(fields[0], 16)
    if "_lemonades_early_trace" in symbols or "_lemonades_trace_console_address" in symbols:
        p.error("phone RAM-console instrumentation is forbidden in QEMU")
    def symbol(name):
        if name not in symbols:
            p.error(f"missing exact kernel symbol: {name}")
        return hex(symbols[name])
    stop = hex(int(a.stop_address, 0)) if a.stop_address else symbol(a.stop)
    esp = out / "esp"
    payload = esp / "EFI/UniXNU/Payloads"
    payload.mkdir(parents=True)
    (esp / "EFI/BOOT").mkdir(parents=True)
    firmware = ROOT / "out/lemonades-qemu/firmware"
    inputs = {
        esp / "EFI/BOOT/BOOTAA64.EFI":
            firmware / "Build/Out/AARCH64-DEBUG/UniXNU.efi",
        payload / "DarwinBoot.efi":
            firmware / "build/DarwinBoot/DEBUG_CLANGPDB/AARCH64/DarwinBoot.efi",
        payload / "kernel.macho": kernel,
    }
    for target, source in inputs.items():
        shutil.copyfile(source, target)
    data_input = None
    if a.data_ramdisk:
        sys.path.insert(0, str(UPSTREAM / "drivers/DarwinBoot/Test"))
        from packed_ramdisk import inspect
        seed = a.data_ramdisk.resolve()
        data_input, header = inspect(seed)
        if not data_input.get("packed") or header[32:36] != b"NXSB":
            p.error("requires the actual packed APFS Data seed")
        build = json.loads(kernel.with_suffix(".source-build.json").read_text())
        expected = build.get("data_ramdisk") or {}
        if any(expected.get(k) != value for k, value in data_input.items()):
            p.error("Data input differs from the compiled volume identity")
        shutil.copyfile(seed, payload / "kernel.macho.ramdisk")
    trust_sha = None
    if a.trust_cache:
        trust_sha = hashlib.sha256(a.trust_cache.read_bytes()).hexdigest()
        if trust_sha != "7416ca4f8377146626bb284e2133c76bee6cb4e3ee0af5d648b186235a7323a7":
            p.error("requires the exact unchanged original static/System trust modules")
        shutil.copyfile(a.trust_cache,payload / "kernel.macho.trustcache")
    root_args, disk_command = [], []
    gdb_script = UPSTREAM / "scripts/qemu-entry/gdb-stop.py"
    root_input = systemos_input = None
    if a.root_volume:
        manifest = json.loads((ROOT / "out/lemonades-xnu/lemonades/userdata/userdata-root.json").read_text())
        disk = Path(manifest["image"])
        window = next(w for w in manifest["windows"] if w["name"] == "OS")
        root_input = verify_window(disk, window, ROOT / "out/lemonades/qemu-os-window.json")
        fdt = out / "qemu-virt.dtb"
        subprocess.run(["qemu-system-aarch64","-M",f"virt,gic-version=3,dumpdtb={fdt}",
                        "-cpu","cortex-a710","-m","1024","-display","none"],check=True,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        root_args = ["--virtio-mmio-fdt",str(fdt),"--root-match-volume-uuid",
                     "04769D26-2CA0-4825-B443-E2E5F88300F2"]
        # Keep the upstream observer unchanged except for exposing a bounded
        # raw file window. Both QEMU nodes remain strictly read-only.
        content = gdb_script.read_text()
        assert content.count("\nimport argparse\n") == 1
        content = content.replace("\nimport argparse\n",
            "\nimport argparse\nimport sys\nsys.path.insert(0, " + repr(str(gdb_script.parent)) + ")\n")
        before = "        first_sector = stream.read(512)"
        assert content.count(before) == 1
        content = content.replace(before, f"        stream.seek({window['offset']})\n"+before)
        before = "block_input = dict(name=disk.name, bytes=disk.stat().st_size, format='raw', read_only=True,"
        assert content.count(before) == 1
        content = content.replace(before, f"block_input = dict(name=disk.name, bytes={window['size']}, offset={window['offset']}, format='raw', read_only=True,")
        before = "'driver': 'raw', 'node-name': 'offline-block', 'read-only': True,"
        assert content.count(before) == 1
        content = content.replace(before,before+f" 'offset': {window['offset']}, 'size': {window['size']},")
        disk_command = ["--virtio-block-image",str(disk)]
        if a.systemos_volume:
            system = next(w for w in manifest["windows"] if w["name"] == "SystemOS")
            systemos_input = verify_window(disk, system, ROOT / "out/lemonades/qemu-systemos-window.json")
            disjoint = (window["offset"] + window["size"] <= system["offset"] or
                        system["offset"] + system["size"] <= window["offset"])
            if not disjoint:
                raise ValueError("OS and SystemOS windows overlap")
            # The original observer requires distinct files. Here both read-only
            # raw nodes use independently hashed, strictly disjoint file windows.
            before = "or extra_disk == disk"
            assert content.count(before) == 1
            content = content.replace(before, "or (extra_disk == disk and not " + repr(disjoint) + ")")
            before = "        extra_sector = stream.read(512)"
            assert content.count(before) == 1
            content = content.replace(before, f"        stream.seek({system['offset']})\n" + before)
            before = "extra_block_input = dict(name=extra_disk.name, bytes=extra_disk.stat().st_size,"
            assert content.count(before) == 1
            content = content.replace(before, f"extra_block_input = dict(name=extra_disk.name, bytes={system['size']}, offset={system['offset']},")
            before = "'driver': 'raw', 'node-name': 'offline-extra', 'read-only': True,"
            assert content.count(before) == 1
            content = content.replace(before, before + f" 'offset': {system['offset']}, 'size': {system['size']},")
            disk_command += ["--virtio-extra-block-image", str(disk)]
        gdb_script = out / "gdb-stop-root-window.py"
        gdb_script.write_text(content)
        root_input["observer_sha256"] = hashlib.sha256(gdb_script.read_bytes()).hexdigest()
    subprocess.run([
        sys.executable, str(UPSTREAM / "scripts/qemu-entry/make-dt.py"),
        "--output", str(payload / "kernel.macho.adt"), "--armvirt", "--armcpu",
        "--qemu-accel", a.accel, *( [] if a.no_vmm_property else ["--qemu-vmm-present"]), "--nvram-proxy",
        "--crypto-hash-method", "sha2-384", "--osenvironment", "ramdisk",
        "--amfi-platform-only",
        "--owned-memory-size", hex(a.owned_memory_mib << 20), "--dram-size", "0x40000000",
        *root_args,
        *(["--trust-cache"] if a.trust_cache else []),
        *(["--data-ramdisk"] if data_input else []),
    ], check=True, stdout=subprocess.DEVNULL)
    if data_input:
        sys.path.insert(0, str(ROOT / "devices/lemonades/scripts"))
        from lemonades_adt import decode
        dt = payload / "kernel.macho.adt"
        tree = decode(dt.read_bytes())
        memory = tree.at("/chosen/memory-map").properties
        assert memory.pop("RAMDisk") == bytes(16)
        memory["PackedRAMDisk"] = bytes(16)
        dt.write_bytes(tree.encode())
    (esp / "EFI/UniXNU/unixnu.toml").write_text(
        'version = 1\n[boot]\ntimeout = 1\ndefault = "qemu"\n'
        '[kits]\nautoload = false\n[[driver]]\npath = "Payloads/DarwinBoot.efi"\n'
        '[[entry]]\nid = "qemu"\ntitle = "lemonades source on QEMU"\ntype = "xnu"\n'
        'path = "Payloads/kernel.macho"\n' +
        ('initrd = "Payloads/kernel.macho.ramdisk"\n' if data_input else '') +
        f'args = "{a.args}"\n')
    command = [sys.executable, str(gdb_script),
               stop, "--fixture", str(out), "--esp", str(esp),
               "--kernel", str(payload / "kernel.macho"), "--qemu-accel", a.accel,
               "--qemu-memory-mib", "1024", "--gic-version", "3",
               "--timeout", str(a.timeout), *disk_command]
    for name in a.trace:
        command += ["--trace-address", symbol(name)]
    for name in a.also_stop:
        command += ["--also-stop", symbol(name)]
    for request in a.read_symbol:
        name, size = request.rsplit(":", 1)
        command += ["--read-memory", f"{symbol(name)}:{int(size, 0):x}"]
    for request in a.read_address:
        address,size=(int(v,16) for v in request.split(":"))
        if address<0xffff000000000000 or not 0<size<=4096:
            p.error("component observation must be a bounded kernel address")
        command += ["--read-memory",f"{address:x}:{size:x}"]
    if a.finish:
        command.append("--finish-function")
    if a.entry_register_equals:
        if not a.finish:
            p.error("entry register selection requires a real function return")
        command += ["--entry-register-equals", a.entry_register_equals]
    if a.inspect_user_state:
        command.append("--inspect-entry-user-state")
    if a.skip_target_hits:
        command += ["--skip-target-hits", str(a.skip_target_hits)]
    if a.capture_screen:
        command += ["--qemu-ramfb", "--capture-screen"]
    if a.accel == "tcg":
        command.append("--system-registers")
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    provenance = {
        "command": command, "stop_symbol": a.stop, "stop_address": stop,
        "boot_args": a.args, "trace_symbols": {n: symbol(n) for n in a.trace},
        "source_kernel": str(kernel), "kernel_sha256": digest(kernel),
        "qemu_version": subprocess.check_output(
            ["qemu-system-aarch64", "--version"], text=True).splitlines()[0],
        "esp_sha256": {str(f.relative_to(esp)): digest(f)
                       for f in sorted(esp.rglob("*")) if f.is_file()},
        "upstream_scripts_sha256": {n: digest(UPSTREAM / "scripts/qemu-entry" / n)
                                   for n in ("gdb-stop.py", "make-dt.py")},
        "physical_phone_access": False, "guest_memory_patched": False,
        "vmm_property_declared": not a.no_vmm_property,
        "component_stop_address": a.stop_address,
        "owned_memory_bytes": a.owned_memory_mib << 20,
        "root_input": root_input,
        "systemos_input": systemos_input,
        "data_input": data_input,
        "trustcache_sha256": trust_sha,
    }
    (out / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    with (out / "runner.log").open("w") as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    print(f"QEMU exit={result.returncode}; evidence: {out}")
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
