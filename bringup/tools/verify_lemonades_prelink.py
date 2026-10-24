#!/usr/bin/env python3
"""Verify a phone or QEMU prelink and its unchanged Apple code."""
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sources/UniXNU/kits/NativePrelink"))
from native_prelink import macho, backed_offset, unserialize_xml


def audit_pan_instructions(path):
    observations = {}
    for name, callee in (("_copyin", "__bcopyin"), ("_copyout", "__bcopyout"),
                         ("_copyinstr", "__bcopyinstr")):
        disassembly = subprocess.check_output(
            ["xcrun", "llvm-objdump", "-d", "--disassemble-symbols=" + name, str(path)], text=True)
        lines = disassembly.splitlines()
        clear = [i for i, s in enumerate(lines) if re.search(r"\bmsr\s+PAN,\s*#0x0\b", s)]
        restore = [i for i, s in enumerate(lines) if re.search(r"\bmsr\s+PAN,\s*#0x1\b", s)]
        call = [i for i, s in enumerate(lines) if re.search(r"\bbl\s+.*<" + callee + r">", s)]
        if not (len(clear) == len(restore) == len(call) == 1 and clear[0] < call[0] < restore[0]):
            raise ValueError("Missing original PAN clear/copy/restore sequence in " + name)
        observations[name] = {"copy_call": callee, "pan_clear": lines[clear[0]].strip(),
                              "pan_restore": lines[restore[0]].strip(), "static_check_only": True}
    return observations


def audit(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    report = json.loads(path.with_suffix(".json").read_text())
    provenance = json.loads(path.with_suffix(".provenance.json").read_text())
    qemu = json.loads((ROOT / "out/lemonades/qemu-baseline.json").read_text())
    qualified = ROOT / "out/lemonades-xnu/lemonades/kernel/kernel.macho"
    reference = json.loads(qualified.with_suffix(".json").read_text())
    from lemonades_historical_receipts import HistoricalReceipts
    historical = HistoricalReceipts()
    sha = historical.sha
    if not (digest == report["candidate_sha256"] == provenance["kernel_sha256"]
            and sha(qualified) == qemu["kernel_sha256"] == reference["candidate_sha256"]
            and qemu["status"] == "passed_scoped_runtime_checks"):
        raise ValueError("prelink or QEMU baseline provenance mismatch")
    status = provenance["source_build"]
    for name, expected in status.get("userspace_observers", {}).items():
        if sha(ROOT/name) != expected:
            raise ValueError("Userspace observer changed after compilation: " + name)
    component_reference = reference
    if status.get("legacy_display"):
        display = status["legacy_display_build"]
        ref_path = Path(display["reference_candidate"])
        if sha(ref_path) != display["original_candidate_sha256"]:
            raise ValueError("Original graphics reference candidate changed")
        component_reference = json.loads(ref_path.with_suffix(".json").read_text())
        if (component_reference["original_sha256"] != reference["original_sha256"]
                or component_reference["original_executable_sha256"] != display["reference_component_hashes"]
                or not set(reference["components"]).issubset(component_reference["components"])):
            raise ValueError("Graphics closure must preserve all qualified original components")
        for name, expected in reference["original_executable_sha256"].items():
            if component_reference["original_executable_sha256"].get(name) != expected:
                raise ValueError("Existing Apple code differs in graphics closure: " + name)
        archive = ROOT / "out/lemonades-xnu/lemonades/tree/build/native-legacy-display"
        if (display["virtual_entries"] != 358 or display["original_instructions_modified"]
                or sha(archive / "libNativeLegacyDisplay.late.a") != display["archive_sha256"]):
            raise ValueError("Original Legacy ABI/archive mismatch")
        for name, expected in display["source_sha256"].items():
            if sha(ROOT / "out/lemonades-xnu/lemonades/tree" / name) != expected:
                raise ValueError("Legacy display source changed after compilation: " + name)
        if display.get("keystore_state_service"):
            if (sha(ROOT / "devices/lemonades/package/legacy-display/KeyStoreProbe.cpp") !=
                    sha(ROOT / "sources/UniXNU-sheng/package/KeyStoreProbe.cpp") or
                    display["keystore_probe_original_sha256"] != "f6ac0fbb46d49ab9cc3909d18cc39b048a56b56f3386086ff6322538fece4aa9"):
                raise ValueError("KeyStore must preserve the original sheng probe")
    touch_checked = False
    if status.get("fts_touch"):
        touch = status["touch_build"]
        reference_path = Path(touch["reference_candidate"])
        if sha(reference_path) != touch["reference_candidate_sha256"]:
            raise ValueError("HID reference changed")
        hid_reference = json.loads(reference_path.with_suffix(".json").read_text())
        if (hid_reference["original_sha256"] != component_reference["original_sha256"] or
                not set(component_reference["components"]).issubset(hid_reference["components"])):
            raise ValueError("HID closure must extend the existing graphics/storage closure")
        for name, expected in component_reference["original_executable_sha256"].items():
            if hid_reference["original_executable_sha256"].get(name) != expected:
                raise ValueError("Existing component changed with HID: " + name)
        for name, expected in touch["sources"].items():
            if sha(ROOT / name) != expected:
                raise ValueError("Touch source changed after build: " + name)
        if sha(ROOT / "out/lemonades-xnu/lemonades/tree/build/lemonades-touch/libLemonadesTouch.a") != touch["archive_sha256"]:
            raise ValueError("Touch archive changed")
        if (touch["original_hid_abi"]["original_slots"] != 207 or
                touch["original_hid_abi"]["original_text_sha256"] != "7e4c5104814f2e773d5be13d092dec53ee44ba5a61a81264b229780406e86b72"):
            raise ValueError("Unqualified original HID ABI")
        # Check the original constructor thunks against this native kernel too.
        script = (ROOT / "out/lemonades-xnu/lemonades/tree/build/lemonades-touch/build-hid-from-upstream.py").read_text()
        script = script[:script.index("header="+chr(39)*3)].replace(repr(str(reference_path)), repr(str(path)))
        exec(compile(script, "original-hid-abi-final-candidate", "exec"), {})
        test_path=Path(touch.get("host_test_report",ROOT / "out/lemonades/attempt-56-preparation/host-tests.json"))
        if "host_test_report_sha256" in touch and sha(test_path)!=touch["host_test_report_sha256"]:
            raise ValueError("Touch qualification report changed after build")
        tests = json.loads(test_path.read_text())
        if not tests["passed"] or tests["qemu_test_performed"]:
            raise ValueError("Missing FTS host qualification")
        for name, expected in tests["inputs"].items():
            if sha(ROOT / name) != expected:
                raise ValueError("FTS host-test source changed: " + name)
        component_reference = hid_reference
        touch_checked = True
    if status.get("data_ramdisk"):
        seed = status["data_ramdisk"]
        from importlib.util import spec_from_file_location, module_from_spec
        spec = spec_from_file_location("lemonades_packed_data", ROOT / "devices/lemonades/package/data-store/packed_ramdisk.py")
        module = module_from_spec(spec)
        spec.loader.exec_module(module)
        actual, header = module.inspect(Path(seed["path"]))
        if any(seed.get(k) != v for k, v in actual.items()) or header[32:36] != b"NXSB":
            raise ValueError("Compiled packed Data seed identity changed")
        environment = json.loads((Path(status["log_directory"]) / "environment.json").read_text())
        if (environment.get("XNU_NATIVE_RAM_BLOCK") != "1" or environment.get("XNU_OWNER_DATA_MOUNT") != "1"
                or environment.get("XNU_OWNER_DATA_VOLUME_UUID") != seed["volume_uuid"]):
            raise ValueError("Data mount profile does not bind the actual seed UUID")
        ram = ROOT / "out/lemonades-xnu/lemonades/tree/build/native-ram-block"
        if sha(ram / "NativeRamBlock.o") != status["ram_block_build"]["object_sha256"]:
            raise ValueError("Original RAM block object changed after linking")
    pan_instructions = audit_pan_instructions(path) if status.get("native_pan") else None
    if status.get("systemos"):
        environment = json.loads((Path(status["log_directory"]) / "environment.json").read_text())
        for option in ("OWNER_CACHE_MOUNT", "OWNER_CACHE_STARTUP", "OWNER_BOOT_MANIFEST",
                       "OWNER_UNION_SYSTEMOS", "NATIVE_CS_HASH_CACHE"):
            if environment.get("XNU_" + option) != "1":
                raise ValueError("SystemOS profile is incomplete: " + option)
        if status.get("owner_root") != "trust" or not status.get("native_pan"):
            raise ValueError("SystemOS requires authenticated owner root and PAN")
        for name, expected in status["systemos_sources"].items():
            if sha(ROOT / name) != expected:
                raise ValueError("SystemOS source changed after compilation: " + name)
        symbols = {}
        for line in subprocess.check_output(["xcrun", "nm", "-n", path], text=True).splitlines():
            row = line.split()
            if len(row) == 3:
                symbols[row[2]] = int(row[0], 16)
        for name in ("_load_init_program", "_native_owner_cache_checkpoint",
                     "_native_owner_publish_boot_manifest", "_native_owner_cache_dyld_flags",
                     "_cs_native4k_hash_cache_version", "_cs_native4k_prepare"):
            if name not in symbols:
                raise ValueError("Missing compiled SystemOS feature: " + name)
        parsed = macho(data)
        version_at = backed_offset(parsed["segments"], symbols["_cs_native4k_hash_cache_version"], 4, len(data))
        if struct.unpack_from("<I", data, version_at)[0] != 1:
            raise ValueError("Native 4K code hash cache version is invalid")
        # LLVM can inline the static prepare helper. Check its real operations
        # inside the caller instead of requiring an out-of-line helper symbol.
        startup = subprocess.check_output(["xcrun", "llvm-objdump", "-d",
            "--disassemble-symbols=_load_init_program", str(path)], text=True)
        for callee in ("_native_verified_block_volume_device", "_mount",
                       "_native_owner_publish_boot_manifest", "_commpage_update_dyld_flags",
                       "_native_owner_cache_checkpoint"):
            if not re.search(r"\bbl\s+.*<" + re.escape(callee) + r">", startup):
                raise ValueError("Missing compiled SystemOS operation: " + callee)
    if status.get("execution_trace"):
        execution = json.loads((ROOT / "out/lemonades/exec-trace-qemu-baseline.json").read_text())
        if execution["status"] != "passed_real_exec_entry_error_and_panic_recording":
            raise ValueError("Execution recorder has no runtime qualification")
        if status["execution_trace"] != execution["device_sources"]:
            raise ValueError("Execution recorder differs from the qualified sources")
        if sha(Path(execution["kernel"])) != execution["kernel_sha256"]:
            raise ValueError("Execution recorder QEMU kernel changed")
        for name, expected in {**execution["device_sources"], **execution["evidence_files"]}.items():
            evidence = ROOT / name
            # The historical runtime proof retains its exact decoder version.
            # New host-only decoding features do not rewrite that evidence.
            if name in ("tools/lemonades_exec_trace.py", "tools/test_lemonades_exec_trace.py") and sha(evidence) != expected:
                evidence = ROOT / "out/lemonades/exec-trace-qualified-tools" / Path(name).name
            if sha(evidence) != expected:
                raise ValueError("Execution recorder source or evidence changed: " + name)
    if status.get("critical_exit_trace"):
        for name, expected in status["critical_exit_trace"].items():
            if sha(ROOT / name) != expected:
                raise ValueError("Critical-exit recorder source changed: " + name)
    if status.get("trust_cache_runtime"):
        tc = json.loads((ROOT / "out/lemonades/trustcache-qemu-baseline.json").read_text())
        if tc["status"] != "passed_original_amfi_query_with_initialized_target_trust_caches":
            raise ValueError("Trust-cache initialization/query was not runtime qualified")
        if sha(Path(tc["kernel"])) != tc["kernel_sha256"]:
            raise ValueError("Trust-cache QEMU kernel changed")
        for name, expected in tc["evidence_files"].items():
            if sha(ROOT / name) != expected:
                raise ValueError("Trust-cache qualification artifact changed: " + name)
    if status.get("lock_failure_trace"):
        lock_baseline = json.loads((ROOT / "out/lemonades/lock-trace-qemu-baseline.json").read_text())
        if lock_baseline["status"] != "passed_original_lock_failure_backtrace_and_normal_root_control":
            raise ValueError("Lock diagnostic failure path was not runtime qualified")
        if status["lock_failure_trace"] != lock_baseline["device_sources"]:
            raise ValueError("Lock trace sources differ from runtime qualification")
        for name, expected in {**lock_baseline["device_sources"], **lock_baseline["evidence_files"]}.items():
            if sha(ROOT / name) != expected:
                raise ValueError("Lock trace source or runtime artifact changed: " + name)
        if sha(Path(lock_baseline["kernel"])) != lock_baseline["kernel_sha256"]:
            raise ValueError("Lock trace QEMU kernel changed")
    owner_baseline = None
    if status.get("owner_root", "off") != "off":
        owner_baseline = json.loads((ROOT / "out/lemonades/owner-root-qemu-baseline.json").read_text())
        if (status["owner_root"] != "trust" or not status.get("native_ufs")
                or owner_baseline["status"] != "passed_real_mounted_owner_root_binding_and_aes"
                or sha(Path(owner_baseline["kernel"])) != owner_baseline["kernel_sha256"]):
            raise ValueError("Mounted owner-root runtime qualification is missing")
        archive = ROOT / owner_baseline["source_archive"]
        if sha(archive / "sha256.json") != owner_baseline["source_archive_index_sha256"]:
            raise ValueError("Owner-root qualification archive changed")
        for name, expected in json.loads((archive / "sha256.json").read_text()).items():
            if sha(archive / name) != expected:
                raise ValueError("Owner-root qualification artifact changed: " + name)
        for name, expected in {**owner_baseline["sources"], **owner_baseline["evidence_files"]}.items():
            if sha(ROOT / name) != expected:
                raise ValueError("Owner-root source or runtime evidence changed: " + name)
        build = status["storage_providers_build"]
        reference_build = owner_baseline["storage_providers_build"]
        without_archive_hashes = lambda b: {k:v for k,v in b.items() if k not in
            ("aes_archive_sha256", "virtio_archive_sha256")}
        if without_archive_hashes(build) != without_archive_hashes(reference_build):
            raise ValueError("Storage provider implementation or ABI differs from QEMU")
        folder = ROOT / "out/lemonades-xnu/lemonades/tree/build/lemonades-storage-providers"
        for component, field in (("NativeAES", "aes_archive_sha256"),
                                  ("NativeVirtioBlock", "virtio_archive_sha256")):
            if sha(folder / ("lib" + component + ".a")) != build[field]:
                raise ValueError("Storage provider archive changed after linking")
            if sha(folder / (component + ".o")) != sha(archive / "providers" / (component + ".o")):
                raise ValueError("Storage provider object differs from qualified QEMU code")
    native_ufs_baseline = None
    if status.get("native_ufs"):
        native_ufs_baseline = json.loads((ROOT / "out/lemonades/native-ufs-qemu-baseline.json").read_text())
        baseline = native_ufs_baseline
        if (baseline["status"] != "passed_native_ufs_abi_crypto_and_hardware_exclusion"
                or sha(Path(baseline["kernel"])) != baseline["kernel_sha256"]):
            raise ValueError("Native UFS runtime qualification changed")
        reference = json.loads(Path(baseline["kernel"]).with_suffix(".json").read_text())
        archive = ROOT / baseline["source_archive"]
        if sha(archive / "sha256.json") != baseline["source_archive_index_sha256"]:
            raise ValueError("Native UFS qualification index changed")
        for name, expected in json.loads((archive / "sha256.json").read_text()).items():
            if sha(archive / name) != expected:
                raise ValueError("Native UFS qualification artifact changed: " + name)
        current = status["native_ufs_build"]
        profile = status.get("profile")
        if (profile not in ("phone", "qemu") or current["profile"] != profile
                or (profile == "qemu" and (status.get("early_trace") or current["disk_write_path"]))
                or not current["verified_block_policies"] or status.get("ufs_probe")):
            raise ValueError("Native UFS profile or exclusive transport ownership mismatch")
        fields = ("device_sources", "upstream_sources", "generated_source_sha256")
        if current.get("disk_write_path"):
            from audit_lemonades_data_store import audit as audit_data_store
            audit_data_store(current, status["ram_block_build"])
        elif any(current[field] != baseline["native_ufs_build"][field] for field in fields):
            # The original queue/protocol/block and signed-policy implementation
            # remains unchanged. Check only the exact board identity and DMA
            # ownership adaptation, without claiming new QEMU qualification.
            from audit_lemonades_ufs_memory import audit as audit_ufs_memory
            audit_ufs_memory(current, baseline["native_ufs_build"])
        for name, expected in current["device_sources"].items():
            if sha(ROOT / name) != expected:
                raise ValueError("Native UFS source changed after compilation: " + name)
        for name, expected in current["upstream_sources"].items():
            if sha(ROOT / "sources/UniXNU" / name) != expected:
                raise ValueError("Native UFS upstream input changed: " + name)
        if (current["bindings"]["bindings"] != baseline["native_ufs_build"]["bindings"]["bindings"]
                or current["bindings"]["virtual_methods_checked"] != 190
                or {k:v for k,v in status["root_policy_build"].items() if k != "archive_sha256"}
                != {k:v for k,v in baseline["root_policy_build"].items() if k != "archive_sha256"}):
            raise ValueError("Storage ABI or verified policies changed")
        # BSD ar member headers contain timestamps. Compare every compiled
        # object as well as the exact archive digest recorded by the phone build.
        policy_archive = ROOT / "out/lemonades-xnu/lemonades/tree/build/lemonades-root-policy/libVerifiedRootProbe.a"
        if sha(policy_archive) != status["root_policy_build"]["archive_sha256"]:
            raise ValueError("Phone policy archive changed after linking")
        for name in ("verified_root.o", "xnu_crypto.o", "verified-root-probe.o", "inputs.o"):
            member = subprocess.check_output(["xcrun", "ar", "-p", str(policy_archive), name])
            if hashlib.sha256(member).hexdigest() != sha(archive / "root-policy" / name):
                raise ValueError("Phone policy object differs from QEMU: " + name)
        # Absolute original-class imports must remain at the audited addresses.
        for segment in ("__TEXT_EXEC", "__DATA_CONST", "__DATA"):
            pick = lambda r: [e for e in r["extents"] if
                e["module"] == "com.apple.iokit.IOStorageFamily" and e["segment"] == segment]
            if pick(report) != pick(reference):
                raise ValueError("Original storage binding address changed")
        for name, expected in baseline["evidence_files"].items():
            if sha(ROOT / name) != expected:
                raise ValueError("Native UFS runtime evidence changed")
    for field in ("original_sha256", "components", "slide", "early_security_initializers",
                  "original_executable_sha256"):
        if report[field] != component_reference[field]:
            raise ValueError("prelink differs from QEMU component contract: " + field)
    if (not status["success"] or status["crypto_bootstrap"] != "prelinked"
            or report["native_sha256"] != status["sha256"]
            or sha(Path(status["kernel"])) != status["sha256"]):
        raise ValueError("prelink source build mismatch")
    parsed = macho(data)
    if parsed["kind"] != 2:
        raise ValueError("expected MH_EXECUTE")
    segments = parsed["segments"]
    info = next(s for s in segments if s["name"] == "__PRELINK_INFO")
    metadata = unserialize_xml(data[info["fileoff"]:info["fileoff"] + info["filesize"]])
    entries = {e["CFBundleIdentifier"]: e for e in metadata["_PrelinkInfoDictionary"]}
    for name, expected in report["original_executable_sha256"].items():
        entry = entries[name]
        address = entry["_PrelinkExecutableLoadAddr"]
        at = backed_offset(segments, address, 32, len(data))
        module = macho(data, at)
        executable = [s for s in module["segments"] if s["name"] == "__TEXT_EXEC" and s["filesize"]]
        if len(executable) != 1:
            raise ValueError("unexpected component code extent")
        code = executable[0]
        offset = backed_offset(segments, code["va"], code["filesize"], len(data))
        if hashlib.sha256(data[offset:offset + code["filesize"]]).hexdigest() != expected:
            raise ValueError("Apple component executable bytes differ: " + name)
    entries_pc = [struct.unpack_from("<Q", data, at + 272)[0]
                  for command, at, size in parsed["commands"] if command == 5 and size == 288]
    if len(entries_pc) != 1:
        raise ValueError("expected one ARM64 entry")
    entry = entries_pc[0]
    loaded = sorted([s for s in segments if s["size"] and s["name"] != "__PAGEZERO"],
                    key=lambda s: s["va"])
    for i, s in enumerate(loaded):
        if s["fileoff"] + s["filesize"] > len(data):
            raise ValueError("segment file range invalid")
        if i and loaded[i-1]["va"] + loaded[i-1]["size"] > s["va"]:
            raise ValueError("overlapping load segments")
    if not any(s["initprot"] & 4 and s["va"] <= entry < s["va"] + s["filesize"] for s in loaded):
        raise ValueError("entry is not executable")
    span = loaded[-1]["va"] + loaded[-1]["size"] - loaded[0]["va"]
    owned = (320 if status.get("native_ufs") else 256) << 20
    if provenance.get("high_memory_profile"):
        from lemonades_memory_profile import audit_high_memory
        if provenance["high_memory_profile"] != audit_high_memory():
            raise ValueError("High memory profile differs from the audited board/evidence")
        owned = 0x130000000
    fat = (124 if status.get("native_ufs") else 64) << 20
    copies = status.get("root_policy_build", {}).get("manifest_bytes", 0)
    if (provenance["owned_memory_bytes"] != owned or provenance["fat_volume_bytes"] != fat
            or span + copies + 32 * 1024**2 > owned or len(data) + 4 * 1024**2 > fat):
        raise ValueError("prelink exceeds phone memory or payload budget")
    pmgr_baseline = None
    if status.get("pmgr"):
        pmgr_baseline = json.loads((ROOT / "out/lemonades/pmgr-qemu-baseline.json").read_text())
        if (pmgr_baseline["status"] != "passed_scoped_pmgr_runtime_checks" or
                sha(Path(pmgr_baseline["kernel"])) != pmgr_baseline["kernel_sha256"]):
            raise ValueError("PMGR QEMU candidate changed or was not qualified")
        archive = ROOT / pmgr_baseline["source_archive"]
        if sha(archive / "sha256.json") != pmgr_baseline["source_archive_index_sha256"]:
            raise ValueError("PMGR QEMU source index changed")
        index = json.loads((archive / "sha256.json").read_text())
        for name, expected in index.items():
            if sha(archive / name) != expected:
                raise ValueError("PMGR QEMU source changed: " + name)
        reference_build = json.loads((archive / "build-report.json").read_text())
        driver = ROOT / "devices/lemonades/package/LemonadesPlatformPower.cpp"
        if sha(driver) != status["pmgr_build"]["source_sha256"]:
            raise ValueError("PMGR source changed after compilation")
        source = driver.read_text()
        # The phone-only root-boundary observer reads counters and is excluded
        # from QEMU. All service/lifecycle code must match the exercised source.
        marker = "// Called at the root-volume lookup"
        if marker in source:
            start = source.index(marker)
            end = source.index("\n#endif\n}", start) + len("\n#endif\n")
            source = source[:start] + source[end:]
        if source != (archive / "LemonadesPlatformPower.cpp").read_text():
            raise ValueError("PMGR service code differs from exercised QEMU source")
        for key in ("bindings", "virtual_entries", "reference_sha256", "original_executable_modified"):
            if status["pmgr_build"][key] != reference_build[key]:
                raise ValueError("PMGR ABI differs from runtime-qualified implementation: " + key)
        if status["pmgr_build"]["virtual_entries"] != 340 or status["pmgr_build"]["original_executable_modified"]:
            raise ValueError("PMGR ABI guard contract invalid")
        for case in pmgr_baseline["cases"]:
            for name, expected in case["files"].items():
                if sha(ROOT / case["path"] / name) != expected:
                    raise ValueError("PMGR runtime evidence changed")
    gic_baseline = None
    if status.get("gic_diagnostics"):
        gic_baseline = json.loads((ROOT / "out/lemonades/gic-qemu-baseline.json").read_text())
        if (gic_baseline["status"] != "passed_real_timer_irq_checks" or
                sha(Path(gic_baseline["kernel"])) != gic_baseline["kernel_sha256"]):
            raise ValueError("GIC QEMU candidate changed or was not qualified")
        archive = ROOT / gic_baseline["source_archive"]
        if sha(archive / "sha256.json") != gic_baseline["source_archive_index_sha256"]:
            raise ValueError("GIC QEMU source index changed")
        for name, expected in json.loads((archive / "sha256.json").read_text()).items():
            if sha(archive / name) != expected:
                raise ValueError("GIC QEMU source changed: " + name)
        reference_build = json.loads((archive / "build-report.json").read_text())
        current_build = status["armcpu_build"]
        if (not current_build["actual_instruction_sequences_checked"] or
                current_build["gic_diagnostics"] != status["profile"] or
                current_build["compiled_source_sha256"] != reference_build["compiled_source_sha256"]):
            raise ValueError("ArmCpu source differs from QEMU-qualified implementation")
        for name, item in current_build["inputs"].items():
            if (item["sha256"] != reference_build["inputs"][name]["sha256"] or
                    sha(Path(item["path"])) != item["sha256"]):
                raise ValueError("ArmCpu input changed after qualification: " + name)
        for name, expected in gic_baseline["evidence_files"].items():
            if sha(ROOT / name) != expected:
                raise ValueError("GIC runtime evidence changed")
    screen_baseline = None
    if status.get("screen_diagnostics"):
        screen_baseline = json.loads((ROOT / "out/lemonades/screen-qemu-baseline.json").read_text())
        if (screen_baseline["status"] != "passed_real_timed_framebuffer_diagnostics"
                or sha(Path(screen_baseline["kernel"])) != screen_baseline["kernel_sha256"]):
            raise ValueError("Screen diagnostic QEMU candidate was not qualified")
        archive = ROOT / screen_baseline["source_archive"]
        if sha(archive / "sha256.json") != screen_baseline["source_archive_index_sha256"]:
            raise ValueError("Screen qualification archive changed")
        for name, expected in json.loads((archive / "sha256.json").read_text()).items():
            if sha(archive / name) != expected:
                raise ValueError("Screen qualification source changed: " + name)
        reference_build = json.loads((archive / "build/build-report.json").read_text())
        build = status["screen_build"]
        qualified_screen_sources = dict(build["sources"])
        persistent_watchdog_policy_checked = False
        if qualified_screen_sources.get("BootWatchdogPolicy.c") != reference_build["sources"].get("BootWatchdogPolicy.c"):
            # Qualify only the upstream persistent-Data open flag change. The
            # same real initializer must reproduce the old second-boot failure
            # and pass the new repeated-boot and syscall failure tests.
            from test_lemonades_watchdog_policy import verify_report
            policy_report = verify_report()
            if (qualified_screen_sources.get("BootWatchdogPolicy.c") != policy_report["source_sha256"] or
                    reference_build["sources"].get("BootWatchdogPolicy.c") != policy_report["reference_sha256"]):
                raise ValueError("Watchdog policy differs from its qualified delta")
            qualified_screen_sources["BootWatchdogPolicy.c"] = policy_report["reference_sha256"]
            persistent_watchdog_policy_checked = True
        runtime_trace_checked = False
        wait_trace_checked = False
        if "LemonadesWaitTrace.h" in qualified_screen_sources:
            source = (ROOT / "devices/lemonades/package/boot-progress/BootUiTraceProbe.c").read_text()
            for addition in ('#include "LemonadesWaitTrace.h"\n', ' lemonades_wait_capture_begin();\n', '  lemonades_wait_publish();\n'):
                if source.count(addition) != 1:
                    raise ValueError("Unexpected original stack capture adapter")
                source = source.replace(addition, "")
            expected = reference_build["sources"]["BootUiTraceProbe.c"]
            if hashlib.sha256(source.encode()).hexdigest() != expected:
                raise ValueError("Original stack capture changed beyond publication observer")
            wait_report = "out/lemonades/attempt-56-preparation/wait-tests.json" if status.get("fts_touch") else "out/lemonades/attempt-54-preparation/wait-tests.json"
            test = json.loads((ROOT / wait_report).read_text())
            if not test["passed"] or test["qemu_test_performed"]:
                raise ValueError("Missing wait snapshot host tests")
            if status.get("fts_touch") and (not test.get("touch_delta_preserves_wait") or
                    test["maximum_diagnostic_bytes"] >= 0x200000-12):
                raise ValueError("Touch logging must preserve WAIT and the console budget")
            for name, input_digest in test["inputs"].items():
                if sha(ROOT / name) != input_digest:
                    raise ValueError("Wait snapshot changed since host tests: " + name)
            qualified_screen_sources["BootUiTraceProbe.c"] = expected
            qualified_screen_sources.pop("LemonadesWaitTrace.h")
            wait_trace_checked = True
        runtime_headers = ("LemonadesRuntimeTrace.h", "LemonadesRuntimeWire.h", "LemonadesUserspaceProbe.c", "LemonadesUserWire.h")
        if all(name in qualified_screen_sources for name in runtime_headers):
            for name in runtime_headers:
                qualified_screen_sources.pop(name)
            runtime_trace_checked = True
        overlay_policy_checked = False
        if qualified_screen_sources.get("BootProgress.c") != reference_build["sources"].get("BootProgress.c"):
            # The optional post-scanout overlay guard is host-qualified. Apart
            # from these exact additions the full qualified renderer must match.
            source = (ROOT / "devices/lemonades/package/boot-progress/BootProgress.c").read_text()
            additions = (
                "// Optional clean system frames; default preserves the original live overlay.\nstatic unsigned post_scanout_overlay=1;\n",
                '  PE_parse_boot_argn("boot-diag-overlay",&post_scanout_overlay,sizeof(post_scanout_overlay));\n',
                "  // Serialize with the actual display handoff before deciding to draw.\n  if(!post_scanout_overlay && boot_progress_display_owned) {\n    __atomic_store_n(&render_busy,0,__ATOMIC_RELEASE);return;\n  }\n",
                "extern void lemonades_user_start(void);\nextern void lemonades_user_exit_observe(int,const char *,int,unsigned,uint64_t,const char *);\n",
                '  lemonades_user_exit_observe(pid,name,status,ns,code,signal==6?exit_records.reason:"");\n',
                "  lemonades_user_start();\n",
            )
            for addition in additions:
                if source.count(addition) != 1:
                    raise ValueError("Unqualified screen handoff policy change")
                source = source.replace(addition, "")
            if runtime_trace_checked:
                for addition in ('#include "LemonadesRuntimeTrace.h"\n', '    lemonades_runtime_trace_poll(now);\n'):
                    if source.count(addition) != 1:
                        raise ValueError("Unqualified runtime snapshot hook")
                    source = source.replace(addition, "")
            expected = reference_build["sources"]["BootProgress.c"]
            if hashlib.sha256(source.encode()).hexdigest() != expected:
                raise ValueError("Changes beyond the explicit clean-frame overlay policy")
            qualified_screen_sources["BootProgress.c"] = expected
            overlay_policy_checked = True
        expanded_providers = bool(status.get("legacy_display") or status.get("data_ramdisk"))
        if expanded_providers:
            # The renderer stays byte-for-byte source-identical; only typed
            # unavailable telemetry becomes real imports from newly linked drivers.
            missing = set(build["unavailable_optional_imports"])
            old_missing = set(reference_build["unavailable_optional_imports"])
            if not missing.issubset(old_missing):
                raise ValueError("Newly unavailable observer imports")
            allowed = ("_native_legacy_", "_native_ram_block_", "_native_data_persist_")
            if status.get("legacy_display_build", {}).get("keystore_state_service"):
                allowed += ("_native_aks_", "_native_keyevents_", "_native_keystore_")
            if status.get("fts_touch"):
                allowed += ("_native_touch_", "_native_hid_")
            if any(not name.startswith(allowed) for name in old_missing - missing):
                raise ValueError("Unexpected observer provider transition")
            for name, source_digest in build["generated_sources"].items():
                if sha(ROOT / "out/lemonades-xnu/lemonades/tree/build/boot-progress" / name) != source_digest:
                    raise ValueError("Generated observer source changed")
        if (not build["actual_arm64_instructions_checked"]
                or build["phone_trace"] != status["early_trace"]
                or qualified_screen_sources != reference_build["sources"]
                or (not expanded_providers and build["generated_sources"] != reference_build["generated_sources"])
                or (not expanded_providers and build["unavailable_optional_imports"] != reference_build["unavailable_optional_imports"])):
            raise ValueError("Screen implementation differs from QEMU-qualified source")
        for name, expected in build["sources"].items():
            if sha(ROOT / "devices/lemonades/package/boot-progress" / name) != expected:
                raise ValueError("Screen source changed after compilation: " + name)
        for name, expected in screen_baseline["evidence_files"].items():
            if sha(ROOT / name) != expected:
                raise ValueError("Screen runtime evidence changed: " + name)
    if status.get("ufs_probe"):
        baseline = json.loads((ROOT / "out/lemonades/ufs-probe-qemu-baseline.json").read_text())
        if (baseline["status"] != "passed_qemu_ufs_hardware_exclusion" or
                sha(Path(baseline["kernel"])) != baseline["kernel_sha256"]):
            raise ValueError("UFS probe lacks QEMU hardware-exclusion evidence")
        archive = ROOT / baseline["source_archive"]
        if sha(archive / "sha256.json") != baseline["source_archive_index_sha256"]:
            raise ValueError("UFS probe qualification index changed")
        for name, expected in json.loads((archive / "sha256.json").read_text()).items():
            if sha(archive / name) != expected:
                raise ValueError("UFS probe qualification source changed: " + name)
        current = status["ufs_probe_build"]
        reference_build = json.loads((archive / "build/build-report.json").read_text())
        if (current["source_sha256"] != reference_build["source_sha256"] or
                current["script_sha256"] != reference_build["script_sha256"] or
                current["phone"] != status["early_trace"] or
                sha(ROOT / "devices/lemonades/package/LemonadesUfsProbe.cpp") != current["source_sha256"] or
                current["disk_write_path"]):
            raise ValueError("UFS probe source or execution contract changed")
        if current.get("contract_version")==2:
            if (not current["smmu_host_test_passed"] or
                current["dma_submission_path"]!=status["early_trace"] or
                any(current[k]!=reference_build[k] for k in
                    ("sources","upstream_sources","generated_sources","contract_version"))):
                raise ValueError("UFS transport lacks matching source and planner qualification")
            for name,expected in current["sources"].items():
                if sha(ROOT/"devices/lemonades/package"/name)!=expected:
                    raise ValueError("UFS source changed: "+name)
            for name,expected in current["upstream_sources"].items():
                if sha(ROOT/"sources/UniXNU/drivers/NativeUfs"/name)!=expected:
                    raise ValueError("UFS upstream source changed: "+name)
        elif current["dma_submission_path"]:
            raise ValueError("Unexpected DMA path in passive UFS contract")
        for name, expected in baseline["evidence_files"].items():
            if sha(ROOT / name) != expected:
                raise ValueError("UFS QEMU evidence changed")
    return {
        "status": "host_verified_prelink", "kernel": str(path), "sha256": digest,
        "bytes": len(data), "architecture": "ARM64 (subtype 0)", "file_type": "MH_EXECUTE",
        "entry": hex(entry), "virtual_base": hex(loaded[0]["va"]),
        "virtual_span_bytes": span, "prelinked": True,
        "original_component_code_verified": True, "components": report["components"],
        "crypto_bootstrap": "prelinked", "early_trace": status["early_trace"],
        "profile": status["profile"],
        "qemu_base_sha256": qemu["kernel_sha256"],
        "exact_candidate_qemu_tested": digest == qemu["kernel_sha256"],
        "historical_binary_receipts_used": historical.used,
        "historical_receipt_note": "Explicitly pruned baseline binaries use hash-pinned attempt-55 verification receipts, not fresh binary or runtime verification. Current candidate and source files are directly checked.",
        "pmgr": bool(status.get("pmgr")),
        "ufs_probe": bool(status.get("ufs_probe")),
        "native_ufs": bool(status.get("native_ufs")),
        "owner_root": status.get("owner_root", "off"),
        "owner_root_qemu_sha256": owner_baseline["kernel_sha256"] if owner_baseline else None,
        "lock_failure_trace": bool(status.get("lock_failure_trace")),
        "execution_trace": bool(status.get("execution_trace")),
        "critical_exit_trace": bool(status.get("critical_exit_trace")),
        "native_pan": bool(status.get("native_pan")),
        "native_pan_instructions": pan_instructions,
        "native_pan_runtime_verified": False,
        "systemos": bool(status.get("systemos")),
        "legacy_display": bool(status.get("legacy_display")),
        "fts_touch_static_checked": touch_checked,
        "fts_touch_runtime_qualified": False,
        "data_ramdisk": status.get("data_ramdisk"),
        "systemos_runtime_verified": False,
        "trust_cache_runtime": bool(status.get("trust_cache_runtime")),
        "owned_memory_bytes": owned, "fat_volume_bytes": fat,
        "pmgr_qemu_sha256": pmgr_baseline["kernel_sha256"] if pmgr_baseline else None,
        "gic_diagnostics": bool(status.get("gic_diagnostics")),
        "gic_qemu_sha256": gic_baseline["kernel_sha256"] if gic_baseline else None,
        "screen_diagnostics": bool(status.get("screen_diagnostics")),
        "clean_frame_overlay_policy_checked": overlay_policy_checked if status.get("screen_diagnostics") else False,
        "runtime_snapshot_hook_checked": runtime_trace_checked if status.get("screen_diagnostics") else False,
        "persistent_watchdog_policy_host_checked": persistent_watchdog_policy_checked if status.get("screen_diagnostics") else False,
        "original_stack_publication_adapter_checked": wait_trace_checked if status.get("screen_diagnostics") else False,
        "screen_qemu_sha256": screen_baseline["kernel_sha256"] if screen_baseline else None,
        "functional_power_backend": False,
        "hardware_tested": False,
    }
