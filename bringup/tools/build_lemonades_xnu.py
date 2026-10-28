#!/usr/bin/env python3
"""Build the source-only lemonades XNU baseline; no prelink, boot image or device writes."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def rel(p):
    """Report path names must stay stable when the device repo is a symlink
    that resolves outside the workspace (the CI checkout layout)."""
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return "../" + str(p)
sys.path.insert(0, str(ROOT / "sources/UniXNU/scripts"))
from unixnu import feeds, tree
from unixnu.cli import parser as upstream_parser
from unixnu.config import Context
from unixnu.kernel import version_env, xnu_env

REFERENCES = {
    "xnu", "libplatform", "libdispatch", "AvailabilityVersions",
    "corecrypto-2023", "libpthread", "xnu-driverkit", "xnu-trustcache",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "out/lemonades-xnu")
    parser.add_argument("--stage", choices=("all", "bootstrap", "libraries", "kernel"), default="all")
    parser.add_argument("--early-trace", action="store_true",
                        help="build a separate lemonades entry diagnostic kernel with RAM-console markers")
    parser.add_argument("--profile", choices=("phone", "qemu"), default="phone",
                        help="qemu preserves the phone baseline and disables physical RAM-console tracing")
    parser.add_argument("--crypto-bootstrap", choices=("source", "prelinked"), default="source",
                        help="provider mode; source also seals the POST HMAC after the kernel link")
    parser.add_argument("--pmgr", action="store_true",
                        help="link lemonades's guarded original PMGR service integration")
    parser.add_argument("--gic-diagnostics", action="store_true",
                        help="observe original ArmCpu GIC and real timer IRQ milestones")
    parser.add_argument("--screen-diagnostics", action="store_true",
                        help="build the complete official sheng diagnostic with lemonades provider adaptation")
    parser.add_argument("--ufs-probe", action="store_true",
                        help="include gated lemonades UFS inspection and read-only storage bring-up")
    parser.add_argument("--verified-root", action="store_true",
                        help="link the VerifiedRoot provider with only the owner key in the kernel; "
                             "the signed envelopes are read from the userdata image")
    parser.add_argument("--native-ufs", action="store_true",
                        help="include official NativeUfsBlock with lemonades transport and full signed policies")
    parser.add_argument("--owner-root", choices=("off", "audit", "trust"), default="off",
                        help="official mounted-media binding with NativeAES and verified VirtIO/UFS")
    parser.add_argument("--systemos", action="store_true",
                        help="official readonly SystemOS union, authenticated cache startup and 4K code hashes")
    parser.add_argument("--data-ramdisk", type=Path,
                        help="original packed APFS Data seed with its adjacent JSON identity")
    parser.add_argument("--legacy-display", action="store_true",
                        help="sheng's original Legacy framebuffer and IOSurface-to-GOP backend")
    parser.add_argument("--reuse-storage-from", type=int, help="reuse source-unchanged storage archives from retained phone attempt 55")
    parser.add_argument("--fts-touch", action="store_true", help="Mi 10 ST FTS with original HID event stack")
    parser.add_argument("--touch-qualification", type=Path, default=ROOT / "out/lemonades/attempt-56-preparation/host-tests.json")
    parser.add_argument("-j", "--jobs", type=int, default=6)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("jobs must be positive")
    if args.profile == "qemu" and args.early_trace:
        parser.error("lemonades physical RAM-console tracing must not be enabled in QEMU")
    if args.pmgr and args.crypto_bootstrap != "prelinked":
        parser.error("PMGR requires --crypto-bootstrap prelinked")
    if args.gic_diagnostics and args.profile == "phone" and not args.early_trace:
        parser.error("phone GIC diagnostics require --early-trace")
    if args.screen_diagnostics and not args.gic_diagnostics:
        parser.error("screen diagnostics require the qualified GIC observer")
    if args.ufs_probe and args.profile == "phone" and not args.early_trace:
        parser.error("phone UFS inspection requires --early-trace")
    if args.verified_root and not args.native_ufs:
        parser.error("--verified-root requires --native-ufs")
    if args.native_ufs and (args.ufs_probe or args.crypto_bootstrap != "prelinked"):
        parser.error("native UFS requires prelinked crypto and exclusive ownership of the transport")
    if args.owner_root != "off" and not args.native_ufs:
        parser.error("owner root requires the complete verified storage configuration")
    # --verified-root also enforces owner root trust (XNU_OWNER_ROOT_TRUST=1),
    # it just answers the mount binding through the native UFS window table
    # instead of NativeVirtioBlock.
    if args.systemos and args.owner_root != "trust" and not args.verified_root:
        parser.error("SystemOS requires the complete authenticated owner-root profile")
    if (args.data_ramdisk or args.legacy_display) and not args.systemos:
        parser.error("Data/display require the complete SystemOS profile")
    if args.legacy_display and not args.screen_diagnostics:
        parser.error("Legacy display requires the full diagnostic scanout handoff")
    if args.fts_touch and (args.profile != "phone" or not args.legacy_display):
        parser.error("FTS requires the phone display profile")
    data_input = None
    if args.data_ramdisk:
        sys.path.insert(0, str(ROOT / "devices/lemonades/package/data-store"))
        from packed_ramdisk import inspect
        seed = args.data_ramdisk.resolve()
        identity = json.loads(seed.with_suffix(".json").read_text())
        actual, header = inspect(seed)
        if not actual.get("packed") or header[32:36] != b"NXSB" or any(actual[k] != identity[k] for k in actual):
            parser.error("Data seed differs from its actual packed APFS identity")
        data_input = {**identity, "path": str(seed), "identity_sha256": hashlib.sha256(seed.with_suffix(".json").read_bytes()).hexdigest()}
    ctx = Context(upstream_parser().parse_args([
        "build", "kernel", "-D", str(ROOT / "devices/lemonades"),
        "--out", str(args.out.resolve()), "-j", str(args.jobs),
    ]))
    ctx.work.mkdir(parents=True, exist_ok=True)
    if not ctx.config_path.exists():
        shutil.copyfile(ctx.device / "configs/lemonades_defconfig", ctx.config_path)
        ctx = Context(ctx.args)
    modules = feeds.resolve(ctx)
    commits = feeds.fetch(ctx, modules, only=REFERENCES)
    feeds.lock_write(ctx, {**feeds.lock_read(ctx), **commits})
    tree.assemble(ctx, modules)
    # Only modify the assembled COPY, never the pinned upstream repository.
    # The original guard concerns mandatory telemetry imports, not pixels:
    # lemonades keeps the full implementation but guards absent providers explicitly.
    script = ctx.tree / "scripts/build-xnu-4k-baseline.sh"
    upstream_script = ctx.root / "scripts/build-xnu-4k-baseline.sh"
    script.write_bytes(upstream_script.read_bytes())
    if args.screen_diagnostics:
        text = script.read_text()
        start = text.index('  if [ "${XNU_NATIVE_UFS:-0}" != 1 ]')
        end = text.index("  python3 scripts/build-boot-progress.py", start)
        text = text[:start] + (
            '  if [ "${LEMONADES_FULL_BOOT_PROGRESS:-0}" != 1 ]; then\n'
            "    echo 'Explicit complete lemonades diagnostic implementation required' >&2\n"
            "    exit 1\n  fi\n") + text[end:]
        script.write_text(text)
    env = dict(os.environ)
    settings = {**xnu_env(ctx), **version_env(modules), "JOBS": str(args.jobs),
                "LEMONADES_EARLY_TRACE": str(int(args.early_trace)),
                "LEMONADES_PMGR": str(int(args.pmgr)),
                "LEMONADES_UFS_PROBE": str(int(args.ufs_probe)),
                "LEMONADES_FULL_BOOT_PROGRESS": str(int(args.screen_diagnostics)),
                "XNU_BOOT_PROGRESS": str(int(args.screen_diagnostics))}
    if args.pmgr:
        settings["XNU_EXTRA_LD_ARCHIVES"] = str(ctx.tree / "build/lemonades-platform-power/libLemonadesPlatformPower.a")
    if args.ufs_probe:
        settings["XNU_EXTRA_LD_ARCHIVES"] = (
            settings.get("XNU_EXTRA_LD_ARCHIVES", "") + " " +
            str(ctx.tree / "build/lemonades-ufs-probe/libLemonadesUfsProbe.a")).strip()
    settings["XNU_NATIVE_UFS"] = str(int(args.native_ufs))
    # The verified-root probe links the owner-root policy archive; without
    # the owner-root profile there is no policy archive to link.
    settings["XNU_VERIFIED_ROOT_PROBE"] = str(int(args.native_ufs and (args.verified_root or args.owner_root != "off")))
    if args.native_ufs:
        settings["XNU_VERIFIED_ROOT_ARCHIVE"] = str(ctx.tree / "build/lemonades-root-policy/libVerifiedRootProbe.a")
    # --verified-root accepts the mounted root from the owner-signed UFS
    # window: the audit records the decision and trust lets it replace the
    # missing Apple root seal. The native UFS provider answers the binding
    # query, so the NativeVirtioBlock dependency is not needed.
    settings["XNU_OWNER_ROOT_AUDIT"] = str(int(args.verified_root or args.owner_root != "off"))
    settings["XNU_OWNER_ROOT_TRUST"] = str(int(args.verified_root or args.owner_root == "trust"))
    # bsd_init's launchd exec queries the runtime trust cache; on BCM2837
    # trust_cache_init() is only compiled in with this flag, and without it
    # trust_cache_rt_lock stays zeroed (non-sleepable) and panics on first use.
    settings["XNU_TRUST_CACHE_RUNTIME"] = str(int(args.verified_root or args.owner_root != "off"))
    settings["XNU_NATIVE_AES"] = settings["XNU_NATIVE_VIRTIO_BLOCK"] = str(int(args.owner_root != "off"))
    for option in ("OWNER_CACHE_MOUNT", "OWNER_CACHE_STARTUP", "OWNER_BOOT_MANIFEST",
                   "OWNER_UNION_SYSTEMOS", "NATIVE_CS_HASH_CACHE"):
        settings["XNU_" + option] = str(int(args.systemos))
    settings["XNU_NATIVE_RAM_BLOCK"] = settings["XNU_OWNER_DATA_MOUNT"] = str(int(bool(data_input)))
    settings["XNU_SOURCE_MOCKFS"] = str(int(bool(data_input)))
    if data_input:
        settings["XNU_OWNER_DATA_VOLUME_UUID"] = data_input["volume_uuid"]
    settings["LEMONADES_FTS_TOUCH"] = str(int(args.fts_touch))
    if args.fts_touch:
        settings["LEMONADES_FTS_QUALIFICATION"] = str(args.touch_qualification.resolve(strict=True))
    if args.fts_touch:
        settings["XNU_EXTRA_LD_ARCHIVES"] = (settings.get("XNU_EXTRA_LD_ARCHIVES", "") + " " + str(ctx.tree / "build/lemonades-touch/libLemonadesTouch.a")).strip()
    settings["XNU_NATIVE_LEGACY_DISPLAY"] = str(int(args.legacy_display))
    settings["XNU_NATIVE_MOBILE_DISPLAY"] = "0"
    if args.owner_root != "off":
        providers = ctx.tree / "build/lemonades-storage-providers"
        settings["XNU_NATIVE_AES_ARCHIVE"] = str(providers / "libNativeAES.a")
        settings["XNU_NATIVE_VIRTIO_BLOCK_ARCHIVE"] = str(providers / "libNativeVirtioBlock.a")
    if args.crypto_bootstrap:
        settings["XNU_CRYPTO_BOOTSTRAP"] = args.crypto_bootstrap
    if settings.get("XNU_DT_PANIC_REGION") != "1":
        raise SystemExit("lemonades requires CONFIG_XNU_DT_PANIC_REGION=y; disabling it "
                         "uses the BCM2837 fixed panic address. Update the saved .config.")
    if args.owner_root != "off" and settings.get("XNU_NATIVE_PAN") != "1":
        raise SystemExit("lemonades user-space boot requires CONFIG_XNU_NATIVE_PAN=y on SM8250")
    env.update(settings)
    ctx.logs.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    logdir = ctx.logs / stamp
    logdir.mkdir()
    (logdir / "environment.json").write_text(json.dumps(settings, indent=2) + "\n")
    report = {"stage": args.stage, "log_directory": str(logdir), "steps": [],
              "prelinked": False, "hardware_tested": False, "early_trace": args.early_trace,
              "profile": args.profile, "crypto_bootstrap": settings["XNU_CRYPTO_BOOTSTRAP"],
              "pmgr": args.pmgr, "gic_diagnostics": args.gic_diagnostics,
              "screen_diagnostics": args.screen_diagnostics, "ufs_probe": args.ufs_probe}
    report["native_ufs"] = args.native_ufs
    report["verified_root"] = args.verified_root
    report["owner_root"] = args.owner_root
    report["trust_cache_runtime"] = args.owner_root != "off"
    report["native_pan"] = settings.get("XNU_NATIVE_PAN") == "1"
    report["systemos"] = args.systemos
    report["data_ramdisk"] = data_input
    report["legacy_display"] = args.legacy_display
    report["fts_touch"] = args.fts_touch
    report["persistent_data"] = bool(data_input and data_input.get("persistent_ufs_store"))
    user_inputs = [ROOT / "devices/lemonades/scripts/lemonades-userspace-api.h",
                   ROOT / "devices/lemonades/patches/lemonades-xnu/zzzzzzzzzzzzzz-lemonades-persistent-data-userspace.patch",
                   ROOT / "devices/lemonades/patches/lemonades-xnu/zzzzzzzzzzzzzzz-lemonades-protected-open-observation.patch",
                   ROOT / "devices/lemonades/package/boot-progress/LemonadesUserspaceProbe.c",
                   ROOT / "devices/lemonades/package/boot-progress/LemonadesUserWire.h",
                   ROOT / "devices/lemonades/package/boot-progress/BootUiTraceProbe.c",
                   ROOT / "devices/lemonades/package/boot-progress/LemonadesWaitTrace.h"]
    report["userspace_observers"] = {str(rel(p)):hashlib.sha256(p.read_bytes()).hexdigest() for p in user_inputs}
    prelink_input = settings["XNU_CRYPTO_BOOTSTRAP"] == "prelinked"
    prefix = ("qemu-" if args.profile == "qemu" else "") + ("prelink-" if prelink_input else "")
    status = ctx.work / (prefix + "source-build-status.json")

    def run(name, command, overrides=None):
        if name in ("bootstrap", "kernel"):
            # This is a generated clone, separate from both reference trees.
            # Device and upstream hooks overlap, so selective reversal can leave
            # half of a series behind after a context change. Save its exact
            # state, then replay all patches from the pinned clean base.
            work = ctx.tree / ".cache/xnu-work"
            if (work / ".git").exists():
                assert work.resolve() == (ctx.tree / ".cache/xnu-work").absolute()
                head = subprocess.check_output(["git", "-C", work, "rev-parse", "HEAD"])
                reference = subprocess.check_output(["git", "-C", ctx.tree / "refer/xnu", "rev-parse", "HEAD"])
                if head != reference:
                    raise ValueError("Generated XNU clone differs from its pinned reference")
                (logdir / "source-before-rebuild.patch").write_bytes(subprocess.check_output(
                    ["git", "-C", work, "diff", "--binary", "HEAD"]))
                (logdir / "source-before-rebuild-status.txt").write_bytes(subprocess.check_output(
                    ["git", "-C", work, "status", "--porcelain"]))
                subprocess.run(["git", "-C", work, "restore", "--source=HEAD", "--worktree", "--staged", "--", "."], check=True)
                tracked = set(subprocess.check_output(["git", "-C", work, "ls-files", "-z"]).decode().split("\0"))
                created = set()
                patches = [*(ctx.tree / "patches/xnu").glob("*.patch"),
                           *(ctx.tree / "kits/NativePrelink/patches").glob("*.patch"),
                           *(ctx.device / "patches/lemonades-xnu").glob("*.patch")]
                for patch in patches:
                    lines = patch.read_text().splitlines()
                    for before, after in zip(lines, lines[1:]):
                        if before == "--- /dev/null" and after.startswith("+++ b/"):
                            created.add(after[6:])
                removed = []
                for relative in sorted(created - tracked):
                    source = work / relative
                    if not source.exists():
                        continue
                    assert source.is_file() and not source.is_symlink() and source.resolve().is_relative_to(work.resolve())
                    data = source.read_bytes()
                    backup = logdir / "source-before-rebuild-created-files" / relative
                    backup.parent.mkdir(parents=True, exist_ok=True)
                    backup.write_bytes(data)
                    assert backup.read_bytes() == source.read_bytes()
                    removed.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "backup": str(backup)})
                    source.unlink()
                (logdir / "source-before-rebuild-created-files.json").write_text(json.dumps(removed, indent=2)+"\n")
            obj = ctx.tree / "build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837"
            # Trace mode and bootstrap/provider flags are not Make prerequisites.
            for relative in ("osfmk/DEVELOPMENT/start.o", "osfmk/DEVELOPMENT/arm_init.o",
                             "osfmk/DEVELOPMENT/startup.o", "pexpert/DEVELOPMENT/pe_init.o",
                             "osfmk/DEVELOPMENT/machine_routines.o", "osfmk/DEVELOPMENT/debug.o",
                             "osfmk/DEVELOPMENT/prng_random.o",
                             "iokit/DEVELOPMENT/IOPlatformExpert.cpo",
                             "iokit/DEVELOPMENT/IOKitBSDInit.cpo",
                             "iokit/DEVELOPMENT/KernelConfigTables.cpo",
                             "bsd/DEVELOPMENT/bsd_init.o",
                             "mach.development.bcm2837.unstripped.noctf"):
                (obj / relative).unlink(missing_ok=True)
        print(f"{name}: {logdir / (name + '.log')}", flush=True)
        with (logdir / (name + ".log")).open("w") as stream:
            result = subprocess.run(command, cwd=ctx.tree, env={**env, **(overrides or {})},
                                    stdout=stream, stderr=subprocess.STDOUT)
        report["steps"].append({"name": name, "exit_code": result.returncode})
        status.write_text(json.dumps(report, indent=2) + "\n")
        if result.returncode:
            print("\n".join((logdir / (name + ".log")).read_text(errors="replace").splitlines()[-25:]))
            raise SystemExit(result.returncode)

    build = ["bash", *(["-x"] if os.environ.get("LEMONADES_BASH_X") else []),
            "scripts/build-xnu-4k-baseline.sh"]
    if args.stage in ("all", "bootstrap"):
        # This pass supplies compile records and symbol tables for the real providers.
        # It is not a runnable kernel and is never packaged as a payload.
        # The umi flow reuses an earlier bootstrap for owner-root builds; a
        # fresh all-in-one run must zero the storage flags too, or the
        # baseline's NativeAES prelinked-closure assertion fires on this pass.
        run("bootstrap", build, {k: "0" for k in (
            "XNU_SOURCE_CORECRYPTO14", "XNU_SOURCE_PTHREAD", "XNU_ARM_DT_PLATFORM",
            "XNU_ARMCPU", "XNU_NATIVE_ARCH_TIMER", "XNU_BOOT_PROGRESS",
            "LEMONADES_PMGR", "XNU_NATIVE_AES", "XNU_NATIVE_VIRTIO_BLOCK",
            "XNU_VERIFIED_ROOT_PROBE", "XNU_OWNER_ROOT_AUDIT",
            "XNU_OWNER_ROOT_TRUST", "XNU_TRUST_CACHE_RUNTIME",
            "XNU_OWNER_CACHE_MOUNT", "XNU_OWNER_CACHE_STARTUP",
            "XNU_OWNER_BOOT_MANIFEST", "XNU_OWNER_UNION_SYSTEMOS",
            "XNU_NATIVE_CS_HASH_CACHE")})
    if args.stage in ("all", "libraries"):
        run("corecrypto-plain", ["python3", "scripts/build-corecrypto-14.py"])
        run("corecrypto-namespace", ["python3", "scripts/build-corecrypto-14.py", "--namespace"])
        run("pthread", ["python3", "scripts/build-libpthread-kernel.py"])
        run("ArmDTPlatform", ["python3", "scripts/build-lemonades-arm-driver.py", "ArmDTPlatform"])
    if args.stage in ("all", "libraries", "kernel"):
        # Always rebuild: a previous profile's archive may contain phone-only
        # tracing or a diagnostic overlay that is not a kernel Make prerequisite.
        run("ArmCpu", [sys.executable, "scripts/build-lemonades-arm-driver.py", "ArmCpu",
                      *(["--gic-diagnostics", args.profile] if args.gic_diagnostics else [])])
    if args.stage in ("all", "kernel"):
        if args.reuse_storage_from:
            if not (args.native_ufs and args.owner_root == "trust" and data_input):
                parser.error("Storage reuse requires the complete phone storage profile")
            from reuse_lemonades_storage import restore
            report["storage_reuse"] = restore(args.reuse_storage_from, ctx.tree)
        if args.native_ufs and not args.reuse_storage_from:
            run("native-ufs", [sys.executable, str(ROOT / "tools/build_lemonades_native_ufs.py"),
                              "--profile", args.profile]
                + (["--verified-root"] if args.verified_root else [])
                + (["--boot-progress"] if args.screen_diagnostics else []))
            if args.verified_root:
                # The pinned recipe requires the virtio provider for owner-root
                # trust; this profile substitutes the native UFS query.
                recipe = ctx.tree / "scripts/build-xnu-4k-baseline.sh"
                text = recipe.read_text()
                gate = ('if [ "$OWNER_ROOT_TRUST" = 1 ] && { [ "$OWNER_ROOT_AUDIT" != 1 ] || '
                        '[ "${XNU_NATIVE_VIRTIO_BLOCK:-0}" != 1 ]; }; then')
                assert gate in text, "owner-root trust gate changed"
                recipe.write_text(text.replace(gate, 'if [ "$OWNER_ROOT_TRUST" = 1 ] && [ "$OWNER_ROOT_AUDIT" != 1 ]; then'))
                # The audit's vfs_devvp/vnode_put pair is not needed: rootdev
                # names the same mounted device and both calls take vnode
                # locks in a preemptible bsd_init context. Trim them from the
                # pinned patch.
                audit = ctx.tree / "patches/xnu/offline-owner-root-binding-audit.patch"
                text = audit.read_text()
                for line in ("+\t\t\t\tvnode_t device_vnode = vfs_devvp(root_mount);\n",
                             "+\t\t\t\tif (device_vnode) vnode_put(device_vnode);\n"):
                    assert line in text, "audit patch line changed"
                    text = text.replace(line, "")
                for old_line, new_line in (
                        ("+\t\t\t\tdev_t device = device_vnode ? vnode_specrdev(device_vnode) : NODEV;\n",
                         "+\t\t\t\tdev_t device = rootdev;\n"),
                        ("+\t\t\t\tint owner = readonly && device_vnode && native_verified_block_root_authorized(device);\n",
                         "+\t\t\t\tint owner = readonly && native_verified_block_root_authorized(device);\n")):
                    assert old_line in text, "audit patch line changed"
                    text = text.replace(old_line, new_line)
                assert "@@ -987,9 +987,41 @@" in text
                audit.write_text(text.replace("@@ -987,9 +987,41 @@", "@@ -987,9 +987,39 @@"))
                # The SystemOS mount failed with EFTYPE (80) before any media
                # diagnostics existed. Record the exact failing stage, the
                # selected device path and the actual mount return status so
                # the panic screen can attribute the failure precisely.  The
                # replacement stays a single added line so the hunk counts in
                # the pinned diff remain valid.
                systemos = ctx.tree / "patches/xnu/offline-owner-systemos-mount.patch"
                text = systemos.read_text()
                panic_old = '+\tif (cache_error) panic("offline owner SystemOS mount failed: %d", cache_error);\n'
                assert panic_old in text, "systemos panic line"
                text = text.replace(panic_old,
                    '+\tif (cache_error) panic("offline owner SystemOS mount failed: %d stage=%d mount=%d dev=%s auth=%d rc=%d", cache_error, native_owner_cache_stage, native_owner_cache_mount_status, native_owner_cache_device_path[0] ? native_owner_cache_device_path : "-", native_owner_cache_authorized, native_owner_cache_root_recheck);\n')
                # Union mode leaves envp NULL, so dyld searches the default
                # cryptex paths (/System/Cryptexes/OS/...) and finds no shared
                # cache. Point DYLD_SHARED_CACHE_DIR at the real cache dir via
                # the query-module helper (probed with vnode_lookup).
                envp_old = '+\t*envp = USER_ADDR_NULL;\n'
                assert envp_old in text, "systemos envp line"
                text = text.replace(envp_old,
                    '+\t*envp = native_owner_cache_envp(scratch);\n')
                # The helper's extern needs one more added line in the big
                # prepare-function hunk.
                extern_old = '+extern int native_verified_block_volume_device(const char *, dev_t *, char *, size_t);\n'
                assert extern_old in text, "extern anchor"
                text = text.replace(extern_old,
                    extern_old + '+extern user_addr_t native_owner_cache_envp(user_addr_t);\n')
                hunk_old = '@@ -7013,8 +7013,256 @@'
                assert hunk_old in text, "big hunk header"
                text = text.replace(hunk_old, '@@ -7013,8 +7013,257 @@')
                systemos.write_text(text)
                # zzz-boot-progress.patch carries the old line as hunk context;
                # the assembled tree applies that patch after this one.
                bootsys = ctx.tree / "patches/xnu/zzz-boot-progress.patch"
                text = bootsys.read_text()
                ctx_old = ' \tif (cache_error) panic("offline owner SystemOS mount failed: %d", cache_error);\n'
                assert ctx_old in text, "boot-progress systemos context"
                text = text.replace(ctx_old,
                    ' \tif (cache_error) panic("offline owner SystemOS mount failed: %d stage=%d mount=%d dev=%s auth=%d rc=%d", cache_error, native_owner_cache_stage, native_owner_cache_mount_status, native_owner_cache_device_path[0] ? native_owner_cache_device_path : "-", native_owner_cache_authorized, native_owner_cache_root_recheck);\n')
                bootsys.write_text(text)
                run("root-policy", [sys.executable, str(ROOT / "tools/build_lemonades_root_bundle.py"),
                                    "--external"])
            elif args.owner_root != "off":
                run("root-policy", [sys.executable, str(ROOT / "tools/build_lemonades_root_bundle.py")])
        if args.owner_root != "off" and not args.reuse_storage_from:
            run("storage-providers", [sys.executable, str(ROOT / "tools/build_lemonades_storage_providers.py"),
                "--snapshot", str(ROOT / "out/lemonades-qemu/29-aes-live-metadata/gdb-stop.json")])
        for component, selected in (("ram", bool(data_input) and not args.reuse_storage_from), ("display", args.legacy_display)):
            if selected:
                run("original-" + component, [sys.executable, str(ROOT / "tools/build_lemonades_data_display.py"), "--component", component])
        if args.fts_touch:
            run("fts-touch", [sys.executable, str(ROOT / "tools/build_lemonades_touch.py")])
        if data_input:
            run("original-mockfs", [sys.executable, "scripts/build-mockfs-fixture.py"])
        if args.ufs_probe:
            run("ufs-probe", [sys.executable, "scripts/build-lemonades-ufs-probe.py"])
        if args.pmgr:
            # Only refresh this compile-time mode for the library. Device
            # patches must be reversed as a series before reapplying them;
            # the kernel recipe and prepare hook handle that below.
            # The kits sources include the umi-era config header name/macro.
            (ctx.tree / ".cache/xnu-work/osfmk/arm64/umi_early_trace_config.h").write_text(
                f"#define UMI_EARLY_TRACE {int(args.early_trace)}\n")
            prelinked = ROOT / "out/lemonades-xnu/lemonades/kernel/kernel.macho"
            donor = ROOT / "out/lemonades-xnu/ipsw/21H461/kernelcache.decompressed"
            if prelinked.is_file():
                run("pmgr", [sys.executable, "scripts/build-lemonades-platform-power.py",
                             "--candidate", str(prelinked), "--donor", str(donor)])
            else:
                # A fresh workspace has no prelink plan yet (that is produced
                # where the donor IPSW is decoded, on the Linux host); build
                # the archive without the contract audit.
                run("pmgr", [sys.executable, "scripts/build-lemonades-platform-power.py",
                             "--donor", str(donor)])
        run("kernel", build)
        kernel = ctx.tree / "build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/mach.development.bcm2837.unstripped.noctf"
        data = kernel.read_bytes()
        if struct.unpack_from("<4I", data) != (0xfeedfacf, 0x100000c, 0, 2):
            raise SystemExit("Unexpected source-kernel Mach-O header")
        destination = ctx.work / "kernel" / (prefix + (
            "entry-trace-kernel.macho" if args.early_trace else "source-kernel.macho"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(kernel, destination)
        report.update(kernel=str(destination), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        if args.pmgr:
            report["pmgr_build"] = json.loads((ctx.tree / "build/lemonades-platform-power/build-report.json").read_text())
        report["armcpu_build"] = json.loads((ctx.tree / "build/armcpu/build-report.json").read_text())
        if args.screen_diagnostics:
            report["screen_build"] = json.loads((ctx.tree / "build/boot-progress/build-report.json").read_text())
        if args.ufs_probe:
            report["ufs_probe_build"] = json.loads((ctx.tree / "build/lemonades-ufs-probe/build-report.json").read_text())
        if args.native_ufs:
            report["native_ufs_build"] = json.loads((ctx.tree / "build/native-ufs/build-report.json").read_text())
            root_policy = ctx.tree / "build/lemonades-root-policy/build-report.json"
            if args.owner_root != "off" or root_policy.is_file():
                report["root_policy_build"] = json.loads(root_policy.read_text())
        if args.owner_root != "off":
            report["storage_providers_build"] = json.loads((ctx.tree / "build/lemonades-storage-providers/build-report.json").read_text())
        if data_input:
            report["ram_block_build"] = json.loads((ctx.tree / "build/native-ram-block/build-report.json").read_text())
        if args.fts_touch:
            report["touch_build"] = json.loads((ctx.tree / "build/lemonades-touch/build-report.json").read_text())
        if args.legacy_display:
            report["legacy_display_build"] = json.loads((ctx.tree / "build/native-legacy-display/build-report.json").read_text())
        lock_inputs = [
            ctx.device / "scripts/lemonades-lock-trace.h",
            ctx.device / "patches/lemonades-xnu/zzzzzzzzz-lemonades-lock-trace.patch",
        ]
        if all(p.is_file() for p in lock_inputs):
            report["lock_failure_trace"] = {
                str(rel(p)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in lock_inputs
            }
    exec_inputs = [ROOT / "devices/lemonades/scripts/lemonades-exec-trace.h",
                   ROOT / "devices/lemonades/patches/lemonades-xnu/zzzzzzzzzz-lemonades-exec-trace.patch",
                   ROOT / "devices/lemonades/patches/lemonades-xnu/zzzzzzzzzzz-lemonades-exec-retry-trace.patch"]
    report["execution_trace"] = {
        str(rel(p)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in exec_inputs
    }
    exit_patch = ROOT / "devices/lemonades/patches/lemonades-xnu/zzzzzzzzzzzz-lemonades-critical-exit-trace.patch"
    report["critical_exit_trace"] = {str(rel(exit_patch)):
                                   hashlib.sha256(exit_patch.read_bytes()).hexdigest()}
    if args.systemos:
        inputs = [ROOT / "devices/lemonades/patches/lemonades-xnu/zzzzzzzzzzzzz-lemonades-systemos-trace.patch"]
        inputs += [ROOT / "sources/UniXNU/patches/xnu" / name for name in (
            "offline-owner-systemos-mount.patch", "offline-owner-boot-manifest.patch",
            "native-4k-signature-hash-cache.patch")]
        report["systemos_sources"] = {str(rel(p)): hashlib.sha256(p.read_bytes()).hexdigest()
                                     for p in inputs}
    report["success"] = True
    status.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
