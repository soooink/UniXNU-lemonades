#!/usr/bin/env python3
"""Validate the lemonades repository and assemble its official UniXNU build tree.

Host-only: no firmware/kernel build, device I/O or IPSW download.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tomllib


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unixnu", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    device = Path(__file__).resolve().parents[1]
    base = args.unixnu.resolve(strict=True)
    out = args.out.resolve()
    require(out != device and device not in out.parents,
            "keep generated validation output outside the device repository")
    board = tomllib.loads((device / "board.toml").read_text())
    pins = json.loads((device / "source-lock.json").read_text())
    commit = subprocess.check_output(
        ["git", "-C", str(base), "rev-parse", "HEAD"], text=True).strip()
    require(commit == pins["UniXNU"], "UniXNU commit differs from source-lock.json")
    require(not subprocess.check_output(
        ["git", "-C", str(base), "status", "--porcelain"], text=True).strip(),
        "the pinned UniXNU base has local changes")
    require(board["board"]["name"] == "lemonades" and board["board"]["soc"] == "SM8250",
            "wrong device identity")
    require(board["board"]["kit"] == "lemonades" and not board["board"].get("example"),
            "device kit must be lemonades, not an example")
    require(board["bootimg"]["image"]["header_version"] == 1
            and board["bootimg"]["image"]["pagesize"] == 4096,
            "boot image differs from the verified lemonades layout")
    config_path = device / "configs" / board["kernel"]["defconfig"]
    # Use the pinned driver's parser and environment mapping, not a second parser.
    sys.path.insert(0, str(base / "scripts"))
    from unixnu.config import parse_config
    config = parse_config(config_path.read_text())
    for key in ("XNU_SOURCE_CORECRYPTO14", "XNU_ARM_DT_PLATFORM", "XNU_ARMCPU",
                "XNU_NATIVE_ARCH_TIMER"):
        require(config.get(key) is True, f"missing minimal source option: {key}")
    for key in ("XNU_SHENG_PMGR", "XNU_NATIVE_UFS", "XNU_NATIVE_ADRENO",
                "XNU_ARMVIRT_PLATFORM", "XNU_OWNER_DATA_MOUNT", "XNU_BOOT_PROGRESS"):
        require(config.get(key) is False, f"unqualified hardware/root option: {key}")
    require(config["XNU_CRYPTO_BOOTSTRAP"] == "source",
            "initial kernel configuration must not assume an IPSW prelink")
    package = device / "package"
    kit = tomllib.loads((package / "Kit.toml").read_text())
    require(kit["schema"] == 1 and kit["kit"]["name"] == "lemonades"
            and kit["match"]["arch"] == "AARCH64", "invalid device kit metadata")
    require(not any(kit.get(k) for k in ("driver", "kext", "overlay")),
            "initial device kit must not claim unqualified drivers")
    menu = tomllib.loads((package / "unixnu.toml").read_text())
    require(menu["version"] == 1 and menu["kits"]["autoload"] is False,
            "unexpected diagnostic menu configuration")
    require([(e["id"], e["type"]) for e in menu["entry"]]
            == [("payload-check", "efi"), ("reset", "action")],
            "diagnostic package must retain the verified EFI/reset entries")
    require(menu["entry"][0]["path"] == "Payloads/LemonadesPayloadCheck.efi",
            "wrong diagnostic application path")
    report_dir = out / "lemonades/repository-validation"
    report_dir.mkdir(parents=True, exist_ok=True)
    common = ["-D", str(device), "--out", str(out)]
    for action, extra in (("defconfig", [config_path.name]), ("tree", []), ("status", [])):
        result = subprocess.run(
            [sys.executable, str(base / "unixnu"), action, *extra, *common],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        (report_dir / f"{action}.log").write_bytes(result.stdout)
        require(result.returncode == 0, f"unixnu {action} failed; see {report_dir}")
    tree = out / "lemonades/tree"
    require((tree / "kits/lemonades").resolve() == package, "device package was not linked")
    require((tree / "package").resolve() == base / "package", "base package was replaced")
    require((out / "lemonades/.config").read_bytes() == config_path.read_bytes(),
            "selected defconfig differs from the repository")
    for driver in ("ArmCpu", "ArmDTPlatform", "DarwinBoot"):
        require((tree / "drivers" / driver).resolve() == base / "drivers" / driver,
                f"unexpected source for generic driver {driver}")
    feeds = {entry["name"]: entry
             for entry in tomllib.loads((base / "feeds.toml").read_text())["source"]}
    device_feeds = device / "feeds.toml"
    if device_feeds.exists():
        feeds.update({entry["name"]: entry
                      for entry in tomllib.loads(device_feeds.read_text())["source"]})
    report = {
        "status": "passed", "scope": "minimal baseline configuration and tree assembly only",
        "device": "lemonades", "soc": "SM8250", "unixnu_commit": commit,
        "defconfig": config_path.name, "config_option_count": len(config),
        "device_package": str((tree / "kits/lemonades").resolve()),
        "generic_drivers": ["ArmCpu", "ArmDTPlatform", "DarwinBoot"],
        "reference_source_pins": {
            name: {"ref": entry.get("ref"), "commit": entry["commit"]}
            for name, entry in feeds.items()
        },
        "reference_sources_fetched": False, "kernel_built": False,
        "kernel_hardware_tested": False, "ipsw_selected": "ipsw" in board,
        "adt_generator_present": (tree / "scripts/make-lemonades-adt.py").is_file(),
        "remaining": ["IPSW identity and prelink qualification", "lemonades ADT hardware handoff",
                      "DarwinBoot memory/handoff", "kernel and driver builds"],
        "files_sha256": {
            str(p.relative_to(device)): digest(p)
            for p in sorted(device.rglob("*"))
            if p.is_file() and not any(x in p.parts for x in (".git", "__pycache__"))
            and p.name != "local.toml"
        },
    }
    (report_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: lemonades defconfig, package resolution and official build tree ({len(config)} options)")
    print(f"Report: {report_dir / 'report.json'}")
    print("This host-only baseline check does not assess the full phone profile; see docs/validation.json.")


if __name__ == "__main__":
    main()
