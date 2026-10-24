#!/usr/bin/env python3
"""Build generic UniXNU and DarwinBoot for QEMU without the phone overlays."""
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sources/UniXNU/scripts"))
from unixnu.util import clang_bin


def main():
    out = ROOT / "out/lemonades-qemu/firmware"
    out.mkdir(parents=True, exist_ok=True)
    edk = ROOT / "sources/uefi-lemonades/Mu_Basecore"
    package = ROOT / "sources/UniXNU/package"
    os.environ["PATH"] = ("/opt/homebrew/opt/llvm/bin:/opt/homebrew/opt/lld/bin:"
                          + os.environ["PATH"])
    env = {
        **os.environ, "UNIXNU_EDK2": str(edk), "UNIXNU_BUILD_DIR": str(out),
        "JOBS": "6", "CLANG_BIN": clang_bin(out / "toolchain"),
        "PYTHON_COMMAND": str(ROOT / "out/venv-lemonades/bin/python3"),
    }
    with (out / "build-package.log").open("w") as log:
        subprocess.run(["bash", str(package / "build.sh")], env=env,
                       stdout=log, stderr=subprocess.STDOUT, check=True)
    env.update(
        WORKSPACE=str(out),
        PACKAGES_PATH=f"{ROOT}/sources/UniXNU/drivers/DarwinBoot:{package}:{edk}",
        EDK_TOOLS_PATH=str(edk / "BaseTools"),
        CONF_PATH=str(out / "Build/Conf"),
    )
    env["PATH"] = (f"{edk}/BaseTools/BinWrappers/PosixLike:"
                   f"{edk}/BaseTools/Source/C/bin:" + env["PATH"])
    with (out / "build-darwinboot.log").open("w") as log:
        subprocess.run(
            ["build", "-p", "DarwinBootPkg/DarwinBoot.dsc", "-a", "AARCH64",
             "-b", "DEBUG", "-t", "CLANGPDB", "-n", "6"],
            cwd=out, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    print(f"Generic QEMU firmware built in {out}")


if __name__ == "__main__":
    main()
