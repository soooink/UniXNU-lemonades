#!/usr/bin/env python3
"""Compare the exact firmware SHA source with hashlib; optional real image."""
from pathlib import Path
import hashlib
import random
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "devices/lemonades/overlay/Platforms/OnePlus/lemonadesPkg/Application/LemonadesPayload64Check/PayloadSha256.c"


def main():
    with tempfile.TemporaryDirectory(prefix="lemonades-sha256-") as tmp:
        d = Path(tmp)
        (d / "Library").mkdir()
        (d / "Uefi.h").write_text(
            "#include <stdint.h>\n#include <stddef.h>\n"
            "typedef uint8_t UINT8;typedef uint32_t UINT32;"
            "typedef uint64_t UINT64;typedef size_t UINTN;\n")
        (d / "Library/BaseMemoryLib.h").write_text(
            "#include <string.h>\n#define ZeroMem(p,n) memset(p,0,n)\n#define CopyMem memcpy\n")
        (d / "main.c").write_text(r'''
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <Uefi.h>
void PayloadSha256(const UINT8*,UINTN,UINT8[32]);
int main(int argc,char **argv) {
  assert(argc==2);
  FILE *f=fopen(argv[1],"rb");assert(f);
  assert(!fseek(f,0,SEEK_END));long n=ftell(f);assert(n>=0);
  rewind(f);UINT8 *p=malloc(n?n:1),hash[32];assert(p);
  assert(fread(p,1,n,f)==(size_t)n);fclose(f);
  PayloadSha256(p,n,hash);free(p);
  for(unsigned i=0;i<32;i++)printf("%02x",hash[i]);
  puts("");return 0;
}
''')
        exe = d / "check"
        subprocess.run(["clang", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", "-I", str(d), str(SOURCE),
                        str(d / "main.c"), "-o", str(exe)], check=True)
        paths = [Path(s) for s in sys.argv[1:]]
        if not paths:
            rng = random.Random(554)
            cases = [b"", b"abc", b"a" * 1000000]
            cases += [rng.randbytes(n) for n in (1, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 65521)]
            for i, data in enumerate(cases):
                path = d / f"case-{i}"
                path.write_bytes(data)
                paths.append(path)
        for path in paths:
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            actual = subprocess.check_output([str(exe), str(path)], text=True).strip()
            assert actual == expected, path
        print(f"lemonades payload SHA256 PASS: {len(paths)} inputs match hashlib under ASan/UBSan")


if __name__ == "__main__":
    main()
