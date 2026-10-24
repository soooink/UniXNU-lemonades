#!/usr/bin/env python3
"""Run the firmware's actual Mach-O parser against the selected lemonades kernel."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from test_lemonades_payload import function

ROOT = Path(__file__).resolve().parents[1]


class DarwinBootKernelTests(unittest.TestCase):
    def test_registration_without_text_console(self):
        source = (ROOT / "out/lemonades-menu-package/DarwinBootPkg/Driver/DarwinBoot.c").read_text()
        entry = source[source.index("EFI_STATUS\nEFIAPI\nDarwinBootEntry"):]
        harness = r'''
#include <assert.h>
#include <stddef.h>
#define EFIAPI
#define VOID void
#define EFI_STATUS int
#define EFI_HANDLE void *
#define EFI_SYSTEM_TABLE void
#define EFI_ERROR(s) ((s)!=0)
#define EFI_ALREADY_STARTED 20
#define DEBUG(args) do {} while(0)
/* Model Print's NULL-ConOut assertion, not a successful fake console. */
#define Print(...) assert(!"Print called before ConOut exists")
typedef struct { void *Unload; } EFI_LOADED_IMAGE_PROTOCOL;
static EFI_LOADED_IMAGE_PROTOCOL loaded;
static int gUniXNULoaderProtocolGuid, gEfiLoadedImageProtocolGuid, mLoader, installed;
static void *mImage;
static void Unload(void) {}
static int locate(void *guid, void *registration, void **out) {
  (void)guid; (void)registration; (void)out; return 14;
}
static int handle(void *image, void *guid, void **out) {
  (void)image; (void)guid; *out=&loaded; return 0;
}
static int install(void **image, void *guid, void *protocol, void *end) {
  assert(*image == (void *)1);
  assert(guid == &gUniXNULoaderProtocolGuid && protocol == &mLoader && !end);
  installed++; return 0;
}
static struct {
 int (*LocateProtocol)(void *,void *,void **);
 int (*HandleProtocol)(void *,void *,void **);
 int (*InstallMultipleProtocolInterfaces)(void **,void *,void *,void *);
} bs={locate,handle,install}, *gBS=&bs;
'''
        main = r'''
int main(void) {
 assert(DarwinBootEntry((void *)1, NULL) == 0);
 assert(installed == 1 && mImage == (void *)1 && loaded.Unload == Unload);
}
'''
        with tempfile.TemporaryDirectory(prefix="lemonades-darwin-register-") as directory:
            work = Path(directory)
            c, exe = work / "registration.c", work / "registration"
            c.write_text(harness + entry + main)
            subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=address,undefined", str(c), "-o", str(exe)], check=True)
            subprocess.run([str(exe)], check=True)

    def test_actual_kernel_and_rejected_mutations(self):
        payload = json.loads((ROOT / "out/lemonades/payload/payload.json").read_text())
        baseline = payload["xnu"]["kernel"]
        kernel = Path(baseline["kernel"]).read_bytes()
        self.assertEqual(hashlib.sha256(kernel).hexdigest(), baseline["sha256"])
        source = (ROOT / "out/lemonades-menu-package/DarwinBootPkg/Driver/DarwinBoot.c").read_text()
        types = source[source.index("typedef struct {"):source.index("STATIC EFI_HANDLE")]
        prelude = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define STATIC static
#define CONST const
#define VOID void
#define UINT8 uint8_t
#define UINT32 uint32_t
#define UINT64 uint64_t
#define UINTN size_t
#define BOOLEAN int
#define TRUE 1
#define FALSE 0
#define EFI_STATUS int
#define EFI_SUCCESS 0
#define EFI_UNSUPPORTED 3
#define EFI_LOAD_ERROR 1
#define MAX_UINT64 UINT64_MAX
#define MAX_SEGMENTS 64
#define WINDOW_SIZE (256ULL << 20)
#define SIZE_2MB (2ULL << 20)
#define EFI_PAGE_MASK 4095
#define MIN(a,b) ((a)<(b)?(a):(b))
#define MAX(a,b) ((a)>(b)?(a):(b))
#define ZeroMem(p,n) memset(p,0,n)
static uint32_t U32(const void *p) { uint32_t v; memcpy(&v,p,4); return v; }
static uint64_t U64(const void *p) { uint64_t v; memcpy(&v,p,8); return v; }
'''
        main = r'''
int main(int argc, char **argv) {
  assert(argc == 3);
  FILE *f = fopen(argv[1], "rb"); assert(f);
  assert(fseek(f,0,SEEK_END)==0); long n=ftell(f); assert(n>0); rewind(f);
  uint8_t *p=malloc((size_t)n); assert(p);
  assert(fread(p,1,(size_t)n,f)==(size_t)n); fclose(f);
  KERNEL k;
  int result=ParseKernel(p,(size_t)n,&k);
  assert((result==EFI_SUCCESS)==atoi(argv[2]));
  if(result==EFI_SUCCESS) {
    assert(k.Base == 0xfffffff007004000ULL);
    assert(k.Entry == 0xfffffff0073f9488ULL);
    assert(k.End-k.Base == 20152320);
    uint64_t physical=0xc0000000ULL+(k.Base & 0x1fffff);
    assert((physical & 0x1fffff) == (k.Base & 0x1fffff));
    assert(physical+WINDOW_SIZE <= 0xe0000000ULL);
  }
  free(p);
}
'''
        with tempfile.TemporaryDirectory(prefix="lemonades-darwin-parse-") as directory:
            work = Path(directory)
            c = work / "parser.c"
            exe = work / "parser"
            main = main.replace("0xfffffff007004000", baseline["virtual_base"])
            main = main.replace("0xfffffff0073f9488", baseline["entry"])
            main = main.replace("20152320", str(baseline["virtual_span_bytes"]))
            c.write_text(prelude + types + function(source, "ParseKernel") + main)
            subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=address,undefined", str(c), "-o", str(exe)], check=True)
            cases = [("source", kernel, True), ("truncated", kernel[:128], False)]
            for name, offset, value in (("arm64e", 8, 2), ("fileset", 12, 12),
                                        ("oversized-commands", 20, 0xffffffff)):
                altered = bytearray(kernel)
                struct.pack_into("<I", altered, offset, value)
                cases.append((name, altered, False))
            for name, data, valid in cases:
                with self.subTest(name=name):
                    path = work / (name + ".macho")
                    path.write_bytes(data)
                    subprocess.run([str(exe), str(path), str(int(valid))], check=True)


if __name__ == "__main__":
    unittest.main()
