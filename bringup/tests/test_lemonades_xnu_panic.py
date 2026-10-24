#!/usr/bin/env python3
"""Check the compiled DT panic path and execute its actual C with host DT/I/O adapters."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TREE = ROOT / "out/lemonades-xnu/lemonades/tree"


def panic_function(source):
    start = source.index("static void\ncheck_for_panic_log(void)")
    end = source.index("\nint\nPE_initialize_console", start)
    return source[start:end]


class PanicRegionTests(unittest.TestCase):
    def test_real_compile_uses_dt_and_excludes_bcm_address(self):
        record = TREE / "build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/pexpert/DEVELOPMENT/pe_init.o.json"
        compile = json.loads(record.read_text().rstrip().rstrip(","))
        args = compile["arguments"]
        self.assertIn("XNU_DT_PANIC_REGION=1", args)
        command = []
        it = iter(args)
        for arg in it:
            if arg == "-o":
                next(it)
            elif arg != "-c":
                command.append(arg)
        command += ["-E", "-P"]
        result = subprocess.run(command, cwd=compile["directory"], check=True,
                                capture_output=True, text=True)
        body = panic_function(result.stdout)
        self.assertIn('SecureDTLookupEntry(0, "pram"', body)
        self.assertNotIn("0x3c0fc000", body.lower())

    def test_missing_malformed_and_valid_regions(self):
        source = (TREE / ".cache/xnu-work/pexpert/arm/pe_init.c").read_text()
        prelude = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#define XNU_DT_PANIC_REGION 1
/* Keep the fallback defined so an incorrect selector fails the I/O assertions. */
#define PLATFORM_PANIC_LOG_PADDR 0x3c0fc000
#define PLATFORM_PANIC_LOG_SIZE 16384
#define kSuccess 0
#define TRUE 1
#define EMBEDDED_PANIC_MAGIC 0x46554e4b
typedef void *DTEntry;
typedef uintptr_t vm_offset_t;
struct embedded_panic_header { uint32_t eph_magic; uint32_t reserved[5]; };
static unsigned char arena[128];
static vm_offset_t gPanicBase;
static unsigned int gPanicSize, panic_text_len;
static struct embedded_panic_header *panic_info;
static int panic_console_available, mode, mappings;
static uintptr_t reg[2];
static uint32_t length;
static int SecureDTLookupEntry(void *root, const char *name, DTEntry *entry) {
 (void)root;
 if (!strcmp(name,"pram")) {
  if(mode==0) return -1;
  *entry=(void *)1; return 0;
 }
 assert(!strcmp(name,"/chosen"));
 if(mode==6) return -1;
 *entry=(void *)2; return 0;
}
static int SecureDTGetProperty(DTEntry entry, const char *name, const void **out,
                               unsigned int *size) {
 if(entry==(void *)1) {
  assert(!strcmp(name,"reg"));
  if(mode==1) return -1;
  *out=reg; *size=mode==2?8:sizeof(reg); return 0;
 }
 assert(entry==(void *)2 && !strcmp(name,"embedded-panic-log-size"));
 if(mode==7) return -1;
 *out=&length; *size=mode==8?8:sizeof(length); return 0;
}
static vm_offset_t ml_io_map_wcomb(uintptr_t pa, unsigned int bytes) {
 assert(pa==0x12340000 && bytes==sizeof(arena));
 mappings++;
 return mode==11?0:(uintptr_t)arena;
}
'''
        main = r'''
int main(void) {
 for(mode=0;mode<=14;mode++) {
  gPanicBase=gPanicSize=panic_text_len=0; panic_info=NULL;
  panic_console_available=mappings=0;
  reg[0]=0x12340000; reg[1]=sizeof(arena); length=sizeof(arena);
  memset(arena,0xa5,sizeof(arena));
  if(mode==3) reg[0]=0;
  if(mode==4) reg[1]=1;
  if(mode==5) reg[0]=UINTPTR_MAX-4;
  if(mode==9) length=1;
  if(mode==10) length=sizeof(arena)+1;
  if(mode==13) ((struct embedded_panic_header *)arena)->eph_magic='SHMC';
  if(mode==14) ((struct embedded_panic_header *)arena)->eph_magic='BTRC';
  check_for_panic_log();
  if(mode<=11) {
   assert(mappings==(mode==11));
   assert(!gPanicBase && !gPanicSize && !panic_info);
   for(unsigned int i=0;i<sizeof(arena);i++) assert(arena[i]==0xa5);
  } else {
   assert(mappings==1 && gPanicBase==(uintptr_t)arena && gPanicSize==sizeof(arena));
   assert(panic_text_len==sizeof(arena)-sizeof(struct embedded_panic_header));
   assert(panic_info==(void *)arena);
   if(mode==12) for(unsigned int i=0;i<sizeof(arena);i++) assert(arena[i]==0);
   else assert(arena[sizeof(arena)-1]==0xa5);
   assert(panic_console_available==(mode==13));
  }
 }
 puts("actual panic function: missing/malformed/overflow/map-failure/valid/shared-buffer PASS");
}
'''
        with tempfile.TemporaryDirectory(prefix="lemonades-panic-region-") as tmp:
            c, exe = Path(tmp) / "test.c", Path(tmp) / "test"
            c.write_text(prelude + panic_function(source) + main)
            subprocess.run(["clang", "-std=c11", "-D_DEFAULT_SOURCE", "-Wall", "-Wextra",
                            "-Werror", "-Wno-multichar", "-fsanitize=address,undefined",
                            str(c), "-o", str(exe)], check=True)
            subprocess.run([str(exe)], check=True)


if __name__ == "__main__":
    unittest.main()
