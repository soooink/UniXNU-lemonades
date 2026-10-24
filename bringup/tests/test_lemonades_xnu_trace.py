#!/usr/bin/env python3
"""Execute the actual AArch64 leaf trace writer on guarded host RAM."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class TraceTests(unittest.TestCase):
    def test_actual_assembly_ring_bounds_and_wrap(self):
        assembly = (ROOT / "devices/lemonades/scripts/lemonades-early-trace.inc").read_text()
        # The production wrapper now masks IRQ/FIQ with privileged DAIF
        # instructions. Host EL0 can execute the exact ring writer body, but
        # cannot execute the EL1 interrupt mask. Build-time ARM64 inspection
        # separately verifies that the production wrapper retains all three.
        for instruction in ("\tmrs\tx3, daif\n", "\tmsr\tdaifset, #3\n", "\tmsr\tdaif, x3\n"):
            self.assertEqual(assembly.count(instruction), 1)
            assembly = assembly.replace(instruction, "")
        harness = r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
extern void lemonades_early_trace(unsigned long, unsigned long, unsigned long);
#define CAP (0x200000-12)
static unsigned char arena[0x200000+64];
static unsigned char before[sizeof(arena)];
static void check(uint32_t start, uint32_t size) {
 memset(arena,0xa5,sizeof(arena));
 uint32_t *h=(void *)(arena+32);
 h[0]=0x43474244;h[1]=start;h[2]=size;
 unsigned char *data=(void *)(h+3);
 const char *expected="\nUMI XNU 21 fedcba9876543210\n";
 size_t count=strlen(expected);
 lemonades_early_trace(0x21,0xfedcba9876543210UL,(unsigned long)h);
 for(size_t i=0;i<count;i++) assert(data[(start+i)%CAP]==(unsigned char)expected[i]);
 assert(h[1]==(start+count)%CAP);
 assert(h[2]==(size+count>CAP?CAP:size+count));
 for(int i=0;i<32;i++) assert(arena[i]==0xa5 && arena[0x200000+32+i]==0xa5);
}
int main(void) {
 check(0,0);check(123,456);check(CAP-5,CAP);check(CAP,CAP);
 uint32_t *h=(void *)(arena+32);
 for(int i=0;i<3;i++) {
  h[0]=0x43474244;h[1]=0;h[2]=0;
  if(i==0)h[0]=0;
  if(i==1)h[1]=1;
  if(i==2)h[2]=CAP+1;
  memcpy(before,arena,sizeof(arena));
  lemonades_early_trace(0x01,0,(unsigned long)h);
  assert(!memcmp(before,arena,sizeof(arena)));
 }
 lemonades_early_trace(0x01,0,0);
 puts("actual trace assembly: empty/existing/wrapped/full/invalid/null PASS");
}
'''
        with tempfile.TemporaryDirectory(prefix="lemonades-xnu-trace-") as tmp:
            work = Path(tmp)
            a, c, exe = work / "trace.S", work / "main.c", work / "test"
            a.write_text("#define EXT(x) _##x\n#define LEXT(x) _##x:\n" + assembly)
            c.write_text(harness)
            subprocess.run(["clang", "-arch", "arm64", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=address,undefined", str(c), str(a), "-o", str(exe)], check=True)
            subprocess.run([str(exe)], check=True)


if __name__ == "__main__":
    unittest.main()
