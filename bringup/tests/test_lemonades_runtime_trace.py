"""Run the actual bounded C writer, then reject corrupt/incomplete snapshots."""
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from lemonades_runtime_trace import decode_runtime_trace


class RuntimeTraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="lemonades-live-wire-")
        cls.work = Path(cls.temp.name)
        source = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "LemonadesRuntimeWire.h"
int main(int argc,char **argv) {
  assert(argc==2);FILE *f=fopen(argv[1],"wb");assert(f);
  const unsigned total=0x200000,cap=total-12;
  unsigned char *arena=malloc(total+64),*copy=malloc(total+64);assert(arena && copy);
  const unsigned samples[]={1,2,8};
  for(unsigned ix=0;ix<3;++ix) {
    unsigned sample=samples[ix];
    memset(arena,0xa5,total+64);uint32_t *h=(void *)(arena+32);
    h[0]=0x43474244;h[1]=sample==1?0:cap-7;h[2]=sample==1?0:cap;
    uint64_t v[LEMONADES_RUNTIME_FIELDS];for(unsigned i=0;i<LEMONADES_RUNTIME_FIELDS;++i)v[i]=0x11220000+i;
    v[0]=2;v[1]=sample;v[2]=sample==1?10:sample==2?30:300;
    v[203]=0xfffffffe; // CPU1 PSCI denied; preserve the signed result.
    assert(lemonades_runtime_write(h,sample,v));
    assert(h[1]<cap && h[2]<=cap);
    for(unsigned i=0;i<32;++i)assert(arena[i]==0xa5 && arena[total+32+i]==0xa5);
    unsigned char *data=(void *)(h+3);unsigned start=h[2]==cap?h[1]:0;
    for(unsigned i=0;i<h[2];++i)fputc(data[(start+i)%cap],f);
    memcpy(copy,arena,total+64);
    assert(!lemonades_runtime_write(h,0,v) && !memcmp(arena,copy,total+64));
    assert(!lemonades_runtime_write(h,9,v) && !memcmp(arena,copy,total+64));
    h[0]=0;memcpy(copy,arena,total+64);
    assert(!lemonades_runtime_write(h,sample,v) && !memcmp(arena,copy,total+64));
    assert(!lemonades_runtime_write(NULL,sample,v));
    h[0]=0x43474244;h[1]=cap+1;memcpy(copy,arena,total+64);
    assert(!lemonades_runtime_write(h,sample,v) && !memcmp(arena,copy,total+64));
  }
  fclose(f);free(copy);free(arena);
}
'''
        c = cls.work / "writer.c"
        c.write_text(source)
        exe = cls.work / "writer"
        subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", "-I", str(ROOT / "devices/lemonades/package/boot-progress"),
                        str(c), "-o", str(exe)], check=True)
        output = cls.work / "ring.bin"
        subprocess.run([str(exe), str(output)], check=True)
        cls.raw = output.read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_actual_writer_empty_and_wrapped_ring(self):
        decoded = decode_runtime_trace(self.raw)
        self.assertEqual(len(decoded["samples"]), 3)
        self.assertEqual(decoded["crc_valid_records"], 248*5*3)
        self.assertFalse(decoded["incomplete_samples"])
        self.assertEqual(decoded["samples"][1]["seconds"], 30)
        self.assertEqual(decoded["samples"][2]["seconds"], 300)
        self.assertEqual(decoded["samples"][0]["free_pages"], 0x11220004)
        smp = decoded["samples"][0]["smp"]
        self.assertEqual(len(smp["cores"]), 8)
        self.assertEqual(smp["cores"][1]["psci_rc"], -2)
        self.assertEqual(smp["cores"][7]["ipi_irqs"], 0x11220000+247)

    def test_legacy_phone_records_remain_decodable(self):
        rows = []
        for sample, field, value, _ in re.findall(rb"\nUMI LIVE ([0-9a-f]{2}) ([0-9a-f]{2}) ([0-9a-f]{16}) ([0-9a-f]{8})\n", self.raw):
            sample, field, value = (int(v, 16) for v in (sample, field, value))
            if field >= 176:
                continue
            if field == 0:
                value = 1
            crc = zlib.crc32(struct.pack("<BBQ", sample, field, value))
            rows.append(f"\nUMI LIVE {sample:02x} {field:02x} {value:016x} {crc:08x}\n".encode())
        decoded = decode_runtime_trace(b"".join(rows))
        self.assertEqual(len(decoded["samples"]), 3)
        self.assertNotIn("smp", decoded["samples"][0])

    def test_missing_smp_field_is_not_accepted(self):
        raw = re.sub(rb"\nUMI LIVE 01 f7 [0-9a-f]{16} [0-9a-f]{8}\n", b"", self.raw)
        decoded = decode_runtime_trace(raw)
        self.assertEqual(decoded["incomplete_samples"], [1])
        self.assertEqual(len(decoded["samples"]), 2)

    def test_corrupt_copy_uses_only_other_valid_copies(self):
        raw = self.raw.replace(b"0000000011220004", b"00000000112200f4", 1)
        decoded = decode_runtime_trace(raw)
        self.assertEqual(len(decoded["samples"]), 3)
        self.assertEqual(decoded["crc_rejected_records"], 1)

    def test_missing_field_is_not_accepted(self):
        raw = re.sub(rb"\nUMI LIVE 01 04 [0-9a-f]{16} [0-9a-f]{8}\n", b"", self.raw)
        decoded = decode_runtime_trace(raw)
        self.assertEqual(decoded["incomplete_samples"], [1])
        self.assertEqual(len(decoded["samples"]), 2)

    def test_conflicting_valid_copy_is_not_majority_voted(self):
        value = 123
        crc = zlib.crc32(struct.pack("<BBQ", 1, 4, value))
        extra = f"\nUMI LIVE 01 04 {value:016x} {crc:08x}\n".encode()
        decoded = decode_runtime_trace(self.raw + extra)
        self.assertEqual(decoded["conflicting_samples"], [1])
        self.assertEqual(len(decoded["samples"]), 2)


if __name__ == "__main__":
    unittest.main()
