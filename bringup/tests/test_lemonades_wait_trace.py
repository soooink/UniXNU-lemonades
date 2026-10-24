"""Run the actual bounded publication adapter and C wire writer on the host."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from lemonades_wait_trace import decode_wait_trace

SOURCE = r'''
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#define LEMONADES_RUNTIME_TRACE 1
#define LEMONADES_WAIT_HOST 1
#include "BootUiTraceCore.h"
#include "BootUiTraceDetails.h"
static struct bt_main published_main[4];
static struct bt_groups published;
static unsigned published_pid[4],published_busy,published_omitted,trace_lock;
static char published_names[4][32];
static unsigned lemonades_wait_host_seconds;
uint64_t boot_progress_epoch,boot_progress_frequency;
#include "LemonadesWaitTrace.h"
#include "LemonadesUserWire.h"
int main(int argc,char **argv) {
 assert(argc==2);const unsigned total=0x200000;
 unsigned char *arena=malloc(total+64);assert(arena);memset(arena,0xa5,total+64);
 uint32_t *h=(void*)(arena+32);h[0]=0x43474244;h[1]=h[2]=0;
 uint64_t rows[8][64],saved[8][64];memset(rows,0xa5,sizeof(rows));
 memcpy(saved,rows,sizeof(rows));trace_lock=1;
 assert(!lemonades_ui_wait_snapshot(1,120,rows)&&!memcmp(saved,rows,sizeof(rows))&&trace_lock==1);
 trace_lock=0;assert(!lemonades_ui_wait_snapshot(0,120,rows)&&!trace_lock);
 assert(!lemonades_ui_wait_snapshot(249,120,rows)&&!trace_lock);
 lemonades_wait_host_seconds=40;lemonades_wait_capture_begin();
 const char *names[]={"usermanagerd","SpringBoard","backboardd","runningboardd"};
 for(unsigned r=0;r<4;++r) {
  struct bt_main *m=&published_main[r];m->pid=(int)(27+r);published_pid[r]=(unsigned)m->pid;
  strcpy(published_names[r],names[r]);m->slide=0x3a000;m->image=0x100000000ull+r*0x10000;
  m->entry.role="BSTU"[r];m->entry.index=1;
  m->entry.pc=0x1cf258b58ull+r*4;m->entry.lr=0x1cf000100ull;m->entry.fp=0x16ff00000ull;
  m->entry.trap=UINT64_MAX-46;m->entry.peer=64;m->entry.peer_code=0;
  m->entry.regs[1]=3;m->entry.regs[3]=0x1103;m->entry.regs[4]=0x123400000000ull;
  for(unsigned i=0;i<32;++i)m->frames[i]=0x100000000ull+i*4;
 }
 // A task can be present while its main thread could not be captured.
 published_main[3].pid=0;published_busy=2;published_omitted=4;
 published.count=5;published.threads=12;
 for(unsigned i=0;i<5;++i) {
  struct bt_entry *e=&published.entries[i];e->role='B';e->index=i+1;e->count=i+1;
  e->pc=0x123000+i*4;e->peer=-1;e->peer_code=4;
  for(unsigned k=0;k<8;++k)e->frames[k]=0x100000004ull+k*8;
 }
 published.entries[3].peer=99;published.entries[3].peer_code=0;
 lemonades_wait_host_seconds=42;lemonades_wait_publish();
 assert(lemonades_ui_wait_snapshot(1,120,rows)&&!trace_lock);memcpy(saved,rows,sizeof(rows));
 assert(rows[0][3]==40&&rows[0][4]==42&&rows[0][5]==1&&rows[0][63]==0x10000007cull);
 assert(rows[1][16]==4&&rows[1][18]==2&&rows[1][19]==2);
 assert(rows[1][20]==4&&rows[1][23]==99&&rows[1][42]==2); // outgoing peer prioritized
 assert(rows[6][8]==30&&!rows[6][9]);
 for(unsigned i=0;i<8;++i)assert(lemonades_user_wire_repeat(h,"WAIT",i+1,rows[i],64,3));
 // Stale published data stays explicitly stale, with the same generation.
 assert(lemonades_ui_wait_snapshot(9,600,rows)&&rows[0][4]==42&&rows[0][5]==1);
 for(unsigned i=0;i<8;++i)assert(lemonades_user_wire_repeat(h,"WAIT",i+9,rows[i],64,3));
 // A new publish cannot change an already copied batch.
 lemonades_wait_host_seconds=610;lemonades_wait_capture_begin();lemonades_wait_host_seconds=612;lemonades_wait_publish();
 assert(lemonades_ui_wait_snapshot(17,620,rows)&&rows[0][5]==2&&saved[0][5]==1);
 for(unsigned i=0;i<8;++i)assert(lemonades_user_wire_repeat(h,"WAIT",i+17,rows[i],64,3));
 unsigned before=h[1];assert(!lemonades_user_wire_repeat(h,"WAIT",1,rows[0],64,0));
 assert(!lemonades_user_wire_repeat(h,"WAIT",1,rows[0],64,6)&&h[1]==before);
 // Existing DATA/USER writer retains its five-copy behavior.
 assert(lemonades_user_wire(h,"DATA",1,rows[0],64)&&h[1]-before==64*42*5);
 for(unsigned i=0;i<32;++i)assert(arena[i]==0xa5&&arena[32+total+i]==0xa5);
 FILE *f=fopen(argv[1],"wb");assert(f);assert(fwrite(h+3,1,h[2],f)==h[2]);fclose(f);free(arena);
}
'''


class WaitTraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='lemonades-wait-')
        p = Path(cls.tmp.name); (p/'test.c').write_text(SOURCE)
        subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-function', '-fsanitize=address,undefined',
                        '-I', str(ROOT/'devices/lemonades/package/boot-progress'),
                        str(p/'test.c'), '-o', str(p/'test')], check=True)
        subprocess.run([str(p/'test'), str(p/'raw')], check=True)
        cls.raw = (p/'raw').read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_complete_main_group_and_time(self):
        d = decode_wait_trace(self.raw); self.assertEqual(len(d['records']), 24)
        self.assertEqual(d['crc_valid_records'], 24*64*3)
        m, g = d['records'][:2]
        self.assertTrue(m['complete']); self.assertEqual(m['frames'][-1], 0x10000007c)
        self.assertEqual(m['capture_age_seconds'], 78)
        self.assertEqual(m['name_prefix'], 'usermanagerd')
        self.assertEqual(g['groups'][0]['peer_pid'], 99)
        self.assertEqual(g['groups'][1]['peer_pid'], -1)
        self.assertEqual(g['unlogged_group_count'], 2)
        self.assertEqual(d['records'][8]['capture_age_seconds'], 558)
        self.assertEqual(d['records'][16]['generation'], 2)
        self.assertEqual(d['records'][6]['main_captured'], 0)

    def test_missing_frame_not_filled(self):
        raw = re.sub(rb'\nUMI WAIT 01 24 [0-9a-f]{16} [0-9a-f]{8}\n', b'', self.raw)
        m = decode_wait_trace(raw)['records'][0]
        self.assertFalse(m['complete']); self.assertIsNone(m['frames'][4])
        self.assertEqual(m['missing_fields'], [36])

    def test_conflicting_valid_field_rejects_whole_record(self):
        crc = zlib.crc32(struct.pack('<BBQ', 1, 36, 7))
        d = decode_wait_trace(self.raw+f'\nUMI WAIT 01 24 {7:016x} {crc:08x}\n'.encode())
        self.assertEqual(d['conflicts'], [1]); self.assertEqual(len(d['records']), 23)

    def test_one_corrupt_copy_recovers_from_other_crc(self):
        raw = self.raw.replace(b'0000000100000010', b'0000000100000011', 1)
        d = decode_wait_trace(raw)
        self.assertEqual(d['crc_rejected_records'], 1)
        self.assertEqual(d['records'][0]['frames'][4], 0x100000010)

    def test_log_budget_and_original_capture_preserved(self):
        new = (ROOT/'devices/lemonades/package/boot-progress/BootUiTraceProbe.c').read_text()
        for addition in ('#include "LemonadesWaitTrace.h"\n', ' lemonades_wait_capture_begin();\n', '  lemonades_wait_publish();\n'):
            self.assertEqual(new.count(addition), 1); new = new.replace(addition, '')
        old = (ROOT/'sources/UniXNU-sheng/package/BootUiTraceProbe.c').read_text()
        self.assertEqual(new, old)
        # Full USER quota, all LIVE/DATA deadlines and 24 three-copy WAIT records.
        diagnostic_bytes = (96*48*5 + 8*248*5 + 10*64*5 + 24*64*3)*42
        self.assertEqual(diagnostic_bytes, 1712256)
        self.assertGreater((0x200000-12)-diagnostic_bytes, 375*1024)

    def test_touch_additions_preserve_wait_worker(self):
        path = 'devices/lemonades/package/boot-progress/LemonadesUserspaceProbe.c'
        source = (ROOT/path).read_text()
        # Remove only the three explicitly gated touch additions and the two
        # new wire tags. Everything else must retain the qualified WAIT worker.
        source, count = re.subn(r'#if LEMONADES_FTS_TOUCH\n.*?#endif\n', '', source, flags=re.S)
        self.assertEqual(count, 3)
        source = source.replace('(!memcmp(tag,"WAIT",4)||!memcmp(tag,"TOUC",4)||!memcmp(tag,"TCHX",4))',
                                '!memcmp(tag,"WAIT",4)')
        self.assertEqual(hashlib.sha256(source.encode()).hexdigest(),
                         'cbdc4b7ab32e24f49e7633ef41bc3a16d98b3d239e0ddf9e67769ac4def5028d')
        self.assertLess(1712256+30*32*42*3+96*16*42*3, 0x200000-12)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-directory', type=Path, required=True)
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(WaitTraceTests))
    if result.wasSuccessful():
        paths = ['tests/test_lemonades_wait_trace.py', 'tools/lemonades_wait_trace.py',
                 'devices/lemonades/package/boot-progress/LemonadesWaitTrace.h',
                 'devices/lemonades/package/boot-progress/BootUiTraceProbe.c',
                 'devices/lemonades/package/boot-progress/LemonadesUserWire.h',
                 'devices/lemonades/package/boot-progress/LemonadesUserspaceProbe.c']
        report = dict(passed=True, tests=result.testsRun, sanitizer='address,undefined',
                      qemu_test_performed=False, task_capture_is_original=True,
                      touch_delta_preserves_wait=True,
                      maximum_diagnostic_bytes=2026752, reserved_bytes=70388,
                      inputs={p: hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in paths})
        out = args.output_directory; out.mkdir(parents=True, exist_ok=True)
        (out/'wait-tests.json').write_text(json.dumps(report, indent=2)+'\n')
    sys.exit(not result.wasSuccessful())
