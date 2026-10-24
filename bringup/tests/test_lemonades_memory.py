#!/usr/bin/env python3
"""Exercise the exact read-only SMEM parser with bounded synthetic regions."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HEADER = ROOT / "devices/lemonades/overlay/Platforms/OnePlus/lemonadesPkg/Application/LemonadesMemoryDiag/SmemRead.h"
GUARD = HEADER.with_name("RamGuard.h")
PROBE = HEADER.with_name("RamProbe.c")


def main():
    prelude = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#define STATIC static
#define CONST const
#define UINT8 uint8_t
#define UINT16 uint16_t
#define UINT32 uint32_t
#define UINT64 uint64_t
#define UINTN size_t
#define BOOLEAN int
#define TRUE 1
#define FALSE 0
'''
    allocator_fixture = r'''
#define VOID void
#define EFI_STATUS uint64_t
#define EFI_PHYSICAL_ADDRESS uint64_t
#define EFI_SUCCESS 0
#define EFI_OUT_OF_RESOURCES 1
#define EFI_COMPROMISED_DATA 2
#define EFI_ERROR(x) ((x)!=0)
#define MAX_UINT64 UINT64_MAX
#define EFI_PAGE_SIZE 4096
#define SIZE_2MB 0x200000ULL
#define SIZE_256MB 0x10000000ULL
#define EFI_PAGES_TO_SIZE(x) ((x)*4096ULL)
#define EFI_SIZE_TO_PAGES(x) ((x)/4096ULL)
#define ALIGN_VALUE(x,a) (((x)+(a)-1)&~((a)-1))
#define EfiConventionalMemory 7
#define EfiLoaderCode 1
#define AllocateAddress 2
typedef struct {uint32_t Type;uint64_t PhysicalStart;uint64_t NumberOfPages;} EFI_MEMORY_DESCRIPTOR;
static EFI_MEMORY_DESCRIPTOR map[8];
static size_t map_count, alloc_calls;
static uint64_t allocated;
static EFI_STATUS fake_map(size_t *size,void *out,size_t *key,size_t *stride,uint32_t *version) {
  assert(*size>=map_count*sizeof(map[0]));
  memcpy(out,map,map_count*sizeof(map[0]));*size=map_count*sizeof(map[0]);
  *key=1;*stride=sizeof(map[0]);*version=1;return 0;
}
static EFI_STATUS fake_alloc(unsigned mode,unsigned type,size_t pages,uint64_t *addr) {
  assert(mode==AllocateAddress && type==EfiLoaderCode && pages==65536);
  assert(RamContains(LEMONADES_RAM_BASE,LEMONADES_RAM_BYTES,*addr,EFI_PAGES_TO_SIZE(pages)));
  alloc_calls++;allocated=*addr;return 0;
}
static struct {EFI_STATUS (*GetMemoryMap)(size_t*,void*,size_t*,size_t*,uint32_t*);
 EFI_STATUS (*AllocatePages)(unsigned,unsigned,size_t,uint64_t*);} fake_bs={fake_map,fake_alloc},*gBS=&fake_bs;
'''
    allocator = PROBE.read_text().split("STATIC EFI_STATUS AllocateDarwinStyle", 1)[1]
    allocator = "STATIC EFI_STATUS AllocateDarwinStyle" + allocator.split("\nEFI_STATUS ProbeCandidateRam", 1)[0]
    tests = r'''
#define BYTES 0x200000
static uint8_t data[BYTES], backup[BYTES];
static void w16(size_t o,uint16_t v){data[o]=v;data[o+1]=v>>8;}
static void w32(size_t o,uint32_t v){w16(o,v);w16(o+2,v>>16);}
static void init(unsigned v) {memset(data,0,sizeof(data));w32(192,1);w32(92,v<<16);}
static void table(size_t o,unsigned v) {
  w32(o,0x9da5e0a8);w32(o+4,0xaf9ec4e2);w32(o+8,v);w32(o+16,1);
  w32(o+24+16,0xc0000000);w32(o+24+24,0x20000000);
}
static void v12(void) {
  init(12);
  size_t toc=BYTES-4096;
  w32(toc,0x434f5424);w32(toc+4,1);w32(toc+8,1);
  w32(toc+32,0x4000);w32(toc+36,0x10000);w16(toc+44,0xfffe);w16(toc+46,0xfffe);
  w32(0x4000,0x54525024);w16(0x4004,0xfffe);w16(0x4006,0xfffe);
  w32(0x4008,0x10000);w32(0x400c,32+16+96+8);w32(0x4010,0x10000);
  w16(0x4020,0xa5a5);w16(0x4022,402);w32(0x4024,104);w16(0x4028,8);
  table(0x4030,2);
}
int main(void) {
  size_t o=0,n=0,stride=0;uint32_t count=0;
  uint64_t addr=0;
  // Adjacent descriptors may have different attributes/order. A real hole
  // must never be bridged. Exercise the exact firmware allocator function.
  map_count=3;
  map[0]=(EFI_MEMORY_DESCRIPTOR){7,0x98900000,0x1000};
  map[1]=(EFI_MEMORY_DESCRIPTOR){7,0xc8000000,0x18000};
  map[2]=(EFI_MEMORY_DESCRIPTOR){7,0xc0000000,0x8000};
  assert(AllocateDarwinStyle(0,&addr)==0 && allocated==0xc8000000);
  assert(AllocateDarwinStyle(0x4000,&addr)==0 && allocated==0xc8004000);
  map[1].PhysicalStart=0xc8001000;map[1].NumberOfPages=0xffff;
  assert(AllocateDarwinStyle(0,&addr)==EFI_OUT_OF_RESOURCES);
  map[1]=(EFI_MEMORY_DESCRIPTOR){7,0xc8000000,0x8000};
  assert(AllocateDarwinStyle(0,&addr)==0 && allocated==0xc0000000);
  assert(AllocateDarwinStyle(0x4000,&addr)==EFI_OUT_OF_RESOURCES);
  map[1].Type=4;
  assert(AllocateDarwinStyle(0,&addr)==EFI_OUT_OF_RESOURCES);
  map_count=1;map[0]=(EFI_MEMORY_DESCRIPTOR){7,0xe0000000,0x20000};
  assert(AllocateDarwinStyle(0,&addr)==EFI_OUT_OF_RESOURCES);
  assert(alloc_calls==3);
  assert(!SmBounds(SIZE_MAX,1,sizeof(data)));
  assert(SmBounds(sizeof(data),0,sizeof(data)));
  assert(RamContains(0xc0000000,UINT64_C(0x140000000),LEMONADES_RAM_BASE,LEMONADES_RAM_BYTES));
  assert(!RamOverlaps(0xb0400000,0x1000000,LEMONADES_RAM_BASE,LEMONADES_RAM_BYTES));
  assert(!RamOverlaps(LEMONADES_RAM_END,0x1000,LEMONADES_RAM_BASE,LEMONADES_RAM_BYTES));
  assert(!RamOverlaps(LEMONADES_RAM_BASE-0x1000,0x1000,LEMONADES_RAM_BASE,LEMONADES_RAM_BYTES));
  assert(RamOverlaps(LEMONADES_RAM_BASE-1,2,LEMONADES_RAM_BASE,LEMONADES_RAM_BYTES));
  assert(RamOverlaps(LEMONADES_RAM_END-1,2,LEMONADES_RAM_BASE,LEMONADES_RAM_BYTES));
  assert(!RamContains(LEMONADES_RAM_BASE,LEMONADES_RAM_BYTES,LEMONADES_RAM_BASE-1,1));
  assert(!RamContains(LEMONADES_RAM_BASE,LEMONADES_RAM_BYTES,LEMONADES_RAM_END,1));
  assert(!RamContains(LEMONADES_RAM_BASE,LEMONADES_RAM_BYTES,LEMONADES_RAM_BASE,LEMONADES_RAM_BYTES+1));
  assert(!RamValid(UINT64_MAX,1));
  assert(!RamValid(0,0));
  assert(RamOverlaps(UINT64_MAX,2,LEMONADES_RAM_BASE,LEMONADES_RAM_BYTES));
  assert(!RamContains(0,UINT64_MAX,UINT64_MAX,1));
  assert(Sm64((uint8_t[]){1,2,3,4,5,6,7,8})==UINT64_C(0x0807060504030201));
  init(11);
  size_t e=208+402*16;
  w32(e,1);w32(e+4,0x4000);w32(e+8,96);table(0x4000,2);
  memcpy(backup,data,sizeof(data));
  assert(SmemRamItem(data,sizeof(data),&o,&n) && o==0x4000 && n==96);
  assert(!memcmp(backup,data,sizeof(data)));
  assert(RamTableLayout(data+o,n,&count,&stride) && count==1 && stride==72);
  assert(!RamTableLayout(data+o,n-1,&count,&stride));
  w32(e+4,BYTES-1);assert(!SmemRamItem(data,sizeof(data),&o,&n));
  w32(e+4,0x4000);w32(e+12,4);assert(!SmemRamItem(data,sizeof(data),&o,&n));
  w32(e+12,0);w32(e+8,0xffffffff);assert(!SmemRamItem(data,sizeof(data),&o,&n));
  v12();memcpy(backup,data,sizeof(data));
  assert(SmemRamItem(data,sizeof(data),&o,&n) && o==0x4030 && n==96);
  assert(!memcmp(backup,data,sizeof(data)));
  assert(RamTableLayout(data+o,n,&count,&stride) && count==1 && stride==72);
  w32(o+8,1);assert(RamTableLayout(data+o,88,&count,&stride) && stride==64);
  w32(o+8,3);assert(RamTableLayout(data+o,n,&count,&stride) && count==1 && stride==72);
  w32(o+8,4);assert(!RamTableLayout(data+o,n,&count,&stride));
  v12();w32(0x4024,0xffffffff);assert(!SmemRamItem(data,sizeof(data),&o,&n));
  v12();w16(0x4028,200);assert(!SmemRamItem(data,sizeof(data),&o,&n));
  v12();w16(0x402a,0xffff);assert(!SmemRamItem(data,sizeof(data),&o,&n));
  v12();w32(0x400c,31);assert(!SmemRamItem(data,sizeof(data),&o,&n));
  v12();w32(0x4010,32);assert(!SmemRamItem(data,sizeof(data),&o,&n));
  v12();w32(BYTES-4096+8,0xffffffff);assert(!SmemRamItem(data,sizeof(data),&o,&n));
  v12();w32(BYTES-4096+32,BYTES-4096-16);assert(!SmemRamItem(data,sizeof(data),&o,&n));
  v12();w16(0x4022,401);assert(!SmemRamItem(data,sizeof(data),&o,&n));
  for (size_t size=0;size<0x3000;size++) assert(!SmemRamItem(data,size,&o,&n));
  // Corrupt every metadata byte, including offsets/counts/padding. ASan
  // protects the enclosing synthetic SMEM allocation; source remains read-only.
  static const size_t bases[]={92,192,204,BYTES-4096,BYTES-4096+32,0x4000,0x4020};
  for (size_t j=0;j<sizeof(bases)/sizeof(bases[0]);j++) {
    for (size_t k=0;k<32;k++) {
      v12();data[bases[j]+k]^=0xff;
      if (SmemRamItem(data,sizeof(data),&o,&n)) {
        assert(o<=sizeof(data) && n<=sizeof(data)-o);
        (void)RamTableLayout(data+o,n,&count,&stride);
      }
    }
  }
  puts("lemonades memory PASS: SMEM/RAM bounds, malformed metadata, range guards, contiguous LoaderCode allocation, holes and alignment");
}
'''
    with tempfile.TemporaryDirectory(prefix="lemonades-memory-test-") as directory:
        c = Path(directory) / "test.c"
        exe = Path(directory) / "test"
        c.write_text(prelude + HEADER.read_text() + GUARD.read_text() +
                     allocator_fixture + allocator + tests)
        subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", str(c), "-o", str(exe)], check=True)
        subprocess.run([str(exe)], check=True)


if __name__ == "__main__":
    main()
