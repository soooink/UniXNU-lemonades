#!/usr/bin/env python3
"""Compile actual RAM block/range functions under ASan/UBSan, no handset I/O."""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "devices/lemonades/overlay/Platforms/OnePlus/lemonadesPkg/Drivers/LemonadesRamPayloadDxe/LemonadesRamPayload.c"


def function(text, name):
    start = re.search(r"STATIC\s+[^{};]*\b" + name + r"\s*\([^{};]*\)\s*\{", text)
    assert start, name
    pos, depth = start.end(), 1
    while depth:
        depth += (text[pos] == "{") - (text[pos] == "}")
        pos += 1
    return text[start.start():pos]


def main():
    source = SOURCE.read_text()
    prelude = r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#define STATIC static
#define EFIAPI
#define VOID void
#define BOOLEAN int
#define TRUE 1
#define UINT64 uint64_t
#define UINT32 uint32_t
#define UINTN size_t
#define EFI_LBA uint64_t
#define EFI_STATUS int
#define EFI_BLOCK_IO_PROTOCOL void
#define EFI_SUCCESS 0
#define EFI_MEDIA_CHANGED 13
#define EFI_INVALID_PARAMETER 2
#define EFI_BAD_BUFFER_SIZE 4
#define EFI_WRITE_PROTECTED 8
#define DEBUG(X) do {} while(0)
#define CopyMem memcpy
#define BLOCK_SIZE 512U
#define BOOT_BASE 0xa0000000ULL
#define BOOT_END 0xb0000000ULL
#define SIZE_1MB 0x100000ULL
#define SIZE_64MB 0x4000000ULL
#define SIZE_128MB 0x8000000ULL
static uint8_t Bytes[SIZE_128MB];
static uint8_t *mRamBase=Bytes;
static struct {UINT32 MediaId; EFI_LBA LastBlock;} mMedia={7,2};
static UINTN mReadCount;
'''
    tests = r'''
int main(void) {
  uint8_t buffer[1024];
  for (size_t i=0;i<sizeof(Bytes);i++) Bytes[i]=(uint8_t)(i*73+19);
  assert(InBootWindow(BOOT_BASE,1));
  assert(InBootWindow(BOOT_END-512,512));
  assert(!InBootWindow(BOOT_END-512,513));
  assert(!InBootWindow(UINT64_MAX-2,4));
  assert(!InBootWindow(BOOT_BASE-1,1));
  assert(!InBootWindow(BOOT_BASE,0));
  assert(ValidInitrd(0xa0000000,0x100000,0xaf800000,0xb0000000));
  assert(ValidInitrd(0xabdfe000,0xd7bf3,0xabfff000,0xaffff000));
  assert(ValidInitrd(0xa0000000,0x100000,0xac000000,0xb0000000));
  assert(ValidInitrd(0xa0000000,0x100000,0xac000000,0xad000200));
  assert(ValidInitrd(0xa0000000,0x100000,0xabfffe00,0xb0000000));
  assert(ValidInitrd(0xa7dfe000,0xd7bf3,0xa7fff000,0xaffff000));
  assert(!ValidInitrd(0xa7ffe000,0x1001,0xa7fff000,0xaffff000));
  assert(!ValidInitrd(0xa0000000,0x100000,0xa7fffe00,0xb0000000));
  assert(!ValidInitrd(0xabfff000,0xd7bf3,0xabfff000,0xaffff000));
  assert(!ValidInitrd(0xabffe000,0x1001,0xabfff000,0xaffff000));
  assert(ValidInitrd(0xabffe000,0x1000,0xabfff000,0xaffff000));
  assert(!ValidInitrd(0xa0000000,0x100000,0x9c000000,0x9c800000));
  assert(!ValidInitrd(0xa0000000,0x100000,0xb0000000,0xb0800000));
  assert(!ValidInitrd(0xaf800000,0x100000,0xaf800000,0xb0000000));
  assert(!ValidInitrd(0xa0000000,0x100000,0xaf800001,0xb0000000));
  assert(!ValidInitrd(0xa0000000,0x100000,0xaf800000,0xafffffff));
  assert(!ValidInitrd(0xa0000000,0x100000,0xaf800000,0xaf800000));
  assert(!ValidInitrd(0xa0000000,0x100000,0xaf800000,UINT64_MAX));
  assert(!ValidInitrd(0xa0000000,0x100000,0xa1000000,0xaf800000));
  assert(!ValidInitrd(UINT64_MAX-3,8,0xaf800000,0xb0000000));
  assert(RamRead(NULL,7,1,1024,buffer)==EFI_SUCCESS);
  assert(!memcmp(buffer,Bytes+512,1024));
  assert(RamRead(NULL,8,0,512,buffer)==EFI_MEDIA_CHANGED);
  assert(RamRead(NULL,7,0,0,NULL)==EFI_SUCCESS);
  assert(RamRead(NULL,7,0,512,NULL)==EFI_INVALID_PARAMETER);
  assert(RamRead(NULL,7,0,513,buffer)==EFI_BAD_BUFFER_SIZE);
  assert(RamRead(NULL,7,2,1024,buffer)==EFI_INVALID_PARAMETER);
  assert(RamRead(NULL,7,3,512,buffer)==EFI_INVALID_PARAMETER);
  assert(RamRead(NULL,7,UINT64_MAX,512,buffer)==EFI_INVALID_PARAMETER);
  assert(RamRead(NULL,7,0,SIZE_MAX & ~(size_t)511,buffer)==EFI_INVALID_PARAMETER);
  assert(RamRead(NULL,7,2,512,buffer)==EFI_SUCCESS);
  assert(RamWrite(NULL,7,0,512,buffer)==EFI_WRITE_PROTECTED);
  assert(RamReset(NULL,TRUE)==EFI_SUCCESS);
  assert(RamFlush(NULL)==EFI_SUCCESS);
  mMedia.LastBlock=SIZE_128MB/512-1;
  assert(RamRead(NULL,7,32767,1024,buffer)==EFI_SUCCESS);
  assert(!memcmp(buffer,Bytes+32767*512,1024));
  assert(RamRead(NULL,7,mMedia.LastBlock,512,buffer)==EFI_SUCCESS);
  assert(!memcmp(buffer,Bytes+SIZE_128MB-512,512));
  assert(RamRead(NULL,7,mMedia.LastBlock,1024,buffer)==EFI_INVALID_PARAMETER);
  assert(RamRead(NULL,7,mMedia.LastBlock+1,512,buffer)==EFI_INVALID_PARAMETER);
  puts("lemonades RAM payload: PASS (8/64/128 MiB, oversized refusal, DTB overlap, overflow, 16 MiB crossing, final sector, read-only)");
}
'''
    with tempfile.TemporaryDirectory(prefix="lemonades-ram-check-") as d:
        c = Path(d) / "test.c"
        # Exercise the real limit, so a stale test constant cannot mask a regression.
        limit = re.search(r"^#define MAX_IMAGE\s+\S+", source, re.M).group(0)
        c.write_text(prelude + limit + "\n" + "\n".join(function(source, n) for n in (
            "InBootWindow", "ValidInitrd", "RamRead", "RamWrite", "RamReset", "RamFlush")) + tests)
        exe = Path(d) / "test"
        subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", str(c), "-o", str(exe)], check=True)
        subprocess.run([str(exe)], check=True)


if __name__ == "__main__":
    main()
