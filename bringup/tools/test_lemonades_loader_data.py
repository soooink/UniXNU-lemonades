#!/usr/bin/env python3
"""Run the staged DarwinBoot C parsers and allocation checks on the real payload."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload-dir", type=Path, required=True)
    args = parser.parse_args()
    staged = ROOT / "out/lemonades-menu-package/DarwinBootPkg/Driver"
    old = ROOT / "sources/UniXNU/drivers/DarwinBoot/DarwinBootPkg/Driver"
    source = (staged / "DarwinBoot.c").read_text()
    kernel_parser = source[source.index("STATIC\nEFI_STATUS\nParseKernel ("):
                           source.index("STATIC\nBOOLEAN\nAdtNode (")]
    adt_parser = source[source.index("STATIC\nBOOLEAN\nAdtNode ("):
                        source.index("STATIC\nBOOLEAN\nValidTrustCaches (")]
    budget = source[source.index("  ArgsAddress = ALIGN_VALUE (Address + Kernel.End"):
                    source.index("  ZeroMem ((VOID *)(UINTN)Address, (UINTN)Used);")]
    preamble = r'''
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
typedef uint8_t UINT8; typedef uint32_t UINT32; typedef uint64_t UINT64;
typedef size_t UINTN; typedef int BOOLEAN; typedef int EFI_STATUS;
typedef char CHAR8;
#define STATIC static
#define CONST const
#define VOID void
#define TRUE 1
#define FALSE 0
#define SIZE_2MB 0x200000ULL
#define SIZE_16KB 0x4000ULL
#define SIZE_256MB 0x10000000ULL
#define SIZE_2GB 0x80000000ULL
#define EFI_PAGE_SIZE 4096
#define EFI_PAGE_MASK 4095
#define MAX_UINT64 UINT64_MAX
#define MAX_UINTN SIZE_MAX
#define WINDOW_SIZE SIZE_256MB
#define BLOCK_SIZE SIZE_2MB
#define MAX_SEGMENTS 64
#define EFI_SUCCESS 0
#define EFI_UNSUPPORTED 1
#define EFI_LOAD_ERROR 2
#define EFI_BAD_BUFFER_SIZE 3
#define CompareMem memcmp
#define CopyMem memcpy
#define ZeroMem(p,n) memset(p,0,n)
#define AsciiStrCmp strcmp
#define ScanMem8(buffer,length,value) memchr(buffer,value,length)
#define ALIGN_VALUE(v,a) (((v)+((a)-1)) & ~((a)-1))
#define MIN(a,b) ((a)<(b)?(a):(b))
#define MAX(a,b) ((a)>(b)?(a):(b))
#define DEBUG(args) ((void)0)
static uint32_t ReadUnaligned32(const uint32_t *p) {uint32_t v; memcpy(&v,p,4);return v;}
static uint64_t ReadUnaligned64(const uint64_t *p) {uint64_t v; memcpy(&v,p,8);return v;}
static UINT32 U32(const void *p) {return ReadUnaligned32(p);}
static UINT64 U64(const void *p) {return ReadUnaligned64(p);}
typedef struct {UINT64 Address, Size, FileOffset, FileSize; UINT32 Protection;} SEGMENT;
typedef struct {SEGMENT Segments[MAX_SEGMENTS]; UINTN Count; UINT64 Base, End, Entry;} KERNEL;
'''
    headers = f'''
#define RamdiskLayout OldRamdiskLayout
#define CopyRamdisk OldCopyRamdisk
#include "{old / 'PackedRamdisk.h'}"
#undef DARWIN_BOOT_PACKED_RAMDISK_H
#undef RamdiskLayout
#undef CopyRamdisk
#include "{staged / 'PackedRamdisk.h'}"
#include "{staged / 'WindowSize.h'}"
'''
    allocation = '''
static int fits(KERNEL Kernel, UINTN TreeSize, UINTN encoded, UINTN logical,
                BOOLEAN KeepPacked, UINT64 WindowSize, UINTN TrustCacheSize) {
  struct {UINTN RamdiskSize;} request = {encoded}, *Request = &request;
  UINT64 Address = 0x100000000ULL, ArgsAddress, TreeAddress, RamdiskAddress;
  UINT64 TrustCacheAddress, Used;
  UINTN RamdiskBytes, RamdiskExpandedSize = logical;
  EFI_STATUS Status = EFI_SUCCESS;
''' + budget + '''
  return 1;
Fail:
  assert(Status == EFI_BAD_BUFFER_SIZE); return 0;
}
'''
    harness = r'''
static unsigned char *readfile(const char *path, size_t *size) {
  FILE *f = fopen(path, "rb"); assert(f); assert(!fseek(f,0,SEEK_END));
  long n = ftell(f); assert(n>0); rewind(f); *size=(size_t)n;
  unsigned char *p=malloc(*size); assert(p); assert(fread(p,1,*size,f)==*size);
  assert(!fclose(f)); return p;
}
static void put64(void *p, uint64_t v) {memcpy(p,&v,8);}
static int valid(void *p, size_t n) {size_t expanded; int packed; return RamdiskLayout(p,n,&expanded,&packed);}
int main(int argc, char **argv) {
  assert(argc==5); (void)OldCopyRamdisk;
  size_t n, tn, kn, cn;
  unsigned char *p=readfile(argv[1],&n), *t=readfile(argv[2],&tn);
  unsigned char *k=readfile(argv[3],&kn), *c=readfile(argv[4],&cn);
  size_t logical; int packed;
  assert(!OldRamdiskLayout(p,n,&logical,&packed));
  assert(RamdiskLayout(p,n,&logical,&packed) && packed);
  assert(logical==215ULL*1024*1024*1024 && n<2*1024*1024);
  size_t offset=0, disk=SIZE_MAX, trust=SIZE_MAX; UINT64 window=0; int keep=0;
  if(!AdtNode(t,tn,&offset,0,3,&disk,&trust,&window,&keep)) {fprintf(stderr,"ADT rejected offset=%zu/%zu disk=%zu trust=%zu window=%llx keep=%d\n",offset,tn,disk,trust,(unsigned long long)window,keep);abort();}
  assert(offset==tn && keep && disk!=SIZE_MAX && trust!=SIZE_MAX);
  assert(!U64(t+disk) && !U64(t+disk+8));
  KERNEL kernel; assert(ParseKernel(k,kn,&kernel)==EFI_SUCCESS);
  assert(window==0x130000000ULL);
  assert(fits(kernel,tn,n,logical,keep,window,cn));
  assert(!fits(kernel,tn,n,logical,FALSE,window,cn));
  unsigned char header[32]={0}; memcpy(header,"DBRDISK1",8);
  uint32_t version=1,page=4096; memcpy(header+8,&version,4);memcpy(header+12,&page,4);
  put64(header+16,1ULL<<40); assert(valid(header,32));
  put64(header+16,(1ULL<<40)+4096);assert(!valid(header,32));
  put64(header+16,0);assert(!valid(header,32));
  put64(header+16,4097);assert(!valid(header,32));
  assert(!valid(p,31));assert(!valid(p,n-1));
  unsigned char *bad=malloc(n+1);assert(bad);memcpy(bad,p,n);bad[n]=0;
  assert(!valid(bad,n+1));
  put64(bad+24,65537);assert(!valid(bad,n));memcpy(bad,p,n);
  put64(bad+32,1);assert(!valid(bad,n));memcpy(bad,p,n);
  put64(bad+40,0);assert(!valid(bad,n));memcpy(bad,p,n);
  put64(bad+32,logical);assert(!valid(bad,n));memcpy(bad,p,n);
  put64(bad+40,UINT64_MAX-4095);assert(!valid(bad,n));
  // Exercise the actual copy routine on a small valid disk, never expand 215 GiB.
  unsigned char small[48+4096]={0}, decoded[8192]; memcpy(small,header,32);
  put64(small+16,8192);put64(small+24,1);put64(small+32,4096);put64(small+40,4096);
  memset(small+48,0x5a,4096);assert(valid(small,sizeof(small)));
  memset(decoded,0,sizeof(decoded));CopyRamdisk(decoded,small,sizeof(small),TRUE);
  for(size_t i=0;i<8192;i++)assert(decoded[i]==(i<4096?0:0x5a));
  printf("{\"status\":\"passed\",\"old_2g_rejection_reproduced\":true,"
         "\"actual_seed_encoded_bytes\":%zu,\"actual_seed_logical_bytes\":%zu,"
         "\"actual_adt_keep_packed\":true,\"actual_kernel_parsed\":true,"
         "\"packed_fits_window\":true,\"dense_expansion_rejected\":true,"
         "\"one_tib_boundary_checked\":true,\"malformed_inputs_rejected\":11,"
         "\"small_copy_verified\":true,\"asan_ubsan\":true,\"qemu\":false}\n",n,logical);
  free(bad);free(p);free(t);free(k);free(c);return 0;
}
'''
    payload = args.payload_dir.resolve(strict=True)
    inputs = [payload / f"kernel.macho{s}" for s in (".ramdisk", ".adt", "", ".trustcache")]
    with tempfile.TemporaryDirectory(prefix="lemonades-loader-data-") as tmp:
        path = Path(tmp)
        (path / "test.c").write_text(preamble + headers + kernel_parser + adt_parser + allocation + harness)
        subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g",
                        str(path / "test.c"), "-o", str(path / "test")], check=True)
        report = json.loads(subprocess.check_output([str(path / "test"), *map(str, inputs)], text=True))
    report["inputs_sha256"] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in inputs + [staged / "PackedRamdisk.h", staged / "DarwinBoot.c"]}
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
