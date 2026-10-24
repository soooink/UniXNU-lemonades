#!/usr/bin/env python3
"""Fault-inject the actual reset implementation; no device access."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "devices/lemonades/overlay/Platforms/OnePlus/lemonadesPkg/Library/LemonadesResetSystemLib/LemonadesResetSystem.c"

HARNESS = r"""
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <setjmp.h>
#include <stdio.h>
typedef uint8_t UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uintptr_t UINTN;
typedef int BOOLEAN;
typedef int EFI_STATUS;
typedef int EFI_RESET_TYPE;
#define STATIC static
#define VOID void
#define EFIAPI
#define OPTIONAL
#define TRUE 1
#define FALSE 0
#define BIT0 1
#define BIT7 128
#define EFI_SUCCESS 0
#define EFI_DEVICE_ERROR 1
#define EFI_UNSUPPORTED 2
#define EFI_ERROR(x) ((x) != 0)
#define EfiResetWarm 1
#define EfiResetCold 0
#define EfiResetShutdown 2
#define EfiResetPlatformSpecific 3
#define DEBUG(x) ((void)0)
#define ZeroMem(p,n) memset(p,0,n)
typedef struct { UINTN Arg0, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6, Arg7,
  Arg8, Arg9, Arg10, Arg11, Arg12, Arg13, Arg14, Arg15, Arg16, Arg17; } ARM_SMC_ARGS;
static UINT8 regs[0x900], original[0x900];
static unsigned reads, writes, fail_read, fail_write, fail_write2, mmio_writes;
static UINT32 fail_smc, fail_available;
static int interrupts, halted, smc32, interrupted, resumed;
static int native_dload, io_write_available, deassert_available, sdi_available;
static int dload_cleared, sdi_disabled;
static unsigned native_queries, io_queries, native_clears, io_clears;
static int pon_delay_ready;
static UINT8 expected_type;
static jmp_buf reset_exit;
static BOOLEAN SaveAndDisableInterrupts(void) { int old=interrupts; interrupts=0; return old; }
static void SetInterruptState(BOOLEAN b) { interrupts=b; }
static void MicroSecondDelay(UINTN n) { assert(n==500); pon_delay_ready=1; }
static void MemoryFence(void) {}
static void CpuDeadLoop(void) { assert(0 && "reset failed"); }
static UINT32 MmioRead32(UINTN a) { assert(a==0x0c264000); return 1; }
static void MmioWrite32(UINTN a,UINT32 v) {
  ++mmio_writes;
  if (a==0x146bf65c) { assert(v==0x77665501 && !halted); return; }
  assert(a==0x0c264000 && v==0 && halted);
  longjmp(reset_exit,1);
}
static EFI_STATUS LemonadesSpmiRead8(UINT8 sid,UINT16 a,UINT8 *v) {
  assert(!halted && sid==0 && a<sizeof(regs));
  if (++reads==fail_read) return EFI_DEVICE_ERROR;
  *v=regs[a]; return EFI_SUCCESS;
}
static EFI_STATUS LemonadesSpmiWrite8(UINT8 sid,UINT16 a,UINT8 v) {
  assert(!halted && !interrupts && sid==0);
  assert(a==0x85a || a==0x85b || a==0x88f);
  ++writes;
  if (writes==fail_write || writes==fail_write2) return EFI_DEVICE_ERROR;
  if (a==0x85a) assert(!(regs[0x85b]&BIT7) && pon_delay_ready);
  if (a==0x85b && !(v&BIT7)) pon_delay_ready=0;
  regs[a]=v; return EFI_SUCCESS;
}
static void ArmCallSmc(ARM_SMC_ARGS *a) {
  UINT32 fn=(UINT32)a->Arg0;
  assert(!interrupts);
  if (fn==1) { assert(interrupted && a->Arg6==0x12345678); resumed=1; a->Arg0=0; a->Arg1=1; return; }
  assert(!a->Arg4 && !a->Arg5 && !a->Arg6 && !a->Arg7);
  if (fn==fail_smc) { a->Arg0=(UINTN)-1; return; }
  if (fn==0xc2000601 || fn==0x82000601) {
    assert(a->Arg1==1 && a->Arg2==0x82000601 && a->Arg3==0);
    if (smc32 && fn==0xc2000601) { a->Arg0=(UINTN)-1; return; }
    if (interrupted && !resumed) { a->Arg0=1; a->Arg6=0x12345678; return; }
  } else if (fn==0x42000601 || fn==0x02000601) {
    assert(fn==(smc32?0x02000601U:0x42000601U));
    assert(a->Arg1==1 && !a->Arg3);
    if (a->Arg2==fail_available) { a->Arg0=(UINTN)-1; return; }
    switch(a->Arg2) {
      case 0x02000902: a->Arg1=deassert_available; break;
      case 0x02000110: ++native_queries; a->Arg1=native_dload; break;
      case 0x02000502: ++io_queries; a->Arg1=io_write_available; break;
      case 0x02000109: a->Arg1=sdi_available; break;
      default: assert(0 && "unknown availability query");
    }
    a->Arg0=0; return;
  } else {
    assert(fn==(0x82000110U|(smc32?0:0x40000000U)) ||
           fn==(0x82000502U|(smc32?0:0x40000000U)) ||
           fn==(0x82000109U|(smc32?0:0x40000000U)) ||
           fn==(0x82000902U|(smc32?0:0x40000000U)));
    if ((fn&0xffff)==0x902) {
      assert(a->Arg1==1 && !a->Arg2 && !a->Arg3);
      assert((regs[0x85a]&15)==expected_type && (regs[0x85b]&128) && regs[0x88f]==0x41);
      assert(mmio_writes==1 && dload_cleared && (sdi_disabled || !sdi_available));
      halted=1;
    } else if ((fn&0xffff)==0x502) {
      assert(!native_dload && io_write_available);
      assert(a->Arg1==2 && a->Arg2==0x01fd3000 && !a->Arg3);
      ++io_clears; dload_cleared=1;
    } else {
      assert(a->Arg1==2 && a->Arg2==((fn&0xffff)==0x109) && !a->Arg3);
      if ((fn&0xffff)==0x110) {
        assert(native_dload); ++native_clears; dload_cleared=1;
      } else {
        assert(sdi_available && dload_cleared); sdi_disabled=1;
      }
    }
  }
  a->Arg0=0; a->Arg1=1;
}
"""

CASES = r"""
static void init(void) {
  memset(regs,0,sizeof(regs)); regs[0x801]=1; regs[0x805]=4;
  regs[0x85a]=0xa7; regs[0x85b]=0x91; regs[0x88f]=0x13;
  memcpy(original,regs,sizeof(regs));
  reads=writes=fail_read=fail_write=fail_write2=mmio_writes=0; fail_smc=fail_available=0;
  interrupts=1; halted=smc32=interrupted=resumed=0;
  native_dload=io_write_available=deassert_available=sdi_available=1;
  dload_cleared=sdi_disabled=0;
  native_queries=io_queries=native_clears=io_clears=0;
  pon_delay_ready=0;
  expected_type=1;
}
int main(void) {
  unsigned n;
  for(n=1;n<=5;n++) { init(); fail_read=n; BoardReset(1); assert(!writes && !mmio_writes && interrupts); }
  init(); regs[0x805]=3; BoardReset(1); assert(!writes && interrupts);
  init(); BoardReset(9); assert(!writes && interrupts);
  init(); deassert_available=0; BoardReset(1);
  assert(!writes && !mmio_writes && interrupts && !native_queries && !io_queries);
  init(); native_dload=io_write_available=0; BoardReset(1);
  assert(!writes && !mmio_writes && interrupts && native_queries==1 && io_queries==1);
  init(); fail_smc=0x42000601; BoardReset(1);
  assert(!writes && !mmio_writes && interrupts);
  init(); native_dload=0; fail_available=0x02000502; BoardReset(1);
  assert(!writes && !mmio_writes && interrupts);
  for(n=1;n<=4;n++) {
    init(); fail_write=n; BoardReset(1);
    assert(!memcmp(regs,original,sizeof(regs)) && !halted && interrupts && !mmio_writes);
  }
  for(n=2;n<=5;n++) {
    init(); fail_write=1; fail_write2=n; BoardReset(1);
    assert(writes==n && !halted && interrupts && !mmio_writes);
    if(n>=3) assert(!(regs[0x85b]&128));
  }
  for(n=6;n<=9;n++) {
    init(); fail_read=n; BoardReset(1);
    assert(!memcmp(regs,original,sizeof(regs)) && !halted && interrupts && !mmio_writes);
  }
  init(); fail_smc=0xc2000110; BoardReset(1);
  assert(!memcmp(regs,original,sizeof(regs)) && !halted && interrupts && !mmio_writes);
  assert(!io_queries && !io_clears);
  init(); fail_smc=0xc2000109; BoardReset(1);
  assert(!memcmp(regs,original,sizeof(regs)) && !halted && interrupts && !mmio_writes);
  for(n=0;n<2;n++) {
    init(); native_dload=0; smc32=n; fail_smc=smc32?0x82000502:0xc2000502;
    BoardReset(1);
    assert(!memcmp(regs,original,sizeof(regs)) && !halted && interrupts && !mmio_writes);
    assert(native_queries==1 && io_queries==1 && !dload_cleared);
  }
  for(n=0;n<24;n++) {
    init(); smc32=(n&1); interrupted=(n&2)!=0; native_dload=(n&4)!=0;
    sdi_available=(n&8)==0;
    expected_type=n<8?1:n<16?7:4;
    if (!setjmp(reset_exit)) { BoardReset(expected_type); assert(0 && "reset returned"); }
    assert(halted && writes==4 && mmio_writes==2);
    assert(native_queries==1 && io_queries==(unsigned)!native_dload);
    assert(native_clears==(unsigned)native_dload && io_clears==(unsigned)!native_dload);
    if(interrupted) assert(resumed);
  }
  // Attempt 12 confirmed SCM64, 02000902 present and 02000110 absent.
  // If secure IO write is available, that case must now reach reset.
  init(); native_dload=0;
  if (!setjmp(reset_exit)) { BoardReset(1); assert(0 && "reset returned"); }
  assert(halted && io_clears==1 && !native_clears && dload_cleared);
  puts("reset guards, rollback, native/TCSR dload, SMC32/64 and interrupted-call tests passed");
  return 0;
}
"""

def main():
    code = "\n".join(line for line in SOURCE.read_text().splitlines()
                     if not line.startswith("#include"))
    with tempfile.TemporaryDirectory(prefix="lemonades-reset-test-") as temp:
        c = Path(temp) / "reset.c"
        binary = Path(temp) / "reset-test"
        c.write_text(HARNESS + code + CASES)
        subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-parameter", "-fsanitize=address,undefined",
                        str(c), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)

if __name__ == "__main__":
    main()
