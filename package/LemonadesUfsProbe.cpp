// SPDX-License-Identifier: MIT
// Passive SM8250 storage handoff inspection. Register facts: Linux v6.12
// gcc-sm8250.c, sm8250.dtsi and this handset's archived FDT.
// Same bring-up order as upstream NativeUfs::inspect, with umi clock offsets.
// Mode 1 observes; mode 2 takes over storage DMA and reads GPT. No disk writes.
#include <IOKit/IOLib.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOPlatformExpert.h>
#include <libkern/c++/OSData.h>
#include <pexpert/pexpert.h>

#ifndef UMI_UFS_PHONE
#error Select the phone or QEMU build explicitly
#endif

extern "C" {
volatile uint64_t umi_ufs_observation[32];
volatile uint64_t umi_ufs_streams[128][3];
#if UMI_UFS_PHONE
void umi_early_trace(uint64_t, uint64_t, uint64_t);
extern uint64_t umi_trace_console_address;
#endif
static void umi_ufs_emit(volatile uint64_t *values)
{
#if UMI_UFS_PHONE
  uint64_t daif;
  __asm__ volatile("mrs %0,daif\n\tmsr daifset,#3" : "=r"(daif) :: "memory");
  if (umi_trace_console_address)
    for (unsigned i=0; i<32; ++i)
      umi_early_trace(0xe0+i,values[i],umi_trace_console_address);
  __asm__ volatile("msr daif,%0" :: "r"(daif) : "memory");
#endif
  __asm__ volatile("" ::: "memory");
}
__attribute__((noinline)) void umi_ufs_checkpoint(void)
{
  umi_ufs_emit(umi_ufs_observation);
}
}

#if UMI_UFS_PHONE
static uint32_t umi_mmio_upper_seen;
static uint32_t read32(uintptr_t base, unsigned offset)
{
  // Attempt 33: SMMU LDR W returned stale upper register bits. Explicitly
  // canonicalize after the load; do not assume a cause in firmware/hardware.
  uint64_t value, raw;
  __asm__ volatile("ldr %w0,[%2]\n\tmov %1,%0\n\tuxtw %0,%w0" :
                   "=&r"(value),"=&r"(raw) : "r"(base+offset) : "memory");
  umi_mmio_upper_seen|=uint32_t(raw>>32);
  return uint32_t(value);
}

static uintptr_t map(uint64_t physical, uint64_t bytes, OSSharedPtr<IOMemoryMap> &hold)
{
  IODeviceMemory *memory=IODeviceMemory::withRange(physical,bytes);
  if (!memory) return 0;
  hold=OSSharedPtr<IOMemoryMap>(memory->map(kIOMapAnywhere|kIOMapInhibitCache),OSNoRetain);
  memory->release();
  return hold ? hold->getVirtualAddress() : 0;
}

static bool isUmi(void)
{
  // Product model retains the physical board identity when the root model
  // selects an iPad userspace compatibility profile. Qualified SM8250 UFS
  // host boards: the umi bring-up baseline and this device's model property
  // (package/lemonades-hardware.json: "kona MTP 20828").
  static const char expected[]="Qualcomm Technologies, Inc. xiaomi umi";
  static const char lemonades[]="Qualcomm Technologies, Inc. kona MTP 20828";
  IORegistryEntry *root=IORegistryEntry::fromPath("/product",gIODTPlane);
  if (!root) return false;
  OSData *model=OSDynamicCast(OSData,root->getProperty("model"));
  bool matches=model &&
    ((model->getLength()==sizeof(expected) &&
      !memcmp(model->getBytesNoCopy(),expected,sizeof(expected))) ||
     (model->getLength()==sizeof(lemonades) &&
      !memcmp(model->getBytesNoCopy(),lemonades,sizeof(lemonades))));
  root->release();
  return matches;
}
#include "UmiUfsRead.inc"
#endif

extern "C" void umi_ufs_probe(void)
{
  unsigned mode=0;
  if (!PE_parse_boot_argn("umi-ufs-probe",&mode,sizeof(mode)) || !mode) return;
  if (umi_ufs_observation[0]) return;
  umi_ufs_observation[0]=1;
  umi_ufs_observation[1]=1;
  umi_ufs_observation[3]=UMI_UFS_PHONE;
  umi_ufs_checkpoint();
  if (mode!=1 && mode!=2) {
    umi_ufs_observation[2]=1; // Unsupported mode.
    umi_ufs_checkpoint();
    return;
  }
#if !UMI_UFS_PHONE
  umi_ufs_observation[1]=2;
  umi_ufs_observation[2]=2; // QEMU: no Qualcomm hardware; do not map MMIO.
  umi_ufs_checkpoint();
  IOLog("UMI UFS: QEMU hardware probe skipped\n");
#else
  if (!isUmi()) {
    umi_ufs_observation[2]=3;
    umi_ufs_checkpoint();
    return;
  }
  OSSharedPtr<IOMemoryMap> gccHold,hostHold,smmuHold;
  uintptr_t gcc=map(0x177000,4096,gccHold);
  if (!gcc) { umi_ufs_observation[2]=4; umi_ufs_checkpoint(); return; }
  umi_ufs_observation[4]=read32(gcc,0x004); // SM8250 UFS_PHY_GDSCR.
  umi_ufs_observation[5]=read32(gcc,0x010); // SM8250 AXI (SM8550 uses 0x018).
  umi_ufs_observation[6]=read32(gcc,0x018); // SM8250 AHB (SM8550 uses 0x024).
  umi_ufs_observation[7]=read32(gcc,0x09c); // SM8250 PHY_AUX.
  umi_ufs_observation[1]=3;
  umi_ufs_checkpoint();
  // GDSC PWR_ON and enabled AXI/AHB. HW-gated clocks may read CLK_OFF while idle.
  if (!(umi_ufs_observation[4]&0x80000000) ||
      !(umi_ufs_observation[5]&1) || !(umi_ufs_observation[6]&1)) {
    umi_ufs_observation[2]=5;
    umi_ufs_checkpoint();
    IOLog("UMI UFS: controller read refused, power/clocks not enabled\n");
    return;
  }
  uintptr_t hc=map(0x1d84000,0x3000,hostHold);
  if (!hc) { umi_ufs_observation[2]=6; umi_ufs_checkpoint(); return; }
  const unsigned offsets[]={0x00,0x08,0x30,0x34,0x50,0x54,0x58,0x60,0x78,0x80,0x18,0x20};
  for(unsigned i=0;i<12;++i) umi_ufs_observation[8+i]=read32(hc,offsets[i]);
  umi_ufs_observation[1]=4;
  umi_ufs_checkpoint();
  // Only global readback; no context-bank takeover or inferred bypass success.
  uintptr_t smmu=map(0x15000000,4096,smmuHold);
  if (!smmu) { umi_ufs_observation[2]=7; umi_ufs_checkpoint(); return; }
  const unsigned so[]={0x00,0x20,0x24,0x28,0x48};
  for(unsigned i=0;i<5;++i) umi_ufs_observation[20+i]=read32(smmu,so[i]);
  unsigned count=umi_ufs_observation[21]&0xff;
  if (count>128) { umi_ufs_observation[2]=8; umi_ufs_checkpoint(); return; }
  umi_ufs_observation[25]=count;
  umi_ufs_observation[27]=~0ULL;
  umi_ufs_observation[29]=~0ULL;
  for(unsigned i=0;i<count;++i) {
    uint32_t smr=read32(smmu,0x800+4*i),s2cr=read32(smmu,0xc00+4*i);
    umi_ufs_streams[i][0]=i;
    umi_ufs_streams[i][1]=smr;
    umi_ufs_streams[i][2]=s2cr;
    if (!(smr&0x80000000)) continue;
    umi_ufs_observation[26]=umi_ufs_observation[26]+1;
    uint32_t mask=(smr>>16)&0x7fff;
    if (!((smr^0x0e0)&0x7fff&~mask)) {
      umi_ufs_observation[27]=i;
      umi_ufs_observation[28]=(uint64_t(smr)<<32)|s2cr;
    }
    if (!((smr^0x4e0)&0x7fff&~mask)) {
      umi_ufs_observation[29]=i;
      umi_ufs_observation[30]=(uint64_t(smr)<<32)|s2cr;
    }
  }
  __asm__ volatile("isb\n\tmrs %0,cntpct_el0" : "=r"(umi_ufs_observation[31]));
  umi_ufs_observation[1]=5;
  umi_ufs_checkpoint();
  IOLog("UMI UFS read-only: version=%llx hcs=%llx hce=%llx queue=%llx:%llx db=%llx SMMU=%llx\n",
    umi_ufs_observation[9],umi_ufs_observation[10],umi_ufs_observation[11],
    umi_ufs_observation[13],umi_ufs_observation[12],umi_ufs_observation[14],
    umi_ufs_observation[20]);
  if(mode==2) umiReadDisk();
#endif
}
