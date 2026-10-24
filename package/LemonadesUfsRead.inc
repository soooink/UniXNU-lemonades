// SPDX-License-Identifier: BSD-2-Clause-Patent
// SM8250 glue around the official NativeUfs production queue/command/parser.
// This bring-up entry publishes no block devices and never writes disk blocks.
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <libkern/crypto/sha2.h>
#include <kern/clock.h>
#include <vm/vm_kern.h>
#include "LemonadesSmmuTakeover.h"
#include "RootDiagnostics.h"
#include "TransferPoll.h"
static UfsRootDiagnostics gRootDiagnostic;
static bool gRootDiagnosticEnabled=true;
static void write32(uintptr_t base,unsigned offset,uint32_t value)
{
  __asm__ volatile("dsb sy\n\tstr %w0,[%1]\n\tdsb sy" ::
                   "r"(value),"r"(base+offset) : "memory");
}
// Generated from the pinned NativeUfs.cpp production section. RootCommands
// is cut at its explicit Persistent store boundary; no write API is compiled.
#include "LemonadesUfsTransport.inc"
#include "RootLayout.h"

extern "C" {
volatile uint64_t lemonades_ufs_smmu[32];
volatile uint64_t lemonades_ufs_read[32];
}
static LemonadesSmmuPlan lemonadesPlan;
static unsigned lemonadesReadPhase,lemonadesReadStatus;

static void lemonadesReadSnapshot()
{
  auto &s=lemonades_ufs_smmu;
  s[0]=2; s[1]=lemonadesReadPhase; s[2]=lemonadesReadStatus; s[3]=1;
  s[4]=gHost.phys; s[5]=gRootDiagnostic.contiguous;
  if(gHost.smmu) {
    s[6]=read32(gHost.smmu,0x20); s[7]=read32(gHost.smmu,0x24);
    s[8]=read32(gHost.smmu,0x28); s[9]=read32(gHost.smmu,0);
    s[10]=lemonadesPlan.bank; s[11]=lemonadesPlan.pages;
    for(unsigned i=0;i<2;++i) {
      s[12+3*i]=lemonadesPlan.slot[i];
      if(lemonadesPlan.slot[i]<128) {
        s[13+3*i]=read32(gHost.smmu,0x800+4*lemonadesPlan.slot[i]);
        s[14+3*i]=read32(gHost.smmu,0xc00+4*lemonadesPlan.slot[i]);
      }
    }
    if(lemonadesPlan.pages && lemonadesPlan.bank<128 &&
       (lemonadesPlan.pages+lemonadesPlan.bank+1)*4096<=0xd0000) {
      s[18]=read32(gHost.smmu,0x1000+4*lemonadesPlan.bank);
      s[19]=read32(gHost.smmu,0x1800+4*lemonadesPlan.bank);
      s[20]=read32(gHost.smmu,(lemonadesPlan.pages+lemonadesPlan.bank)*4096);
      s[21]=read32(gHost.smmu,(lemonadesPlan.pages+lemonadesPlan.bank)*4096+0x58);
    }
    s[22]=read32(gHost.smmu,0x48);
  }
  s[23]=lemonadesPlan.error;
  if(gHost.hc) {
    s[24]=read32(gHost.hc,0x60); s[25]=read32(gHost.hc,0x34);
    s[26]=read32(gHost.hc,0x58); s[27]=read32(gHost.hc,0x78);
  }
  s[28]=lemonades_mmio_upper_seen;
  s[29]=gRootDiagnostic.far; s[30]=gRootDiagnostic.fsyn; s[31]=gRootDiagnostic.gsyn;
  auto &r=lemonades_ufs_read;
  r[0]=3; r[1]=lemonadesReadPhase; r[2]=lemonadesReadStatus; r[3]=gRootDiagnostic.command;
  r[4]=gRootDiagnostic.type; r[5]=gRootDiagnostic.opcode; r[6]=gRootDiagnostic.lun;
  r[7]=gRootDiagnostic.ocs; r[8]=gRootDiagnostic.scsi; r[9]=gRootDiagnostic.response;
  r[10]=gRootDiagnostic.protocol; r[11]=gRootDiagnostic.residual; r[12]=gRootDiagnostic.sense;
  r[13]=gRootDiagnostic.power; r[14]=gRootDiagnostic.polls;
  r[15]=gRootDiagnostic.dbSeen; r[16]=gRootDiagnostic.isSeen;
  r[17]=gHost.phys; r[18]=gHost.hc?read32(gHost.hc,0x60):0;
  r[19]=gHost.hc?(uint64_t(read32(gHost.hc,0x54))<<32)|read32(gHost.hc,0x50):0;
  r[20]=gRootDiagnostic.lba; r[21]=gRootDiagnostic.first; r[22]=gRootDiagnostic.last;
  r[25]=gRootDiagnostic.manifest; r[26]=gRootDiagnostic.magic0; r[27]=gRootDiagnostic.magic1;
  r[28]=gRootDiagnostic.windows;
  __asm__ volatile("isb\n\tmrs %0,cntpct_el0":"=r"(r[31]));
  lemonades_ufs_emit(s); lemonades_ufs_emit(r);
}
static bool lemonadesReadStep(unsigned phase,IOReturn status,const char *why)
{
  lemonadesReadPhase=phase; lemonadesReadStatus=uint32_t(status);
  lemonadesReadSnapshot();
  if(status!=kIOReturnSuccess)
    IOLog("UMI UFS phase=%u refused: %s status=%x SMMU=%u\n",
          phase,why,uint32_t(status),lemonadesPlan.error);
  return status==kIOReturnSuccess;
}
static void lemonadesReadDisk()
{
  // Keep descriptors allocated for the entire boot, especially on timeout:
  // the controller may still own them. No old firmware queue RAM is reused.
  gHost.hc=map(0x1d84000,0x3000,gHost.hcMap);
  if(!lemonadesReadStep(6,gHost.hc?kIOReturnSuccess:kIOReturnNoMemory,"HC mapping")) return;
  gHost.dma=IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task,
    IOOptionBits(kIODirectionInOut)|IOOptionBits(kIOMemoryPhysicallyContiguous)|
    IOOptionBits(kIOMemoryMapperNone),kDmaBytes,4096);
  gHost.lock=IOLockAlloc();
  if(!gHost.dma || !gHost.lock) { lemonadesReadStep(6,kIOReturnNoMemory,"DMA allocation"); return; }
  gHost.virt=static_cast<uint8_t *>(gHost.dma->getBytesNoCopy());
  IOByteCount contiguous=0;
  gHost.phys=gHost.dma->getPhysicalSegment(0,&contiguous,kIOMemoryMapperNone);
  gRootDiagnostic.contiguous=contiguous;
  if(!gHost.virt || (gHost.phys&4095) || contiguous<kDmaBytes ||
     gHost.phys<0xc0000000ULL || gHost.phys>0xd0000000ULL-kDmaBytes) {
    lemonadesReadStep(6,kIOReturnBadArgument,"DMA outside qualified 256 MiB"); return;
  }
  gHost.smmu=map(0x15000000,0xd0000,gHost.smmuMap);
  if(!gHost.smmu) { lemonadesReadStep(7,kIOReturnNoMemory,"SMMU mapping"); return; }
  auto read=[&](unsigned at){return read32(gHost.smmu,at);};
  lemonadesPlan=planLemonadesSmmu(gHost.phys,kDmaBytes,read);
  if(!lemonadesReadStep(7,lemonadesPlan.error?kIOReturnNotReady:kIOReturnSuccess,"SMMU plan")) return;
  const char *why="";
  if(!hostStopQueue(&why)) { lemonadesReadStep(8,kIOReturnNotReady,why); return; }
  if(read32(gHost.hc,0x78) || read32(gHost.hc,0x80)) {
    lemonadesReadStep(8,kIOReturnBusy,"task queue active"); return;
  }
  lemonadesReadStep(8,kIOReturnSuccess,"queue stopped");
  // Replan after quiescing, before any SMMU write.
  lemonadesPlan=planLemonadesSmmu(gHost.phys,kDmaBytes,read);
  lemonadesPlan.error=configureLemonadesSmmu(lemonadesPlan,read,
    [&](unsigned at,uint32_t value){write32(gHost.smmu,at,value);});
  if(!lemonadesReadStep(9,lemonadesPlan.error?kIOReturnNotReady:kIOReturnSuccess,"SMMU readback")) return;
  gHost.cb=gHost.smmu+(lemonadesPlan.pages+lemonadesPlan.bank)*4096;
  bzero(gHost.virt,kDmaBytes);
  cacheCivac(gHost.virt,kDmaBytes);
  if(!hostStartQueue(&why)) { lemonadesReadStep(10,kIOReturnNotReady,why); return; }
  if(!lemonadesReadStep(10,hostNop(),"NOP OUT")) return;
  uint32_t power=0;
  IOReturn result=hostQueryRead(3,2,&power);
  gRootDiagnostic.power=power;
  if(!lemonadesReadStep(11,result,"power query")) return;
  if((power&255)!=0x11) {
    uint8_t wake[6]={0x1b,0,0,0,0x10,0}; uint32_t scsi=0;
    if(!lemonadesReadStep(11,hostScsi(0xd0,wake,6,false,0,500000,&scsi),"device wake")) return;
    IOSleep(50);
  }
  for(unsigned attempt=0;attempt<20;++attempt) {
    uint8_t tur[6]={}; uint32_t scsi=0;
    result=hostScsi(0,tur,6,false,0,200000,&scsi);
    if(result==kIOReturnSuccess || gHost.poisoned) break;
    IOSleep(10);
  }
  if(!lemonadesReadStep(12,result,"LUN0 ready")) return;
  uint8_t capacity[10]={0x25}; uint32_t scsi=0;
  result=hostScsi(0,capacity,10,true,8,200000,&scsi);
  if(result==kIOReturnSuccess) {
    lemonades_ufs_read[29]=loadBe32(gHost.virt+kDataOffset);
    lemonades_ufs_read[30]=loadBe32(gHost.virt+kDataOffset+4);
    if(lemonades_ufs_read[30]!=4096 || lemonades_ufs_read[29]<0x3b51ffa ||
       lemonades_ufs_read[29]==UINT32_MAX) result=kIOReturnBadMedia;
  }
  if(!lemonadesReadStep(13,result,"LUN0 geometry")) return;
  gHost.ready=true;
  RootLayout layout;
  if(!findRootLayout(&layout,&why)) { lemonadesReadStep(14,kIOReturnBadMedia,why); return; }
  lemonades_ufs_read[23]=layout.gptHeaderCrc;
  lemonades_ufs_read[24]=layout.gptEntriesCrc;
  // Cross-check the exact Android-collected partition bounds.
  if(layout.userdataFirst!=0x2c0000 || layout.userdataLast!=0x3b51ffa) {
    lemonadesReadStep(14,kIOReturnBadMedia,"userdata differs from phone baseline"); return;
  }
  lemonadesReadStep(15,kIOReturnSuccess,"GPT verified");
  IOLog("UMI UFS: real LUN0 read; GPT CRC valid; userdata=%llx..%llx manifest=%u windows=%u\n",
    layout.userdataFirst,layout.userdataLast,layout.manifestStatus,layout.windows);
}
