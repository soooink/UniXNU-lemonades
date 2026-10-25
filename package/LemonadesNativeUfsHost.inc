// SPDX-License-Identifier: BSD-2-Clause-Patent
// SM8250 host adapter for the unchanged upstream NativeUfsBlock implementation.
// Uses the same queue, cache, command and two-stream takeover as attempt 34.
static bool hostBringUp(const char **why)
{
  if (gHost.poisoned) { *why="transport quarantined"; return false; }
  if (gHost.ready) return true;
  if (!UMI_UFS_PHONE) { *why="QEMU: no Qualcomm hardware"; return false; }
  if (!isUmi()) { *why="board model not qualified for UFS host access"; return false; }
  OSSharedPtr<IOMemoryMap> clocks;
  uintptr_t gcc=mapPhys(0x177000,4096,clocks);
  if (!gcc || !(read32(gcc,4)&0x80000000) ||
      !(read32(gcc,0x10)&1) || !(read32(gcc,0x18)&1)) {
    *why="UFS power/clocks disabled"; return false;
  }
  gRootDiagnostic.stage="controller map";
  gHost.hc=mapPhys(0x1d84000,0x3000,gHost.hcMap);
  if (!gHost.hc) { *why="controller mapping"; return false; }
  gRootDiagnostic.cap=read32(gHost.hc,0);
  gRootDiagnostic.version=read32(gHost.hc,8);
  gRootDiagnostic.hcs=read32(gHost.hc,0x30);
  gRootDiagnostic.hce=read32(gHost.hc,0x34);
  gRootDiagnostic.stage="DMA allocation";
  gHost.dma=IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task,
    IOOptionBits(kIODirectionInOut)|IOOptionBits(kIOMemoryPhysicallyContiguous)|
    IOOptionBits(kIOMemoryMapperNone),kDmaBytes,4096);
  gHost.lock=IOLockAlloc();
  if (!gHost.dma || !gHost.lock) { *why="DMA allocation"; return false; }
  gHost.virt=static_cast<uint8_t *>(gHost.dma->getBytesNoCopy());
  IOByteCount contiguous=0;
  gHost.phys=gHost.dma->getPhysicalSegment(0,&contiguous,kIOMemoryMapperNone);
  gRootDiagnostic.dma=gHost.phys;
  gRootDiagnostic.contiguous=contiguous;
  // Check the actual XNU-owned allocation. The SMMU planner below separately
  // enforces the hardware's input/output address widths on the real DMA PA.
  if (!gHost.virt || (gHost.phys&4095) || contiguous<kDmaBytes ||
      !umiDmaInOwnedMemory(gHost.phys,kDmaBytes,gPhysBase,gPhysSize)) {
    *why="DMA outside owned conventional RAM"; return false;
  }
  gRootDiagnostic.stage="SMMU mapping";
  gHost.smmu=mapPhys(0x15000000,0xd0000,gHost.smmuMap);
  if (!gHost.smmu) { *why="SMMU mapping"; return false; }
  auto read=[&](unsigned at){return read32(gHost.smmu,at);};
  UmiSmmuPlan plan=planUmiSmmu(gHost.phys,kDmaBytes,read);
  if (plan.error) { *why="SMMU plan refused"; return false; }
  gRootDiagnostic.stage="stop old queue";
  if (!hostStopQueue(why)) return false;
  if (read32(gHost.hc,0x78) || read32(gHost.hc,0x80)) {
    *why="firmware task queue active"; return false;
  }
  plan=planUmiSmmu(gHost.phys,kDmaBytes,read);
  plan.error=configureUmiSmmu(plan,read,
    [&](unsigned at,uint32_t value){write32(gHost.smmu,at,value);});
  if (plan.error) { *why="SMMU dual-stream readback"; return false; }
  gHost.cb=gHost.smmu+(plan.pages+plan.bank)*4096;
  gRootDiagnostic.smmuId2=read32(gHost.smmu,0x28);
  gRootDiagnostic.cba2r=read32(gHost.smmu,0x1800+4*plan.bank);
  gRootDiagnostic.gfsrBefore=read32(gHost.smmu,0x48);
  gRootDiagnostic.fsrBefore=read32(gHost.cb,0x58);
  bzero(gHost.virt,kDmaBytes);
  cacheCivac(gHost.virt,kDmaBytes);
  if (!hostStartQueue(why)) return false;
  gRootDiagnostic.stage="NOP OUT";
  if (hostNop()!=kIOReturnSuccess) { *why="NOP OUT"; return false; }
  uint32_t power=0;
  gRootDiagnostic.stage="power query";
  if (hostQueryRead(3,2,&power)!=kIOReturnSuccess) { *why="power query"; return false; }
  gRootDiagnostic.power=power;
  if ((power&255)!=0x11) {
    uint8_t wake[6]={0x1b,0,0,0,0x10,0}; uint32_t scsi=0;
    if (hostScsi(0xd0,wake,6,false,0,500000,&scsi)!=kIOReturnSuccess) {
      *why="wake"; return false;
    }
    IOSleep(50);
  }
  gRootDiagnostic.stage="LUN ready";
  IOReturn result=kIOReturnNotReady;
  for (unsigned attempt=0; attempt<20; ++attempt) {
    uint8_t tur[6]={}; uint32_t scsi=0;
    result=hostScsi(0,tur,6,false,0,200000,&scsi);
    if (result==kIOReturnSuccess || gHost.poisoned) break;
    IOSleep(10);
  }
  if (result!=kIOReturnSuccess) { *why="LUN ready"; return false; }
  gRootDiagnostic.stage="LUN capacity";
  uint8_t capacity[10]={0x25}; uint32_t scsi=0;
  if (hostScsi(0,capacity,10,true,8,200000,&scsi)!=kIOReturnSuccess ||
      loadBe32(gHost.virt+kDataOffset)!=0x3b51fff ||
      loadBe32(gHost.virt+kDataOffset+4)!=4096) {
    *why="LUN geometry differs from hardware baseline"; return false;
  }
  gHost.ready=true;
  return true;
}
