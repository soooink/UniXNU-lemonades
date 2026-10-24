// SPDX-License-Identifier: BSD-2-Clause-Patent
// Persist the real provider's software state using the existing RAM journal.
extern "C" {
volatile uint64_t lemonades_native_ufs_observation[32];
#if LEMONADES_UFS_PHONE
void lemonades_early_trace(uint64_t,uint64_t,uint64_t);
extern uint64_t lemonades_trace_console_address;
#endif
__attribute__((noinline)) void lemonades_native_ufs_checkpoint(void)
{
  auto &r=lemonades_native_ufs_observation;
  r[0]=4; r[1]=native_ufs_root_step; r[2]=LEMONADES_UFS_PHONE;
  r[3]=native_ufs_probe_requested; r[4]=native_ufs_matched;
  r[5]=gHost.ready; r[6]=gHost.poisoned; r[7]=gRootDiagnostic.command;
  r[8]=gRootDiagnostic.result; r[9]=gRootDiagnostic.ocs;
  r[10]=gRootDiagnostic.scsi; r[11]=gRootDiagnostic.protocol;
  r[12]=gRootDiagnostic.residual; r[13]=gRootDiagnostic.dma;
  r[14]=gRootDiagnostic.first; r[15]=gRootDiagnostic.last;
  r[16]=gRootDiagnostic.manifest; r[17]=gRootDiagnostic.windows;
  r[18]=gRootDiagnostic.prepared; r[19]=native_ufs_blocks_published;
  r[20]=native_ufs_block_reads; r[21]=native_ufs_block_failures;
  r[22]=gRootDiagnostic.policyCount; r[23]=gRootDiagnostic.verify;
  r[24]=gRootDiagnostic.publicationPhase; r[25]=gRootDiagnostic.publicationWindow;
  r[26]=native_ufs_verified_blocks; r[27]=native_ufs_integrity_failures;
  r[28]=gRootDiagnostic.magic0; r[29]=gRootDiagnostic.magic1;
  r[30]=lemonades_mmio_upper_seen;
  uint64_t ticks;
  __asm__ volatile("isb\n\tmrs %0,cntpct_el0":"=r"(ticks));
  r[31]=ticks;
#if LEMONADES_UFS_PHONE
  uint64_t daif;
  __asm__ volatile("mrs %0,daif\n\tmsr daifset,#3":"=r"(daif)::"memory");
  if (lemonades_trace_console_address)
    for (unsigned i=0;i<32;++i)
      lemonades_early_trace(0xe0+i,r[i],lemonades_trace_console_address);
  __asm__ volatile("msr daif,%0"::"r"(daif):"memory");
#endif
}
}
