// SPDX-License-Identifier: MIT
// CPU0 diagnostic observations; no display MMIO or emulated hardware results.
#ifndef LEMONADES_BOOT_PROGRESS_TRACE_H
#define LEMONADES_BOOT_PROGRESS_TRACE_H
extern volatile uint64_t armcpu_timer_interrupts __attribute__((weak_import));
extern volatile uint64_t lemonades_armcpu_timer_completed __attribute__((weak_import));
volatile uint64_t lemonades_boot_progress_observation[16];
volatile uint64_t lemonades_boot_progress_samples[2][16];
volatile uint64_t lemonades_boot_progress_anchor[3];
__attribute__((noinline)) void lemonades_boot_progress_checkpoint_three(void) {
  __asm__ volatile("" ::: "memory");
}
__attribute__((noinline)) void lemonades_boot_progress_checkpoint_eight(void) {
  __asm__ volatile("" ::: "memory");
}
#if LEMONADES_BOOT_PROGRESS_PHONE
extern void lemonades_early_trace(uint64_t, uint64_t, uint64_t);
extern uint64_t lemonades_trace_console_address;
#endif
static void lemonades_boot_progress_record(unsigned phase) {
  uint64_t daif,counter;
  __asm__ volatile("mrs %0,daif\n\tmsr daifset,#3\n\tisb\n\tmrs %1,cntpct_el0"
                   : "=r"(daif),"=r"(counter) :: "memory");
  const uint64_t record[16]={1,phase,
    boot_progress_frequency?(counter-boot_progress_epoch)/boot_progress_frequency:0,
    thread_count,bind_result,bind_base,display.width,display.height,display.stride,
    irq_entries,BP_OPTIONAL(armcpu_timer_interrupts),BP_OPTIONAL(lemonades_armcpu_timer_completed),
    pulse_worker_status,pulse.ready,
    (uint64_t)!!&native_ufs_block_reads | ((uint64_t)!!&native_virtio_ready<<1) |
      ((uint64_t)!!&native_owner_root_accepted<<2),
    counter};
  for(unsigned i=0;i<16;++i) {
    lemonades_boot_progress_observation[i]=record[i];
    if(phase==5 || phase==6)
      lemonades_boot_progress_samples[phase-5][i]=record[i];
#if LEMONADES_BOOT_PROGRESS_PHONE
    if(lemonades_trace_console_address)
      lemonades_early_trace(0xc0+i,record[i],lemonades_trace_console_address);
#endif
  }
  __asm__ volatile("msr daif,%0" :: "r"(daif) : "memory");
}
#endif
