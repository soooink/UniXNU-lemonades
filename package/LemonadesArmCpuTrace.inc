// CPU0-only observations. No register writes except temporary IRQ/FIQ masking;
// the driver retains its original GIC setup, timer programming and dispatch.
#ifndef LEMONADES_ARMCPU_PHONE_TRACE
#error "Select the phone or QEMU observer explicitly"
#endif
extern "C" {
volatile uint64_t lemonades_armcpu_observation[32] = {1};
volatile uint64_t lemonades_armcpu_timer_completed = 0;
volatile uint64_t lemonades_armcpu_timer_returned = 0;
volatile uint64_t lemonades_armcpu_timer_first_counter = 0;
volatile uint64_t lemonades_armcpu_timer_last_counter = 0;
#if LEMONADES_ARMCPU_PHONE_TRACE
void umi_early_trace(unsigned long, unsigned long, unsigned long);
extern unsigned long umi_trace_console_address;
#endif
// Called only after the eighth real timer IRQ has returned from rtclock_intr
// and executed ICC_EOIR1_EL1. The debugger observes; it never invokes this.
__attribute__((noinline)) void lemonades_armcpu_timer_checkpoint(void)
{
  __asm__ volatile ("" ::: "memory");
}
}

static void lemonadesArmCpuObserve(uint64_t phase, uint64_t detail)
{
  uint64_t daif, frequency, count, deadline, control;
  __asm__ volatile ("mrs %0, daif\n\tmsr daifset, #3" : "=r"(daif) :: "memory");
  __asm__ volatile ("mrs %0, cntfrq_el0" : "=r"(frequency));
  __asm__ volatile ("isb\n\tmrs %0, cntvct_el0" : "=r"(count));
  __asm__ volatile ("mrs %0, cntv_cval_el0" : "=r"(deadline));
  __asm__ volatile ("mrs %0, cntv_ctl_el0" : "=r"(control));
  lemonades_armcpu_observation[1] = phase;
  lemonades_armcpu_observation[2] = armcpu_registered;
  lemonades_armcpu_observation[3] = armcpu_gic_ready;
  lemonades_armcpu_observation[4] = armcpu_timer_interrupts;
  lemonades_armcpu_observation[5] = lemonades_armcpu_timer_completed;
  lemonades_armcpu_observation[6] = armcpu_irq_id;
  lemonades_armcpu_observation[7] = armcpu_irq_phase;
  lemonades_armcpu_observation[8] = frequency;
  lemonades_armcpu_observation[9] = count;
  lemonades_armcpu_observation[10] = deadline;
  lemonades_armcpu_observation[11] = control;
  lemonades_armcpu_observation[12] = daif;
  lemonades_armcpu_observation[13] = detail;
  if (phase == 4) { lemonades_armcpu_observation[14] = detail; }
  lemonades_armcpu_observation[15] = armcpu_boot_mpidr;
  for (unsigned i = 0; i < 8; ++i) {
    lemonades_armcpu_observation[16 + i] = armcpu_gic_boot[i];
  }
  lemonades_armcpu_observation[24] = armcpu_quiesce_calls;
  lemonades_armcpu_observation[25] = armcpu_halt_calls;
  lemonades_armcpu_observation[26] = lemonades_armcpu_timer_returned;
  lemonades_armcpu_observation[27] = lemonades_armcpu_timer_first_counter;
  lemonades_armcpu_observation[28] = lemonades_armcpu_timer_last_counter;
  lemonades_armcpu_observation[29] = lemonades_armcpu_observation[29] | (1ULL << phase);
#if LEMONADES_ARMCPU_PHONE_TRACE
  for (unsigned i = 0; i < 32; ++i) {
    umi_early_trace(0x80 + i, lemonades_armcpu_observation[i], umi_trace_console_address);
  }
#endif
  __asm__ volatile ("msr daif, %0" :: "r"(daif) : "memory");
}

static bool lemonadesArmCpuSampleTimer(void)
{
  uint64_t count = armcpu_timer_interrupts;
  return count == 1 || count == 2 || count == 8;
}
