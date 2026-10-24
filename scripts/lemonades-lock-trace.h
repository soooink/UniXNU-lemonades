/* Capture the failing lock and the current thread's bounded XNU backtrace.
 * Called only immediately before the existing preemption-contract panic.
 * The lock rule and panic remain unchanged.
 */
#include <kern/backtrace.h>
#include "../arm64/umi_early_trace_config.h"
volatile uint64_t lemonades_lock_failure_observation[64];
__attribute__((noinline)) void lemonades_lock_failure_checkpoint(void)
{
	__asm__ volatile("" ::: "memory");
}
static void lemonades_lock_failure_record(lck_rw_t *lock, unsigned line)
{
	uint64_t daif;
	__asm__ volatile("mrs %0,daif" : "=r"(daif));
	uintptr_t frames[48];
	unsigned count = backtrace(frames, 48, NULL, NULL);
	volatile uint64_t *v = lemonades_lock_failure_observation;
	for (unsigned i = 0; i < 64; ++i) v[i] = 0;
	v[0] = 1;
	v[1] = (uintptr_t)lock;
	v[2] = lock->lck_rw_data;
	v[3] = lock->lck_rw_owner;
	v[4] = lock->lck_rw_can_sleep;
	v[5] = get_preemption_level();
	v[6] = daif;
	v[7] = (uintptr_t)current_thread();
	v[8] = sizeof(*lock);
	v[9] = count;
	for (unsigned i = 0; i < count; ++i) v[10+i] = frames[i];
	v[58] = line;
#if LEMONADES_EARLY_TRACE
	extern unsigned long lemonades_trace_console_address;
	__asm__ volatile("msr daifset,#3" ::: "memory");
	volatile uint32_t *header = (volatile uint32_t *)lemonades_trace_console_address;
	const uint32_t capacity = 0x200000 - 12;
	if (header && header[0] == 0x43474244 && header[1] <= capacity && header[2] <= capacity) {
		uint32_t at = header[1] == capacity ? 0 : header[1], size = header[2];
		volatile unsigned char *out = (volatile unsigned char *)header + 12;
		const char hex[] = "0123456789abcdef";
		for (unsigned copy = 0; copy < 5; ++copy) {
			for (unsigned field = 0; field < 64; ++field) {
				uint64_t value = v[field];
				uint32_t crc = 0xffffffff;
				for (unsigned i = 0; i < 10; ++i) {
					unsigned byte = i == 0 ? 1 : i == 1 ? field : (value >> ((i-2)*8)) & 255;
					crc ^= byte;
					for (unsigned bit = 0; bit < 8; ++bit)
						crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1)));
				}
				crc ^= 0xffffffff;
				char row[42] = "\nUMI LOCK 01 ";
				unsigned n = 13;
				row[n++] = hex[field >> 4]; row[n++] = hex[field & 15];
				row[n++] = ' ';
				for (int shift = 60; shift >= 0; shift -= 4) row[n++] = hex[(value >> shift) & 15];
				row[n++] = ' ';
				for (int shift = 28; shift >= 0; shift -= 4) row[n++] = hex[(crc >> shift) & 15];
				row[n++] = '\n';
				for (unsigned i = 0; i < n; ++i) {
					out[at] = row[i];
					at = at + 1 == capacity ? 0 : at + 1;
					if (size < capacity) ++size;
				}
			}
		}
		__asm__ volatile("dsb sy" ::: "memory");
		header[2] = size; header[1] = at;
		__asm__ volatile("dsb sy" ::: "memory");
	}
	__asm__ volatile("msr daif,%0" :: "r"(daif) : "memory");
#endif
	lemonades_lock_failure_checkpoint();
}

/* Explicit QEMU-only failure-path input; absent from ordinary boot arguments. */
void lemonades_lock_failure_selftest(void)
{
	static lck_rw_t own_lock;
	own_lock = (lck_rw_t){ .lck_rw_type = LCK_TYPE_RW, .lck_rw_can_sleep = false,
	                       .lck_rw_priv_excl = true };
	lck_rw_lock_shared(&own_lock);
	panic("lemonades lock failure selftest unexpectedly returned");
}
