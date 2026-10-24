/* Bounded observations of real exec, EL0 exception and panic boundaries.
 * No user-memory reads, allocation, policy changes or fabricated results.
 */
#include <stdint.h>
#include "umi_early_trace_config.h"
void lemonades_exec_trace_record(unsigned, uint64_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t);
#ifdef LEMONADES_EXEC_TRACE_IMPLEMENTATION
#include <kern/backtrace.h>
volatile uint64_t lemonades_exec_trace_observation[20];
volatile uint64_t lemonades_exec_trace_seen;
__attribute__((noinline)) void lemonades_exec_trace_checkpoint(void)
{
	__asm__ volatile("" ::: "memory");
}
void lemonades_exec_trace_record(unsigned phase, uint64_t a, uint64_t b, uint64_t c,
    uint64_t d, uint64_t e, uint64_t f)
{
	if (phase >= 64) return;
	uint64_t daif;
	__asm__ volatile("mrs %0,daif\n\tmsr daifset,#3" : "=r"(daif) :: "memory");
	uint64_t bit = 1ull << phase;
	if (lemonades_exec_trace_seen & bit) {
		__asm__ volatile("msr daif,%0" :: "r"(daif) : "memory");
		return;
	}
	lemonades_exec_trace_seen |= bit;
	uint64_t values[20] = {1, phase, a, b, c, d, e, f};
	if (phase == 5 || phase == 7) {
		uintptr_t frames[11];
		unsigned count = backtrace(frames, 11, NULL, NULL);
		values[8] = count;
		for (unsigned i = 0; i < count; ++i) values[9+i] = frames[i];
	}
	for (unsigned i = 0; i < 20; ++i) lemonades_exec_trace_observation[i] = values[i];
#if LEMONADES_EARLY_TRACE
	extern unsigned long lemonades_trace_console_address;
	volatile uint32_t *header = (volatile uint32_t *)lemonades_trace_console_address;
	const uint32_t capacity = 0x200000 - 12;
	if (header && header[0] == 0x43474244 && header[1] <= capacity && header[2] <= capacity) {
		uint32_t at = header[1] == capacity ? 0 : header[1], size = header[2];
		volatile unsigned char *out = (volatile unsigned char *)header + 12;
		const char hex[] = "0123456789abcdef";
		for (unsigned copy = 0; copy < 5; ++copy) {
			for (unsigned field = 0; field < 20; ++field) {
				uint64_t value = values[field];
				uint32_t crc = 0xffffffff;
				for (unsigned i = 0; i < 10; ++i) {
					unsigned byte = i == 0 ? phase : i == 1 ? field : (value >> ((i-2)*8)) & 255;
					crc ^= byte;
					for (unsigned j = 0; j < 8; ++j)
						crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1)));
				}
				crc ^= 0xffffffff;
				char row[42] = "\nUMI EXEC ";
				unsigned n = 10;
				row[n++] = hex[phase >> 4]; row[n++] = hex[phase & 15]; row[n++] = ' ';
				row[n++] = hex[field >> 4]; row[n++] = hex[field & 15]; row[n++] = ' ';
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
#endif
	__asm__ volatile("msr daif,%0" :: "r"(daif) : "memory");
	lemonades_exec_trace_checkpoint();
}
#endif
