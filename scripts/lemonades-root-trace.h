/* Retained RAM observations of the real upstream owner-root decision.
 * CRC per field and five copies allow recovery to reject damaged bytes.
 * This records state only; it does not change the authentication result.
 */
#include <stdint.h>
volatile uint64_t umi_owner_root_observation[18];
static void umi_owner_root_record(unsigned phase)
{
	extern volatile unsigned native_verified_block_root_device;
	extern volatile unsigned native_verified_block_root_media_matches;
	extern volatile unsigned native_verified_block_root_provider_depth;
	extern volatile unsigned native_verified_block_root_uuid_match;
	extern volatile unsigned native_verified_block_wrong_uuid_refused;
	extern volatile unsigned native_ufs_blocks_published;
	extern volatile uint64_t native_ufs_verified_blocks;
	extern volatile unsigned native_ufs_integrity_failures;
	extern volatile unsigned native_aes_kat_status;
	extern volatile unsigned native_aes_registered;
	volatile uint64_t *v = umi_owner_root_observation;
	v[0] = phase;
	v[1] = native_owner_root_trust_enabled;
	v[2] = native_owner_root_apple_autherr;
	v[3] = native_owner_root_decision;
	v[4] = native_owner_root_accepted;
	v[5] = native_owner_root_readonly;
	v[6] = (uint32_t)native_owner_root_mount_device;
	v[7] = (uint32_t)native_owner_root_selected_device;
	v[8] = native_verified_block_root_device;
	v[9] = native_verified_block_root_media_matches;
	v[10] = native_verified_block_root_provider_depth;
	v[11] = native_verified_block_root_uuid_match;
	v[12] = native_verified_block_wrong_uuid_refused;
	v[13] = native_ufs_blocks_published;
	v[14] = native_ufs_verified_blocks;
	v[15] = native_ufs_integrity_failures;
	v[16] = native_aes_kat_status;
	v[17] = native_aes_registered;
#if UMI_EARLY_TRACE
	extern unsigned long umi_trace_console_address;
	uint64_t daif;
	__asm__ volatile("mrs %0,daif\n\tmsr daifset,#3" : "=r"(daif) :: "memory");
	volatile uint32_t *header = (volatile uint32_t *)umi_trace_console_address;
	const uint32_t capacity = 0x200000 - 12;
	if (header && header[0] == 0x43474244 && header[1] <= capacity && header[2] <= capacity) {
		uint32_t at = header[1] == capacity ? 0 : header[1], size = header[2];
		volatile unsigned char *out = (volatile unsigned char *)header + 12;
		const char hex[] = "0123456789abcdef";
		for (unsigned copy = 0; copy < 5; ++copy) {
			for (unsigned field = 0; field < 18; ++field) {
				uint64_t value = v[field];
				uint32_t crc = 0xffffffff;
				for (unsigned i = 0; i < 10; ++i) {
					unsigned byte = i == 0 ? phase : i == 1 ? field : (value >> ((i-2)*8)) & 255;
					crc ^= byte;
					for (unsigned bit = 0; bit < 8; ++bit)
						crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1)));
				}
				crc ^= 0xffffffff;
				char line[42] = "\nUMI ROOT ";
				unsigned n = 10;
				line[n++] = hex[(phase >> 4) & 15]; line[n++] = hex[phase & 15];
				line[n++] = ' ';
				line[n++] = hex[field >> 4]; line[n++] = hex[field & 15];
				line[n++] = ' ';
				for (int shift = 60; shift >= 0; shift -= 4) line[n++] = hex[(value >> shift) & 15];
				line[n++] = ' ';
				for (int shift = 28; shift >= 0; shift -= 4) line[n++] = hex[(crc >> shift) & 15];
				line[n++] = '\n';
				for (unsigned i = 0; i < n; ++i) {
					out[at] = line[i];
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
}
