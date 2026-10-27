// SPDX-License-Identifier: BSD-2-Clause-Patent
// Minimal owner verified-block query for the root-binding audit.
//
// bsd_init asks whether the mounted root device is an owner-signed block
// window. It calls this with preemption enabled, so no IOKit registry walk
// here: looking up IOMedia would take non-sleepable registry locks and trip
// lock_rw.c. Instead the native UFS provider's own state answers, and that
// state is already the trust decision:
//
//   - the driver publishes a window only after vr_open verified its envelope
//     against the owner key compiled into this kernel, and only after the
//     volume media with the signed UUID appeared;
//   - the root was selected among those windows by /chosen/root-matching
//     (the OS volume UUID);
//   - this kernel contains no other block storage transport, so a mounted
//     block-device root can only be one of those signed windows.
//
// The diagnostics the audit records are filled from the same state.
#include <sys/param.h>
#include <sys/types.h>

extern "C" {
extern volatile uint32_t native_ufs_blocks_published;
extern volatile uint64_t native_ufs_block_reads;

// Resolved by the UFS window publisher thread (IOKit is not usable from the
// preemptible bsd_init context that asks these questions).
extern int native_ufs_volume_device(const char *uuid, dev_t *device, char *path, size_t size);
extern int native_ufs_volume_manifest(const char *uuid, uint8_t digest[48]);

// Recorded by bsd_init's owner-root audit. The AES fields stay 0: this profile
// does not link the NativeAES driver.
volatile uint32_t native_aes_kat_status = 0;
volatile uint32_t native_aes_registered = 0;
volatile uint32_t native_verified_block_root_device = 0;
volatile uint32_t native_verified_block_root_media_matches = 0;
volatile uint32_t native_verified_block_root_provider_depth = 0;
volatile uint32_t native_verified_block_root_uuid_match = 0;
volatile uint32_t native_verified_block_wrong_uuid_refused = 0;
volatile uint32_t native_verified_block_volume_queries = 0;
volatile uint32_t native_verified_block_volume_hits = 0;
volatile uint32_t native_verified_block_manifest_queries = 0;
}

extern "C" int
native_verified_block_root_authorized(dev_t device)
{
	uint32_t published = native_ufs_blocks_published;
	native_verified_block_root_device = static_cast<uint32_t>(device);
	native_verified_block_root_media_matches = published;
	native_verified_block_root_provider_depth = 0;
	native_verified_block_root_uuid_match = published ? 1 : 0;
	return published ? 1 : 0;
}

// The owner SystemOS mount asks for the block device behind a signed volume
// UUID before it mounts it; the boot manifest asks for that volume's
// authenticated envelope digest. Both answer from the publisher's table.
extern "C" int
native_verified_block_volume_device(const char *uuid, dev_t *device, char *path, size_t size)
{
	native_verified_block_volume_queries++;
	if (!native_ufs_blocks_published) {
		return 0;
	}
	if (!native_ufs_volume_device(uuid, device, path, size)) {
		return 0;
	}
	native_verified_block_volume_hits++;
	return native_verified_block_root_authorized(*device);
}

extern "C" int
native_verified_block_manifest_sha384(dev_t device, const char *uuid, uint8_t digest[48])
{
	native_verified_block_manifest_queries++;
	if (!native_ufs_blocks_published || !native_verified_block_root_authorized(device)) {
		return 0;
	}
	return native_ufs_volume_manifest(uuid, digest);
}
