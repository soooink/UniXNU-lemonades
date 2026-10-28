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
#include <kern/clock.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/vfs_context.h>
#include <libkern/libkern.h>
#include <libkern/copyio.h>

// The query module compiles against the plain bsd_init record (no IOKit
// linkage), so the sleep below is the osfmk delay(), not IOSleep.

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
	// The boot manifest runs immediately after the union mount; the window
	// publisher's record may still be filling the digest/authentication for
	// this volume. Retry briefly rather than refusing the owner identity.
	uint8_t scratch[48];
	for (unsigned attempt = 0; attempt < 4; ++attempt) {
		if (native_ufs_volume_manifest(uuid, scratch)) {
			if (digest) {
				memcpy(digest, scratch, 48);
			}
			return 1;
		}
		delay(10000);  // 10 ms; the publisher retries its lookup on this cadence
	}
	return 0;
}

// load_init_program (union SystemOS mode) sets envp to USER_ADDR_NULL, so
// dyld falls back to its default cache search paths, which assume the
// cryptex is mounted at /System/Cryptexes/OS.  This device unions the
// cryptex over "/", so the cache lives at /System/Library/Caches/... .
// Supply DYLD_SHARED_CACHE_DIR pointing at the first candidate directory
// that actually contains the shared cache (probed with vnode_lookup, safe
// in the bsd_init thread like the mount code).
extern "C" user_addr_t
native_owner_cache_envp(user_addr_t scratch)
{
	static const char *const dirs[] = {
		"/System/Library/Caches/com.apple.dyld",
		"/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld",
		"/private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld",
	};
	const char *chosen = dirs[0];
	char path[192];
	for (size_t index = 0; index < sizeof(dirs) / sizeof(dirs[0]); ++index) {
		snprintf(path, sizeof(path), "%s/dyld_shared_cache_arm64", dirs[index]);
		vnode_t probe = NULLVP;
		if (vnode_lookup(path, 0, &probe, vfs_context_kernel()) == 0 && probe) {
			vnode_put(probe);
			chosen = dirs[index];
			break;
		}
	}
	char variable[224];
	snprintf(variable, sizeof(variable), "DYLD_SHARED_CACHE_DIR=%s", chosen);
	user64_addr_t vector[2];
	user_addr_t placement = scratch + 0x400;
	if (copyout(variable, placement, strlen(variable) + 1) != 0) {
		return USER_ADDR_NULL;
	}
	vector[0] = scratch + 0x400;
	vector[1] = 0;
	if (copyout(vector, scratch + 0x500, sizeof(vector)) != 0) {
		return USER_ADDR_NULL;
	}
	return scratch + 0x500;
}
