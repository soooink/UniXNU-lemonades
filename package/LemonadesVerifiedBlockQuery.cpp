// SPDX-License-Identifier: BSD-2-Clause-Patent
// Minimal owner verified-block query for the root-binding audit.
//
// The kernel asks whether the mounted root device is an owner-signed block
// window (bsd_init's rootvp authentication). The answer comes from the native
// UFS provider: native_ufs_block_authenticates compares the media's volume
// UUID with the UUID in the signed envelope that published the window, so the
// same signature that authorized publication authorizes the root.
//
// This replaces the full NativeVirtioBlock provider for devices whose only
// verified transport is the native UFS driver.
#include <IOKit/IOBSD.h>
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSIterator.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSString.h>
#include <sys/param.h>
#include <sys/types.h>

extern "C" int native_ufs_block_authenticates(IOService *, const char *, uint8_t *)
    __attribute__((weak));

extern "C" int
native_verified_block_root_authorized(dev_t device)
{
	if (!native_ufs_block_authenticates) {
		return 0;
	}
	OSDictionary *matching = IOService::serviceMatching("IOMedia");
	OSDictionary *properties = OSDictionary::withCapacity(2);
	OSNumber *mjr = OSNumber::withNumber(static_cast<unsigned long long>(major(device)), 32);
	OSNumber *mnr = OSNumber::withNumber(static_cast<unsigned long long>(minor(device)), 32);
	bool ready = matching && properties && mjr && mnr &&
	    properties->setObject(kIOBSDMajorKey, mjr) &&
	    properties->setObject(kIOBSDMinorKey, mnr) &&
	    matching->setObject("IOPropertyMatch", properties);
	if (mnr) {
		mnr->release();
	}
	if (mjr) {
		mjr->release();
	}
	if (properties) {
		properties->release();
	}
	OSIterator *iterator = ready ? IOService::getMatchingServices(matching) : nullptr;
	if (matching) {
		matching->release();
	}
	if (!iterator) {
		return 0;
	}
	int authorized = 0;
	unsigned matches = 0;
	while (OSObject *object = iterator->getNextObject()) {
		IOService *media = OSDynamicCast(IOService, object);
		if (!media) {
			continue;
		}
		if (++matches != 1) {
			authorized = 0;
			break;
		}
		OSString *uuid = OSDynamicCast(OSString, media->getProperty("UUID"));
		if (!uuid || uuid->getLength() != 36) {
			continue;
		}
		for (IOService *provider = media; provider; provider = provider->getProvider()) {
			int ufs = native_ufs_block_authenticates(provider, uuid->getCStringNoCopy(), nullptr);
			if (ufs >= 0) {
				authorized = ufs == 1;
				break;
			}
		}
	}
	iterator->release();
	return authorized;
}
