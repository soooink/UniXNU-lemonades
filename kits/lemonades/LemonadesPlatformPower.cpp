// SPDX-License-Identifier: MIT
// Adapted from UniXNU-sheng, pinned a599a1a8a92093b5077543e071b72130769eb325.
// Umi original PMGR service integration; no SM8550 hardware resources.
// Board-side original PMGR ABI qualification. Default off. Modes: 1 releases
// unpublished objects, 2 publishes the original nub, 3 tests power refusal.
// No clocks, sleep, reset or secondary-CPU success is advertised.
#include "OriginalPMGRABI.h"
#include "arm64/umi_early_trace_config.h"
#include <IOKit/IOLib.h>
#include <IOKit/IOPlatformExpert.h>
#include <libkern/c++/OSSymbol.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>

extern "C" {
extern kmod_info_t g_kernel_kmod_info;
kern_return_t OSKextLoadKextWithIdentifier(const char *);
void umi_pmgr_static_init(void) __asm__("__GLOBAL__sub_I_UmiPlatformPower.cpp");
IOService *umi_original_pmgr_nub_create(IORegistryEntry *, ApplePMGR *);
uint32_t umi_original_pmgr_nub_read(IOService *);
void umi_original_pmgr_nub_write(IOService *, uint64_t);
// stage,status,parent-size,own-size,provider,nub,bound-provider,read-before,
// read-after,own-before,own-after,nub-before,nub-after,attached,registered,mode.
volatile uint64_t umi_pmgr_observation[16];
#if UMI_EARLY_TRACE
void umi_early_trace(unsigned long, unsigned long, unsigned long);
extern unsigned long umi_trace_console_address;
#endif
__attribute__((noinline)) void umi_pmgr_checkpoint(void) {
#if UMI_EARLY_TRACE
  for (unsigned i = 0; i < 16; ++i)
    umi_early_trace(0x70 + i, umi_pmgr_observation[i], umi_trace_console_address);
#endif
  __asm__ volatile("" ::: "memory");
}
// Called at the root-volume lookup boundary, after ordinary platform matching.
// Read existing driver counters; never manufacture readiness or interrupts.
#if UMI_EARLY_TRACE
extern volatile uint32_t armcpu_registered, armcpu_gic_ready;
extern volatile uint64_t armcpu_timer_interrupts;
__attribute__((noinline)) void umi_runtime_checkpoint(void) {
  umi_early_trace(0xd0, 1, umi_trace_console_address);
  umi_early_trace(0xd1, armcpu_registered, umi_trace_console_address);
  umi_early_trace(0xd2, armcpu_gic_ready, umi_trace_console_address);
  umi_early_trace(0xd3, armcpu_timer_interrupts, umi_trace_console_address);
}
#endif
}

__attribute__((noreturn)) static void unavailable(unsigned slot)
{
  umi_pmgr_observation[0] = 0x100 + slot;
  umi_pmgr_observation[1] = static_cast<uint32_t>(kIOReturnUnsupported);
  umi_pmgr_checkpoint();
  panic("UmiPlatformPower: unimplemented operation %u", slot);
}

class UmiPlatformPower : public ApplePMGR {
  OSDeclareDefaultStructors(UmiPlatformPower)
public:
  void enableCPUCore(unsigned, uint64_t) override { unavailable(168); }
  void enableCPUCore(unsigned) override { unavailable(169); }
  void disableCPUCore(unsigned) override { unavailable(170); }
  void enableCPUCluster(unsigned) override { unavailable(171); }
  void disableCPUCluster(unsigned) override { unavailable(172); }
  void initCPUIdle(ml_processor_info_t *) override { unavailable(173); }
  void enterCPUIdle(UInt64 *) override { unavailable(174); }
  void exitCPUIdle(UInt64 *) override { unavailable(175); }
  void updateCPUIdle(UInt64 *) override { unavailable(176); }
#include "GuardedPMGRSlots.inc"
};
OSDefineMetaClassWithInit(UmiPlatformPower, ApplePMGR, )
OSMetaClassConstructorInit(UmiPlatformPower, ApplePMGR, )
OSDefineBasicStructors(UmiPlatformPower, ApplePMGR)
// The original object's storage exceeds kalloc_type's 16 KiB size limit.
// Use XNU's existing zeroed, size-aware OSObject heap allocation pair.
void *UmiPlatformPower::operator new(size_t size) { return OSObject::operator new(size); }
void UmiPlatformPower::operator delete(void *memory, size_t size)
{
  OSObject::operator delete(memory, size);
}
static_assert(sizeof(UmiPlatformPower) == 0x4b8a8, "Exact original provider storage");

static const OSMetaClass *lookup(const char *text)
{
  const OSSymbol *name = OSSymbol::withCString(text);
  const OSMetaClass *meta = name ? OSMetaClass::getMetaClassWithName(name) : nullptr;
  OSSafeReleaseNULL(name);
  return meta;
}

extern "C" void umi_pmgr_run(void)
{
  unsigned mode = 0;
  if (!PE_parse_boot_argn("umi-pmgr", &mode, sizeof(mode)) || !mode) return;
  umi_pmgr_observation[15] = mode;
  umi_pmgr_observation[1] = static_cast<uint32_t>(kIOReturnError);
  if (mode > 3 || umi_pmgr_observation[0]) { umi_pmgr_checkpoint(); panic("UmiPlatformPower: invalid mode or duplicate initialization"); }
  umi_pmgr_observation[0] = 1;
  kern_return_t result = OSKextLoadKextWithIdentifier("com.apple.driver.ApplePMGR");
  if (result) { umi_pmgr_observation[1] = static_cast<uint32_t>(result); umi_pmgr_checkpoint(); return; }
  const OSMetaClass *parent = lookup("ApplePMGR"), *nubMeta = lookup("ApplePMGRNub");
  if (!parent || parent != &ApplePMGR::gMetaClass || parent->getClassSize() != 0x4b8a8 ||
      !nubMeta || nubMeta->getClassSize() != 0x740) { umi_pmgr_checkpoint(); return; }
  umi_pmgr_observation[2] = parent->getClassSize();
  void *handle = OSMetaClass::preModLoad(g_kernel_kmod_info.name);
  if (!handle) { umi_pmgr_checkpoint(); return; }
  umi_pmgr_static_init();
  result = OSMetaClass::postModLoad(handle);
  if (result) { umi_pmgr_observation[1] = static_cast<uint32_t>(result); umi_pmgr_checkpoint(); return; }
  umi_pmgr_observation[9] = UmiPlatformPower::gMetaClass.getInstanceCount();
  umi_pmgr_observation[11] = nubMeta->getInstanceCount();
  UmiPlatformPower *provider = new UmiPlatformPower;
  IORegistryEntry *description = new IORegistryEntry;
  IOService *nub = nullptr;
  do {
    if (!provider || !description || !provider->init() || !description->init()) break;
    umi_pmgr_observation[0] = 2;
    umi_pmgr_observation[3] = provider->getMetaClass()->getClassSize();
    umi_pmgr_observation[4] = reinterpret_cast<uintptr_t>(provider);
    // Empty resource description: no Apple register map or device capabilities.
    description->setName("umi-platform-power");
    nub = umi_original_pmgr_nub_create(description, provider);
    umi_pmgr_observation[5] = reinterpret_cast<uintptr_t>(nub);
    if (!nub || nub->getMetaClass() != nubMeta || !provider->metaCast("ApplePMGR")) break;
    uintptr_t bound = 0;
    memcpy(&bound, reinterpret_cast<const char *>(nub) + 0x88, sizeof(bound));
    umi_pmgr_observation[6] = bound;
    if (bound != reinterpret_cast<uintptr_t>(provider)) break;
    umi_pmgr_observation[0] = 3;
    uint32_t value = umi_original_pmgr_nub_read(nub);
    umi_pmgr_observation[7] = value;
    umi_original_pmgr_nub_write(nub, uint64_t(value | 4));
    umi_pmgr_observation[8] = umi_original_pmgr_nub_read(nub);
    umi_pmgr_observation[13] = nub->getProvider() != nullptr || provider->getProvider() != nullptr;
    umi_pmgr_observation[14] = (nub->getState() | provider->getState()) & kIOServiceRegisteredState;
    if (value != 0xffffffff || umi_pmgr_observation[8] != 0xffffffff ||
        umi_pmgr_observation[13] || umi_pmgr_observation[14]) break;
    if (mode == 3) provider->disableCPUCore(1);
    if (mode == 2) {
      IOService *platform = IOService::getPlatform();
      if (!platform || !provider->attach(platform)) break;
      if (!provider->start(platform)) { provider->detach(platform); break; }
      if (!nub->attach(provider)) {
        provider->stop(platform); provider->detach(platform); break;
      }
      if (!nub->start(provider)) {
        nub->detach(provider); provider->stop(platform); provider->detach(platform); break;
      }
      provider->registerService(kIOServiceSynchronous);
      nub->registerService(kIOServiceSynchronous);
      umi_pmgr_observation[0] = 5;
      umi_pmgr_observation[13] = nub->getProvider() == provider && provider->getProvider() == platform;
      umi_pmgr_observation[14] = (nub->getState() & provider->getState()) & kIOServiceRegisteredState;
      auto matching = IOService::serviceMatching("ApplePMGRNub");
      IOService *matched = matching ? IOService::waitForMatchingService(matching, 1000000) : nullptr;
      OSSafeReleaseNULL(matching);
      // Check actual service discovery and genuine type identity, then retain
      // both live objects. The registry and original nub refer to this provider.
      if (matched != nub || matched->getMetaClass() != nubMeta ||
          !umi_pmgr_observation[13] || !umi_pmgr_observation[14]) {
        umi_pmgr_checkpoint();
        panic("UmiPlatformPower: original nub publication failed");
      }
      umi_pmgr_observation[10] = UmiPlatformPower::gMetaClass.getInstanceCount();
      umi_pmgr_observation[12] = nubMeta->getInstanceCount();
      umi_pmgr_observation[1] = kIOReturnSuccess;
      OSSafeReleaseNULL(matched);
      OSSafeReleaseNULL(description);
      umi_pmgr_checkpoint();
      return;
    }
    umi_pmgr_observation[1] = kIOReturnSuccess;
  } while (false);
  OSSafeReleaseNULL(nub);
  OSSafeReleaseNULL(description);
  OSSafeReleaseNULL(provider);
  umi_pmgr_observation[10] = UmiPlatformPower::gMetaClass.getInstanceCount();
  umi_pmgr_observation[12] = nubMeta->getInstanceCount();
  if (umi_pmgr_observation[9] != umi_pmgr_observation[10] ||
      umi_pmgr_observation[11] != umi_pmgr_observation[12]) umi_pmgr_observation[1] = static_cast<uint32_t>(kIOReturnError);
  umi_pmgr_observation[0] = 4;
  umi_pmgr_checkpoint();
}
