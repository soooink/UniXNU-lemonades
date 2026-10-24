// SPDX-License-Identifier: MIT
// Adapted from UniXNU-sheng, pinned a599a1a8a92093b5077543e071b72130769eb325.
// Lemonades original PMGR service integration; no SM8550 hardware resources.
// Board-side original PMGR ABI qualification. Default off. Modes: 1 releases
// unpublished objects, 2 publishes the original nub, 3 tests power refusal.
// No clocks, sleep, reset or secondary-CPU success is advertised.
#include "OriginalPMGRABI.h"
#include "arm64/lemonades_early_trace_config.h"
#include <IOKit/IOLib.h>
#include <IOKit/IOPlatformExpert.h>
#include <libkern/c++/OSSymbol.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>

extern "C" {
extern kmod_info_t g_kernel_kmod_info;
kern_return_t OSKextLoadKextWithIdentifier(const char *);
void lemonades_pmgr_static_init(void) __asm__("__GLOBAL__sub_I_LemonadesPlatformPower.cpp");
IOService *lemonades_original_pmgr_nub_create(IORegistryEntry *, ApplePMGR *);
uint32_t lemonades_original_pmgr_nub_read(IOService *);
void lemonades_original_pmgr_nub_write(IOService *, uint64_t);
// stage,status,parent-size,own-size,provider,nub,bound-provider,read-before,
// read-after,own-before,own-after,nub-before,nub-after,attached,registered,mode.
volatile uint64_t lemonades_pmgr_observation[16];
#if LEMONADES_EARLY_TRACE
void lemonades_early_trace(unsigned long, unsigned long, unsigned long);
extern unsigned long lemonades_trace_console_address;
#endif
__attribute__((noinline)) void lemonades_pmgr_checkpoint(void) {
#if LEMONADES_EARLY_TRACE
  for (unsigned i = 0; i < 16; ++i)
    lemonades_early_trace(0x70 + i, lemonades_pmgr_observation[i], lemonades_trace_console_address);
#endif
  __asm__ volatile("" ::: "memory");
}
// Called at the root-volume lookup boundary, after ordinary platform matching.
// Read existing driver counters; never manufacture readiness or interrupts.
#if LEMONADES_EARLY_TRACE
extern volatile uint32_t armcpu_registered, armcpu_gic_ready;
extern volatile uint64_t armcpu_timer_interrupts;
__attribute__((noinline)) void lemonades_runtime_checkpoint(void) {
  lemonades_early_trace(0xd0, 1, lemonades_trace_console_address);
  lemonades_early_trace(0xd1, armcpu_registered, lemonades_trace_console_address);
  lemonades_early_trace(0xd2, armcpu_gic_ready, lemonades_trace_console_address);
  lemonades_early_trace(0xd3, armcpu_timer_interrupts, lemonades_trace_console_address);
}
#endif
}

__attribute__((noreturn)) static void unavailable(unsigned slot)
{
  lemonades_pmgr_observation[0] = 0x100 + slot;
  lemonades_pmgr_observation[1] = static_cast<uint32_t>(kIOReturnUnsupported);
  lemonades_pmgr_checkpoint();
  panic("LemonadesPlatformPower: unimplemented operation %u", slot);
}

class LemonadesPlatformPower : public ApplePMGR {
  OSDeclareDefaultStructors(LemonadesPlatformPower)
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
OSDefineMetaClassWithInit(LemonadesPlatformPower, ApplePMGR, )
OSMetaClassConstructorInit(LemonadesPlatformPower, ApplePMGR, )
OSDefineBasicStructors(LemonadesPlatformPower, ApplePMGR)
// The original object's storage exceeds kalloc_type's 16 KiB size limit.
// Use XNU's existing zeroed, size-aware OSObject heap allocation pair.
void *LemonadesPlatformPower::operator new(size_t size) { return OSObject::operator new(size); }
void LemonadesPlatformPower::operator delete(void *memory, size_t size)
{
  OSObject::operator delete(memory, size);
}
static_assert(sizeof(LemonadesPlatformPower) == 0x4b8a8, "Exact original provider storage");

static const OSMetaClass *lookup(const char *text)
{
  const OSSymbol *name = OSSymbol::withCString(text);
  const OSMetaClass *meta = name ? OSMetaClass::getMetaClassWithName(name) : nullptr;
  OSSafeReleaseNULL(name);
  return meta;
}

extern "C" void lemonades_pmgr_run(void)
{
  unsigned mode = 0;
  if (!PE_parse_boot_argn("lemonades-pmgr", &mode, sizeof(mode)) || !mode) return;
  lemonades_pmgr_observation[15] = mode;
  lemonades_pmgr_observation[1] = static_cast<uint32_t>(kIOReturnError);
  if (mode > 3 || lemonades_pmgr_observation[0]) { lemonades_pmgr_checkpoint(); panic("LemonadesPlatformPower: invalid mode or duplicate initialization"); }
  lemonades_pmgr_observation[0] = 1;
  kern_return_t result = OSKextLoadKextWithIdentifier("com.apple.driver.ApplePMGR");
  if (result) { lemonades_pmgr_observation[1] = static_cast<uint32_t>(result); lemonades_pmgr_checkpoint(); return; }
  const OSMetaClass *parent = lookup("ApplePMGR"), *nubMeta = lookup("ApplePMGRNub");
  if (!parent || parent != &ApplePMGR::gMetaClass || parent->getClassSize() != 0x4b8a8 ||
      !nubMeta || nubMeta->getClassSize() != 0x740) { lemonades_pmgr_checkpoint(); return; }
  lemonades_pmgr_observation[2] = parent->getClassSize();
  void *handle = OSMetaClass::preModLoad(g_kernel_kmod_info.name);
  if (!handle) { lemonades_pmgr_checkpoint(); return; }
  lemonades_pmgr_static_init();
  result = OSMetaClass::postModLoad(handle);
  if (result) { lemonades_pmgr_observation[1] = static_cast<uint32_t>(result); lemonades_pmgr_checkpoint(); return; }
  lemonades_pmgr_observation[9] = LemonadesPlatformPower::gMetaClass.getInstanceCount();
  lemonades_pmgr_observation[11] = nubMeta->getInstanceCount();
  LemonadesPlatformPower *provider = new LemonadesPlatformPower;
  IORegistryEntry *description = new IORegistryEntry;
  IOService *nub = nullptr;
  do {
    if (!provider || !description || !provider->init() || !description->init()) break;
    lemonades_pmgr_observation[0] = 2;
    lemonades_pmgr_observation[3] = provider->getMetaClass()->getClassSize();
    lemonades_pmgr_observation[4] = reinterpret_cast<uintptr_t>(provider);
    // Empty resource description: no Apple register map or device capabilities.
    description->setName("lemonades-platform-power");
    nub = lemonades_original_pmgr_nub_create(description, provider);
    lemonades_pmgr_observation[5] = reinterpret_cast<uintptr_t>(nub);
    if (!nub || nub->getMetaClass() != nubMeta || !provider->metaCast("ApplePMGR")) break;
    uintptr_t bound = 0;
    memcpy(&bound, reinterpret_cast<const char *>(nub) + 0x88, sizeof(bound));
    lemonades_pmgr_observation[6] = bound;
    if (bound != reinterpret_cast<uintptr_t>(provider)) break;
    lemonades_pmgr_observation[0] = 3;
    uint32_t value = lemonades_original_pmgr_nub_read(nub);
    lemonades_pmgr_observation[7] = value;
    lemonades_original_pmgr_nub_write(nub, uint64_t(value | 4));
    lemonades_pmgr_observation[8] = lemonades_original_pmgr_nub_read(nub);
    lemonades_pmgr_observation[13] = nub->getProvider() != nullptr || provider->getProvider() != nullptr;
    lemonades_pmgr_observation[14] = (nub->getState() | provider->getState()) & kIOServiceRegisteredState;
    if (value != 0xffffffff || lemonades_pmgr_observation[8] != 0xffffffff ||
        lemonades_pmgr_observation[13] || lemonades_pmgr_observation[14]) break;
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
      lemonades_pmgr_observation[0] = 5;
      lemonades_pmgr_observation[13] = nub->getProvider() == provider && provider->getProvider() == platform;
      lemonades_pmgr_observation[14] = (nub->getState() & provider->getState()) & kIOServiceRegisteredState;
      auto matching = IOService::serviceMatching("ApplePMGRNub");
      IOService *matched = matching ? IOService::waitForMatchingService(matching, 1000000) : nullptr;
      OSSafeReleaseNULL(matching);
      // Check actual service discovery and genuine type identity, then retain
      // both live objects. The registry and original nub refer to this provider.
      if (matched != nub || matched->getMetaClass() != nubMeta ||
          !lemonades_pmgr_observation[13] || !lemonades_pmgr_observation[14]) {
        lemonades_pmgr_checkpoint();
        panic("LemonadesPlatformPower: original nub publication failed");
      }
      lemonades_pmgr_observation[10] = LemonadesPlatformPower::gMetaClass.getInstanceCount();
      lemonades_pmgr_observation[12] = nubMeta->getInstanceCount();
      lemonades_pmgr_observation[1] = kIOReturnSuccess;
      OSSafeReleaseNULL(matched);
      OSSafeReleaseNULL(description);
      lemonades_pmgr_checkpoint();
      return;
    }
    lemonades_pmgr_observation[1] = kIOReturnSuccess;
  } while (false);
  OSSafeReleaseNULL(nub);
  OSSafeReleaseNULL(description);
  OSSafeReleaseNULL(provider);
  lemonades_pmgr_observation[10] = LemonadesPlatformPower::gMetaClass.getInstanceCount();
  lemonades_pmgr_observation[12] = nubMeta->getInstanceCount();
  if (lemonades_pmgr_observation[9] != lemonades_pmgr_observation[10] ||
      lemonades_pmgr_observation[11] != lemonades_pmgr_observation[12]) lemonades_pmgr_observation[1] = static_cast<uint32_t>(kIOReturnError);
  lemonades_pmgr_observation[0] = 4;
  lemonades_pmgr_checkpoint();
}
