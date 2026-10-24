"""Constrain the phone-only UFS change to board identity and owned DMA bounds."""
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IDENTITY_OLD = '  IORegistryEntry *root=IORegistryEntry::fromPath("/",gIODTPlane);\n'
IDENTITY_NEW = ('  // Product model retains the physical board identity when the root model\n'
                '  // selects an iPad userspace compatibility profile.\n'
                '  IORegistryEntry *root=IORegistryEntry::fromPath("/product",gIODTPlane);\n')
RANGE_HELPER = '''static inline bool lemonadesDmaInOwnedMemory(uint64_t address, uint64_t bytes, uint64_t base, uint64_t size)
{
  return bytes && size && size <= UINT64_MAX-base && address >= base &&
         bytes <= size && address-base <= size-bytes;
}

'''
HOST_OLD = '''  // This is the actual UEFI-tested 512 MiB conventional region, not all DRAM.
  if (!gHost.virt || (gHost.phys&4095) || contiguous<kDmaBytes ||
      gHost.phys<0xc0000000ULL || gHost.phys>0xe0000000ULL-kDmaBytes) {
'''
HOST_NEW = '''  // Check the actual XNU-owned allocation. The SMMU planner below separately
  // enforces the hardware's input/output address widths on the real DMA PA.
  if (!gHost.virt || (gHost.phys&4095) || contiguous<kDmaBytes ||
      !lemonadesDmaInOwnedMemory(gHost.phys,kDmaBytes,gPhysBase,gPhysSize)) {
'''


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError("Unexpected UFS compatibility adaptation")
    return text.replace(before, after)


def audit(current, baseline):
    if current["profile"] != "phone" or current["upstream_sources"] != baseline["upstream_sources"]:
        raise ValueError("UFS adaptation must preserve the original storage implementation")
    if current["device_sources"].keys() != baseline["device_sources"].keys():
        raise ValueError("Unexpected UFS source inputs")
    substitutions = {
        "devices/lemonades/package/LemonadesUfsProbe.cpp": (IDENTITY_NEW, IDENTITY_OLD),
        "devices/lemonades/package/LemonadesNativeUfsHost.inc": (HOST_NEW, HOST_OLD),
        "devices/lemonades/package/LemonadesSmmuTakeover.h": (RANGE_HELPER, ""),
        "tools/build_lemonades_native_ufs.py": ('    header+=\'extern "C" unsigned long gPhysBase, gPhysSize;\\n\'\n', ""),
    }
    for name, expected in baseline["device_sources"].items():
        text = (ROOT / name).read_text()
        if name in substitutions:
            text = replace_once(text, *substitutions[name])
        if hashlib.sha256(text.encode()).hexdigest() != expected:
            raise ValueError("Changes beyond bounded UFS compatibility: " + name)
    generated = (ROOT / "out/lemonades-xnu/lemonades/tree/build/native-ufs/NativeUfs.cpp").read_text()
    generated = replace_once(generated, 'extern "C" unsigned long gPhysBase, gPhysSize;\n', "")
    generated = replace_once(generated, IDENTITY_NEW, IDENTITY_OLD)
    if hashlib.sha256(generated.encode()).hexdigest() != baseline["generated_source_sha256"]:
        raise ValueError("Generated UFS code changed beyond the explicit adaptation")
