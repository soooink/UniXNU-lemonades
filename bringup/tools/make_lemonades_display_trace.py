#!/usr/bin/env python3
"""Generate the temporary DisplayDxe service-tracing Mu patch, host only."""
import difflib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DISPATCHER = "MdeModulePkg/Core/Dxe/Dispatcher/Dispatcher.c"

# Signatures match this pinned Mu tree. Wrappers forward each argument and the
# original EFI_STATUS unchanged. No firmware payloads or device data are patched.
SERVICES = [
    ("BS", "LocateProtocol", "EFI_GUID *Protocol, VOID *Registration, VOID **Interface",
     "Protocol, Registration, Interface", '"guid=%g", Protocol'),
    ("BS", "HandleProtocol", "EFI_HANDLE Handle, EFI_GUID *Protocol, VOID **Interface",
     "Handle, Protocol, Interface", '"guid=%g", Protocol'),
    ("BS", "LocateHandleBuffer",
     "EFI_LOCATE_SEARCH_TYPE SearchType, EFI_GUID *Protocol, VOID *SearchKey, UINTN *NumberHandles, EFI_HANDLE **Buffer",
     "SearchType, Protocol, SearchKey, NumberHandles, Buffer", '"type=%u guid=%g", SearchType, Protocol'),
    ("BS", "AllocatePool", "EFI_MEMORY_TYPE PoolType, UINTN Size, VOID **Buffer",
     "PoolType, Size, Buffer", '"bytes=0x%lx", (UINT64)Size'),
    ("BS", "FreePool", "VOID *Buffer", "Buffer", '"buffer=%p", Buffer'),
    ("BS", "Stall", "UINTN Microseconds", "Microseconds",
     '"us=%lu", (UINT64)Microseconds'),
    ("BS", "SignalEvent", "EFI_EVENT Event", "Event", '"event=%p", Event'),
    ("RT", "GetVariable",
     "CHAR16 *VariableName, EFI_GUID *VendorGuid, UINT32 *Attributes, UINTN *DataSize, VOID *Data",
     "VariableName, VendorGuid, Attributes, DataSize, Data", '"name=%s", VariableName'),
    ("RT", "SetVariable",
     "CHAR16 *VariableName, EFI_GUID *VendorGuid, UINT32 Attributes, UINTN DataSize, VOID *Data",
     "VariableName, VendorGuid, Attributes, DataSize, Data", '"name=%s bytes=0x%lx", VariableName, (UINT64)DataSize'),
    ("DS", "GetMemorySpaceDescriptor",
     "EFI_PHYSICAL_ADDRESS BaseAddress, EFI_GCD_MEMORY_SPACE_DESCRIPTOR *Descriptor",
     "BaseAddress, Descriptor", '"base=0x%lx", BaseAddress'),
    ("DS", "AddMemorySpace",
     "EFI_GCD_MEMORY_TYPE GcdMemoryType, EFI_PHYSICAL_ADDRESS BaseAddress, UINT64 Length, UINT64 Capabilities",
     "GcdMemoryType, BaseAddress, Length, Capabilities", '"base=0x%lx bytes=0x%lx", BaseAddress, Length'),
    ("DS", "SetMemorySpaceAttributes",
     "EFI_PHYSICAL_ADDRESS BaseAddress, UINT64 Length, UINT64 Attributes",
     "BaseAddress, Length, Attributes", '"base=0x%lx bytes=0x%lx attr=0x%lx", BaseAddress, Length, Attributes'),
]


def trace_source():
    code = """// lemonades diagnostics: temporary, single-core DisplayDxe entry only.
// DEBUG uses the allocation-free RAM console; wrappers must not log data values.
STATIC EFI_BOOT_SERVICES     mLemonadesOriginalBS;
STATIC EFI_RUNTIME_SERVICES  mLemonadesOriginalRT;
STATIC EFI_DXE_SERVICES      mLemonadesOriginalDS;
STATIC UINTN                mLemonadesTraceSequence;
STATIC UINTN                mLemonadesStallCount;
STATIC UINTN                mLemonadesDisplayImageBase;
STATIC UINTN                mLemonadesDsiPollCount;
STATIC BOOLEAN              mLemonadesTraceActive;
STATIC EFI_GUID mLemonadesDisplayGuid =
  { 0x4138022f, 0x06c7, 0x4f79, { 0x9c, 0x94, 0x7e, 0x33, 0xb5, 0x11, 0xa4, 0xe7 } };

// Read-only observations for the pinned, hash-verified lemonades DisplayDxe.
// RVA 0x467d0 is its MDSS virtual base returned by HWIO; do not assume identity
// mapping or touch the controller until its own DSI polling code is running.
// Controller 0 register offsets match the device kernel dsi_ctrl_reg.h.
STATIC VOID
LemonadesDsiSnapshot (CONST CHAR8 *Stage)
{
  STATIC CONST UINT16 Offsets[] = {
    0x000, 0x004, 0x008, 0x00C, 0x03C, 0x040, 0x048, 0x04C,
    0x068, 0x084, 0x0A8, 0x0AC, 0x0B4, 0x0C0,
    0x10C, 0x110, 0x118, 0x11C, 0x120, 0x15C, 0x1F4
  };
  UINTN Base, Index;
  if ((mLemonadesDisplayImageBase == 0) || (mLemonadesDsiPollCount == 0)) {
    return;
  }
  Base = *(volatile UINTN *)(mLemonadesDisplayImageBase + 0x467D0);
  DEBUG ((DEBUG_ERROR, "UMI DSI %a polls=%u MDSS=%p\\n",
          Stage, (UINT32)mLemonadesDsiPollCount, (VOID *)Base));
  if ((Base == 0) || ((Base & 0xFFF) != 0) || (Base > MAX_UINTN - 0x95000)) {
    return;
  }
  for (Index = 0; Index < ARRAY_SIZE (Offsets); Index++) {
    DEBUG ((DEBUG_ERROR, "UMI DSI0 reg=%03x value=%08x\\n", (UINT32)Offsets[Index],
            *(volatile UINT32 *)(Base + 0x94000 + Offsets[Index])));
  }
}

"""
    for table, name, signature, arguments, detail in SERVICES:
        code += f"""STATIC EFI_STATUS EFIAPI
LemonadesTrace{name} ({signature})
{{
  EFI_STATUS Status;
  UINTN Sequence;
  BOOLEAN Log;
"""
        if name == "Stall":
            code += """  UINTN Caller;
  UINT64 Before, After, Frequency;
  BOOLEAN PollSample;
  Caller = (UINTN)__builtin_return_address (0);
  PollSample = FALSE;
  Before = 0;
  if ((mLemonadesDisplayImageBase != 0) && (Caller == mLemonadesDisplayImageBase + 0x10960)) {
    ++mLemonadesDsiPollCount;
    PollSample = (mLemonadesDsiPollCount == 1) ||
                 ((mLemonadesDsiPollCount <= 996) && ((mLemonadesDsiPollCount % 166) == 0));
    if (PollSample) {
      LemonadesDsiSnapshot ("poll-before-stall");
      __asm__ volatile ("mrs %0, cntvct_el0" : "=r" (Before));
    }
  }
"""
        code += """\
  Sequence = ++mLemonadesTraceSequence;
"""
        code += ("  Log = (++mLemonadesStallCount <= 16) || (Microseconds >= 100000);\n"
                 if name == "Stall" else "  Log = TRUE;\n")
        fmt, args = detail.split('", ', 1)
        code += f"""  if (Log) {{
    DEBUG ((DEBUG_ERROR, "UMI svc %u {name} enter caller=%p {fmt[1:]}\\n",
            (UINT32)Sequence, __builtin_return_address (0), {args}));
  }}
  Status = mLemonadesOriginal{table}.{name} ({arguments});
"""
        if name == "Stall":
            code += """  if (PollSample) {
    __asm__ volatile ("mrs %0, cntvct_el0" : "=r" (After));
    __asm__ volatile ("mrs %0, cntfrq_el0" : "=r" (Frequency));
    DEBUG ((DEBUG_ERROR, "UMI DSI Stall requested=%lu counter-delta=%lu frequency=%lu status=%r\\n",
            (UINT64)Microseconds, After - Before, Frequency, Status));
  }
"""
        code += f"""\
  if (Log) {{
    DEBUG ((DEBUG_ERROR, "UMI svc %u {name} exit %r\\n", (UINT32)Sequence, Status));
  }}
  return Status;
}}

"""
    code += """STATIC VOID
LemonadesRefreshTableCrc (EFI_TABLE_HEADER *Header)
{
  Header->CRC32 = 0;
  mLemonadesOriginalBS.CalculateCrc32 (Header, Header->HeaderSize, &Header->CRC32);
}

STATIC VOID
LemonadesDisplayTraceStart (EFI_GUID *FileName, EFI_HANDLE ImageHandle)
{
  EFI_BOOT_SERVICES *BS;
  EFI_LOADED_IMAGE_PROTOCOL *Image;
  EFI_STATUS ImageStatus;
  if (!CompareGuid (FileName, &mLemonadesDisplayGuid) || mLemonadesTraceActive) {
    return;
  }
  BS = gDxeCoreST->BootServices;
  CopyMem (&mLemonadesOriginalBS, BS, sizeof (mLemonadesOriginalBS));
  CopyMem (&mLemonadesOriginalRT, gDxeCoreRT, sizeof (mLemonadesOriginalRT));
  CopyMem (&mLemonadesOriginalDS, gDxeCoreDS, sizeof (mLemonadesOriginalDS));
  mLemonadesTraceSequence = 0;
  mLemonadesStallCount = 0;
  mLemonadesDsiPollCount = 0;
  mLemonadesDisplayImageBase = 0;
  Image = NULL;
  ImageStatus = BS->HandleProtocol (ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&Image);
  if (!EFI_ERROR (ImageStatus) && (Image != NULL) && (Image->ImageSize >= 0x467D8)) {
    mLemonadesDisplayImageBase = (UINTN)Image->ImageBase;
  }
  mLemonadesTraceActive = TRUE;
"""
    tables = {"BS": "BS", "RT": "gDxeCoreRT", "DS": "gDxeCoreDS"}
    for table, name, *_ in SERVICES:
        code += f"  {tables[table]}->{name} = LemonadesTrace{name};\n"
    code += """  LemonadesRefreshTableCrc (&BS->Hdr);
  LemonadesRefreshTableCrc (&gDxeCoreRT->Hdr);
  LemonadesRefreshTableCrc (&gDxeCoreDS->Hdr);
}

STATIC VOID
LemonadesDisplayTraceStop (EFI_GUID *FileName)
{
  EFI_BOOT_SERVICES *BS;
  if (!CompareGuid (FileName, &mLemonadesDisplayGuid) || !mLemonadesTraceActive) {
    return;
  }
  BS = gDxeCoreST->BootServices;
  LemonadesDsiSnapshot ("display-entry-return");
"""
    for table, name, *_ in SERVICES:
        # Preserve a service that the driver legitimately replaced itself.
        code += f"""  if ({tables[table]}->{name} == LemonadesTrace{name}) {{
    {tables[table]}->{name} = mLemonadesOriginal{table}.{name};
  }}
"""
    code += """  LemonadesRefreshTableCrc (&BS->Hdr);
  LemonadesRefreshTableCrc (&gDxeCoreRT->Hdr);
  LemonadesRefreshTableCrc (&gDxeCoreDS->Hdr);
  mLemonadesTraceActive = FALSE;
}

"""
    return code


def main():
    original = (ROOT / "sources/uefi-lemonades/Mu_Basecore" / DISPATCHER).read_text()
    # This patch applies after the existing short DXE entry/exit trace.
    needle = "        Status = CoreStartImage (DriverEntry->ImageHandle, NULL, NULL);\n"
    if original.count(needle) != 1:
        raise ValueError("pinned Dispatcher no longer matches")
    base = original.replace(
        needle, '        DEBUG ((DEBUG_ERROR, "UMI DXE start %g\\n", &DriverEntry->FileName));\n'
        + needle
        + '        DEBUG ((DEBUG_ERROR, "UMI DXE done %g status %r\\n", &DriverEntry->FileName, Status));\n')
    modified = base.replace('#include "DxeMain.h"\n',
                            '#include "DxeMain.h"\n\n' + trace_source(), 1)
    modified = modified.replace(
        needle, "        LemonadesDisplayTraceStart (&DriverEntry->FileName, DriverEntry->ImageHandle);\n" + needle
        + "        LemonadesDisplayTraceStop (&DriverEntry->FileName);\n", 1)
    # Mu source is CRLF. Preserve it in patch context/additions for git apply.
    patch = "".join(difflib.unified_diff(base.replace("\n", "\r\n").splitlines(True),
                                       modified.replace("\n", "\r\n").splitlines(True),
                                       fromfile="a/" + DISPATCHER,
                                       tofile="b/" + DISPATCHER))
    path = ROOT / "devices/lemonades/overlay/Resources/MuPatches/Display-Services-Trace.patch"
    path.write_bytes(patch.encode())
    print(path)


if __name__ == "__main__":
    main()
