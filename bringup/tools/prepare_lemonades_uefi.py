#!/usr/bin/env python3
"""Stage reviewed lemonades overlays and a private menu package; no device operations."""
import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stage_display_profile(uefi, profile):
    """Select a diagnostic profile in the generated checkout, not the overlay."""
    if profile == "vendor":
        return
    if profile != "inherited":
        raise ValueError(f"unknown display profile: {profile}")
    include = uefi / "Platforms/OnePlus/lemonadesPkg/Include"
    driver = "lemonadesPkg/Drivers/InheritedFbDxe/InheritedFbDxe.inf"
    # Omit the entire vendor initialization chain: clock/PMIC drivers can also
    # change inherited display state even when DisplayDxe itself is absent.
    for name in ("DXE.inc", "APRIORI.inc"):
        path = include / name
        lines = [line for line in path.read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith("#")
                 and "Binaries/lemonades/" not in line]
        if name == "APRIORI.inc":
            anchor = "  INF MdeModulePkg/Universal/Console/GraphicsConsoleDxe/GraphicsConsoleDxe.inf"
            if lines.count(anchor) != 1:
                raise ValueError("unexpected inherited GOP ordering anchor")
            lines.insert(lines.index(anchor), f"  INF {driver}")
        else:
            lines.append(f"  INF {driver}")
        path.write_text("# Inherited display experiment: source drivers only.\n"
                        + "\n".join(lines) + "\n")
    (include / "RAW.inc").write_text("# No vendor resources in inherited display profile.\n")
    dsc = include.parent / "lemonades.dsc"
    dsc.write_text(dsc.read_text() + f"\n[Components]\n  {driver}\n")
    path = include / "APRIORI-order.json"
    order = json.loads(path.read_text())
    removed = [e for e in order["selected_stock_slots"] if e["inf"].startswith("Binaries/lemonades/")]
    order["selected_stock_slots"] = [e for e in order["selected_stock_slots"] if e not in removed]
    order["selected_vendor_entries"] = 0
    order["display_profile"] = profile
    order["profile_omitted_vendor_entries"] = removed
    order["profile_source_addition"] = driver
    order["limitations"] = [
        "Source-only diagnostic profile; no vendor display, clock or PMIC initialization.",
        "The framebuffer layout was observed after vendor GOP initialization in attempts 06-08.",
        "ABL active scanout, panel refresh and visibility with this layout are unverified.",
    ]
    path.write_text(json.dumps(order, indent=2) + "\n")


def stage_input_profile(uefi, profile):
    if profile == "none":
        return
    if profile not in ("buttons", "touch"):
        raise ValueError(f"unknown input profile: {profile}")
    board = uefi / "Platforms/OnePlus/lemonadesPkg"
    drivers = ["lemonadesPkg/Drivers/LemonadesButtonsDxe/LemonadesButtonsDxe.inf"]
    if profile == "touch":
        drivers.append("lemonadesPkg/Drivers/LemonadesTouchDxe/LemonadesTouchDxe.inf")
    for driver in drivers:
        if not (board / driver.removeprefix("lemonadesPkg/")).is_file():
            raise ValueError(f"input driver not staged: {driver}")
    dxe = board / "Include/DXE.inc"
    dxe.write_text(dxe.read_text() + "".join(f"  INF {p}\n" for p in drivers))
    apriori = board / "Include/APRIORI.inc"
    text = apriori.read_text()
    anchor = "  INF MdeModulePkg/Universal/Console/ConPlatformDxe/ConPlatformDxe.inf"
    if text.count(anchor) != 1:
        raise ValueError("unexpected input dispatch anchor")
    text = text.replace(anchor, "".join(f"  INF {p}\n" for p in drivers) + anchor, 1)
    apriori.write_text(text)
    dsc = board / "lemonades.dsc"
    reset = "lemonadesPkg/Library/LemonadesResetSystemLib/LemonadesResetSystemLib.inf"
    if not (board / reset.removeprefix("lemonadesPkg/")).is_file():
        raise ValueError("input profile reset diagnostics not staged")
    dsc.write_text(dsc.read_text() + "\n[LibraryClasses]\n"
                   f"  ResetSystemLib|{reset}\n  HwResetSystemLib|{reset}\n"
                   "  LemonadesSpmiLib|lemonadesPkg/Library/LemonadesSpmiLib/LemonadesSpmiLib.inf\n"
                   "  LemonadesRpmhLib|lemonadesPkg/Library/LemonadesRpmhLib/LemonadesRpmhLib.inf\n"
                   "\n[Components]\n" + "".join(f"  {p}\n" for p in drivers))
    order_path = board / "Include/APRIORI-order.json"
    order = json.loads(order_path.read_text())
    order.update(input_profile=profile, input_source_additions=drivers,
                 input_reset_library=reset)
    order_path.write_text(json.dumps(order, indent=2) + "\n")


def stage_payload_profile(uefi, profile):
    if profile == "none":
        return
    if profile != "ram":
        raise ValueError(f"unknown payload profile: {profile}")
    board = uefi / "Platforms/OnePlus/lemonadesPkg"
    drivers = [
        "MdeModulePkg/Universal/Disk/UnicodeCollation/EnglishDxe/EnglishDxe.inf",
        "MdeModulePkg/Universal/Disk/DiskIoDxe/DiskIoDxe.inf",
        "FatPkg/EnhancedFatDxe/Fat.inf",
        "lemonadesPkg/Drivers/LemonadesRamPayloadDxe/LemonadesRamPayloadDxe.inf",
    ]
    dxe = board / "Include/DXE.inc"
    dxe.write_text(dxe.read_text() + "".join(f"  INF {p}\n" for p in drivers))
    apriori = board / "Include/APRIORI.inc"
    text = apriori.read_text()
    anchor = "  INF MdeModulePkg/Universal/BdsDxe/BdsDxe.inf"
    if text.count(anchor) != 1:
        raise ValueError("unexpected RAM payload dispatch anchor")
    apriori.write_text(text.replace(anchor, "".join(f"  INF {p}\n" for p in drivers) + anchor, 1))
    dsc = board / "lemonades.dsc"
    # The check application is built for the FAT volume, never placed in FDF.
    dsc.write_text(dsc.read_text() + "\n[Components]\n" +
                   "".join(f"  {p}\n" for p in drivers) +
                   "  lemonadesPkg/Application/LemonadesPayloadCheck/LemonadesPayloadCheck.inf\n"
                   "  lemonadesPkg/Application/LemonadesPayload64Check/LemonadesPayload64Check.inf\n"
                   "  lemonadesPkg/Application/LemonadesMemoryDiag/LemonadesMemoryDiag.inf\n")
    order_path = board / "Include/APRIORI-order.json"
    order = json.loads(order_path.read_text())
    order.update(payload_profile=profile, payload_source_additions=drivers)
    order_path.write_text(json.dumps(order, indent=2) + "\n")


def stage_darwinboot(uefi, package):
    """Stage the pinned loader with ramoops checkpoints in the private package."""
    source = ROOT / "sources/UniXNU/drivers/DarwinBoot/DarwinBootPkg"
    target = package / "DarwinBootPkg"
    shutil.copytree(source, target)
    # Data uses the current upstream sparse/persistent format. Its logical size
    # may exceed RAM; KeepPacked still charges only the encoded seed to the
    # boot window. Keep the pinned source checkout unchanged.
    packed = ROOT / "devices/lemonades/package/darwinboot/PackedRamdisk.h"
    if sha(packed) != "8b3a326062baee88a179274e92df05a3a07792d25ef84daa23b71aa47b4a2326":
        raise ValueError("current upstream packed ramdisk header hash mismatch")
    shutil.copy2(packed, target / "Driver/PackedRamdisk.h")
    driver = target / "Driver/DarwinBoot.c"
    text = driver.read_text()
    changes = [
        ('    Print (L"DARWINBOOT: unsupported inputs or exception level; firmware retained\\n");',
         '    DEBUG ((DEBUG_ERROR, "UMI DARWINBOOT: unsupported request, EL%lu\\n", DarwinCurrentEl () >> 2));\n'),
        ('  Status = ReadFile (Root, Request->KernelPath, SIZE_128MB, &Image, &ImageSize);',
         '  DEBUG ((DEBUG_ERROR, "UMI DARWINBOOT: reading %s\\n", Request->KernelPath));\n'),
        ('  Status = ParseKernel (Image, ImageSize, &Kernel);',
         '  DEBUG ((DEBUG_ERROR, "UMI DARWINBOOT: kernel read %lu bytes; parsing\\n", (UINT64)ImageSize));\n'),
        ('  Status = ReadFile (Root, TreePath, SIZE_16MB, &Tree, &TreeSize);',
         '  DEBUG ((DEBUG_ERROR, "UMI DARWINBOOT: kernel parsed; reading ADT\\n"));\n'),
        ('  Offset = 0;\n  RamdiskOffset = MAX_UINTN;',
         '  DEBUG ((DEBUG_ERROR, "UMI DARWINBOOT: ADT read %lu bytes\\n", (UINT64)TreeSize));\n'),
        ('  Status = ReadBootVideo (Video);',
         '  DEBUG ((DEBUG_ERROR, "UMI DARWINBOOT: ADT and optional inputs validated\\n"));\n'),
        ('  Status = AllocateWindow (&Kernel, WindowSize, &Address);',
         '  DEBUG ((DEBUG_ERROR, "UMI DARWINBOOT: allocating window 0x%lx\\n", WindowSize));\n'),
        ('  ArgsAddress = ALIGN_VALUE (Address + Kernel.End - Kernel.Base, SIZE_16KB);',
         '  DEBUG ((DEBUG_ERROR, "UMI DARWINBOOT: allocated window at 0x%lx\\n", Address));\n'),
        ('  Print (L"DARWINBOOT: boot refused: %r; firmware retained\\n", Status);',
         '  DEBUG ((DEBUG_ERROR, "UMI DARWINBOOT: boot refused %r; firmware retained\\n", Status));\n'),
        ('    Loaded->Unload = Unload;',
         '    DEBUG ((DEBUG_ERROR, "UMI DARWINBOOT: loader v2 installed EL%lu\\n", DarwinCurrentEl () >> 2));\n'),
        ('    if (!EFI_ERROR (Status)) {\n      DarwinEnter',
         '    DEBUG ((DEBUG_ERROR, "UMI DARWINBOOT: ExitBootServices attempt %lu status %r\\n", (UINT64)Attempt, Status));\n'),
    ]
    for anchor, checkpoint in changes:
        if text.count(anchor) != 1:
            raise ValueError(f"unexpected DarwinBoot checkpoint anchor: {anchor}")
        text = text.replace(anchor, checkpoint + anchor, 1)
    anchor = "    return EFI_BAD_BUFFER_SIZE;\n  }\n  ZeroMem (CommandLine"
    if text.count(anchor) != 1:
        raise ValueError("unexpected DarwinBoot ramdisk rejection anchor")
    text = text.replace(anchor,
        '    DEBUG ((DEBUG_ERROR, "UMI DARWINBOOT: ramdisk layout rejected encoded=%lu max-logical=0x%lx\\n", (UINT64)Request->RamdiskSize, (UINT64)SIZE_MAX_LOGICAL));\n'
        + anchor, 1)
    anchor = "  TrustCacheAddress = RamdiskAddress + RamdiskBytes;"
    if text.count(anchor) != 1:
        raise ValueError("unexpected DarwinBoot ramdisk allocation anchor")
    text = text.replace(anchor,
        '  DEBUG ((DEBUG_ERROR, "UMI DARWINBOOT: ramdisk encoded=%lu logical=%lu packed=%u keep=%u reserved=%lu\\n", (UINT64)Request->RamdiskSize, (UINT64)RamdiskExpandedSize, (UINT32)RamdiskPacked, (UINT32)KeepPacked, (UINT64)RamdiskBytes));\n'
        + anchor, 1)
    # Entry.S draws this bar before branching to XNU, not inside XNU.
    text = text.replace("means the kernel entry code ran.", "means the loader trampoline ran, not proof of XNU entry.")
    # APRIORI runs before BDS connects ConOut. Print() asserts on NULL ConOut;
    # the allocation-free ramoops DEBUG checkpoint above is available already.
    early_print = '    Print (L"DARWINBOOT: loader v2 installed EL%u\\n", (UINT32)(DarwinCurrentEl () >> 2));'
    if text.count(early_print) != 1:
        raise ValueError("unexpected DarwinBoot pre-console Print anchor")
    text = text.replace(early_print, "    // Registration is logged to ramoops before ConOut exists.")
    driver.write_text(text)
    inf = "DarwinBootPkg/Driver/DarwinBoot.inf"
    board = uefi / "Platforms/OnePlus/lemonadesPkg"
    dsc = board / "lemonades.dsc"
    dsc.write_text(dsc.read_text() + f"\n[Components]\n  {inf}\n")
    dxe = board / "Include/DXE.inc"
    dxe.write_text(dxe.read_text() + f"  INF {inf}\n")
    apriori = board / "Include/APRIORI.inc"
    anchor = "  INF MdeModulePkg/Universal/BdsDxe/BdsDxe.inf"
    text = apriori.read_text()
    if text.count(anchor) != 1:
        raise ValueError("unexpected DarwinBoot dispatch anchor")
    apriori.write_text(text.replace(anchor, f"  INF {inf}\n" + anchor))
    return {str(p.relative_to(package)): sha(p) for p in sorted(target.rglob("*")) if p.is_file()}


def prepare(binaries, display_profile="vendor", input_profile="none", payload_profile="none",
            loader_profile="none"):
    if display_profile not in ("vendor", "inherited"):
        raise ValueError(f"unknown display profile: {display_profile}")
    if input_profile not in ("none", "buttons", "touch"):
        raise ValueError(f"unknown input profile: {input_profile}")
    if input_profile != "none" and display_profile != "inherited":
        raise ValueError("input bring-up requires the verified inherited display profile")
    if payload_profile not in ("none", "ram"):
        raise ValueError(f"unknown payload profile: {payload_profile}")
    if payload_profile == "ram" and (display_profile != "inherited" or input_profile != "buttons"):
        raise ValueError("RAM payload validation uses inherited display and buttons")
    if loader_profile not in ("none", "darwinboot"):
        raise ValueError("unknown loader profile")
    if loader_profile == "darwinboot" and payload_profile != "ram":
        raise ValueError("DarwinBoot bring-up requires the qualified RAM payload profile")
    board = ROOT / "devices/lemonades"
    uefi = ROOT / "sources/uefi-lemonades"
    unixnu = ROOT / "sources/UniXNU"
    lock = json.loads((board / "source-lock.json").read_text())
    for path, expected in ((unixnu, lock["UniXNU"]), (uefi, lock["uefi-lemonades"]),
                           (uefi / "Mu_Basecore", lock["Mu_Basecore"])):
        actual = subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
        if actual != expected:
            raise ValueError(f"source pin mismatch: {path}: {actual}")
    binaries = binaries.resolve(strict=True)
    manifest = json.loads((binaries / "manifest.json").read_text())
    # The importer manifest is also retained alongside the build provenance.
    if manifest.get("device") != "lemonades" or not manifest.get("extraction", {}).get("complete_dump_compared_against_fresh_extraction"):
        raise ValueError("unverified or wrong-device binary import manifest")
    for module in manifest["modules"]:
        if sha(binaries / module["efi"]) != module["pe_sha256"]:
            raise ValueError(f"imported executable changed: {module['efi']}")
        if module["depex"] and sha(binaries / module["depex"]["file"]) != module["depex"]["sha256"]:
            raise ValueError(f"imported dependencies changed: {module['efi']}")
    for resource in manifest["raw_files"]:
        if sha(binaries / resource["file"]) != resource["sha256"]:
            raise ValueError(f"imported resource changed: {resource['file']}")
    binary_link = uefi / "Binaries/lemonades"
    binary_link.parent.mkdir(exist_ok=True)
    if binary_link.is_symlink():
        if binary_link.resolve() != binaries:
            raise ValueError("Binaries/lemonades already points at a different extraction")
    elif binary_link.exists():
        raise ValueError("refusing to replace existing Binaries/lemonades")
    else:
        binary_link.symlink_to(binaries, target_is_directory=True)

    copied = {}
    for path in sorted((board / "overlay").rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(board / "overlay")
        target = uefi / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        copied[str(relative)] = sha(target)

    stage_display_profile(uefi, display_profile)
    stage_input_profile(uefi, input_profile)
    stage_payload_profile(uefi, payload_profile)
    copied = {relative: sha(uefi / relative) for relative in copied}

    # Patch the dedicated generated lemonades checkout; sources/uefi-sheng stays intact.
    sec = uefi / "Silicon/Silicium/SiliciumPkg/Sec/Sec.c"
    text = sec.read_text()
    old = "  // Clear Frame Buffer\n  ClearFrameBuffer ();"
    new = "  // lemonades has no qualified framebuffer until real GOP is installed.\n#ifndef LEMONADES_SKIP_EARLY_FRAMEBUFFER\n  ClearFrameBuffer ();\n#endif"
    if old in text:
        sec.write_text(text.replace(old, new, 1))
    elif new not in text:
        raise ValueError("unexpected Sec.c: cannot gate early framebuffer clear")
    text = sec.read_text()
    start = "#ifndef MDEPKG_NDEBUG\nSTATIC\nVOID\nClearFrameBuffer"
    finish = "\nSTATIC\nVOID\nPrintFirmwareVersion"
    if start in text:
        text = text.replace(start, "#ifndef MDEPKG_NDEBUG\n#ifndef LEMONADES_SKIP_EARLY_FRAMEBUFFER\nSTATIC\nVOID\nClearFrameBuffer", 1)
        text = text.replace(finish, "\n#endif // LEMONADES_SKIP_EARLY_FRAMEBUFFER\n" + finish, 1)
        sec.write_text(text)
    text = sec.read_text()
    checkpoints = [
        ("  // Do Platform Specific Initialization\n  PlatformInitialize ();",
         '  SerialPortInitialize ();\n  DEBUG ((EFI_D_ERROR, "UMI: SEC start\\n"));\n  // Do Platform Specific Initialization\n  PlatformInitialize ();\n  DEBUG ((EFI_D_ERROR, "UMI: platform initialized\\n"));'),
        ("  // Initialize Memory\n  Status = InitializeMemory ();",
         '  DEBUG ((EFI_D_ERROR, "UMI: memory init start\\n"));\n  // Initialize Memory\n  Status = InitializeMemory ();\n  DEBUG ((EFI_D_ERROR, "UMI: memory init returned %r\\n", Status));'),
        ("  // Initialize Platform HOBs\n  Status = PlatformPeim ();",
         '  DEBUG ((EFI_D_ERROR, "UMI: platform PEI start\\n"));\n  // Initialize Platform HOBs\n  Status = PlatformPeim ();\n  DEBUG ((EFI_D_ERROR, "UMI: platform PEI returned %r\\n", Status));'),
        ("  // Decompress all FVs\n  Status = DecompressFirstFv ();",
         '  DEBUG ((EFI_D_ERROR, "UMI: FV decompress start\\n"));\n  // Decompress all FVs\n  Status = DecompressFirstFv ();\n  DEBUG ((EFI_D_ERROR, "UMI: FV decompress returned %r\\n", Status));'),
        ("  // Load DXE Core\n  Status = LoadDxeCoreFromFv (NULL, 0);",
         '  DEBUG ((EFI_D_ERROR, "UMI: DXE core load start\\n"));\n  // Load DXE Core\n  Status = LoadDxeCoreFromFv (NULL, 0);'),
    ]
    for old, new in checkpoints:
        checkpoint_text = text.replace('  LemonadesSmmuSnapshot ("before-platform");\n', '')
        checkpoint_text = checkpoint_text.replace('  LemonadesSmmuSnapshot ("after-platform");\n', '')
        if new not in checkpoint_text:
            if text.count(old) != 1:
                raise ValueError("unexpected SEC checkpoint anchor")
            text = text.replace(old, new, 1)
    if '#include "LemonadesSmmuTrace.h"' not in text:
        text = '#include "LemonadesSmmuTrace.h"\n' + text
        text = text.replace(
            "  PlatformInitialize ();",
            '  LemonadesSmmuSnapshot ("before-platform");\n  PlatformInitialize ();\n'
            '  LemonadesSmmuSnapshot ("after-platform");', 1)
    sec.write_text(text)

    package = ROOT / "out/lemonades-menu-package"
    # This generated copy contains no vendor binaries and is safe to regenerate.
    if package.exists():
        shutil.rmtree(package)
    shutil.copytree(unixnu / "package", package)
    loader_hashes = stage_darwinboot(uefi, package) if loader_profile == "darwinboot" else {}
    copied = {relative: sha(uefi / relative) for relative in copied}
    boot = package / "UniXNUPkg/Library/UniXNULib/Boot.c"
    if input_profile != "none":
        shutil.copy2(board / "menu/Menu.c", package / "UniXNUPkg/Library/UniXNULib/Menu.c")
        library_inf = package / "UniXNUPkg/Library/UniXNULib/UniXNULib.inf"
        library_inf.write_text(library_inf.read_text() +
                               "\n[Protocols]\n  gEfiAbsolutePointerProtocolGuid ## SOMETIMES_CONSUMES\n")
        # Keep ramoops through the menu's diagnostic restart. This changes
        # only the private package; the library still implements cold reset.
        text = boot.read_text()
        old = "gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0, NULL);"
        if text.count(old) != 1:
            raise ValueError("unexpected UniXNU menu restart call")
        boot.write_text(text.replace(old, old.replace("EfiResetCold", "EfiResetWarm")))
    config = package / "UniXNUPkg/Library/UniXNULib/Config.c"
    text = config.read_text()
    old = '  "timeout = 10\\n"'
    new = '  "timeout = 3600\\n"\n  "fallback_timeout = 3600\\n"'
    if input_profile != "none":
        new = '  "timeout = -1\\n"\n  "fallback_timeout = 3600\\n"'
    if text.count(old) != 1:
        raise ValueError("unexpected UniXNU builtin menu timeout")
    text = text.replace(old, new).replace('title = \\"UniXNU\\"', 'title = \\"Mi 10 lemonades - UEFI bring-up\\"')
    if input_profile != "none":
        text = text.replace('  "rotate = 2\\n"', '  "rotate = 0\\n"')
    config.write_text(text)
    ui = package / "UniXNUPkg/Library/UniXNULib/Ui.c"
    text = ui.read_text()
    anchor = '    UniXNULog ("ui: graphics %ux%u, scale %u", Ui->Width, Ui->Height, (UINT32)Ui->Scale);'
    if text.count(anchor) != 1:
        raise ValueError("unexpected UniXNU GOP logging anchor")
    text = text.replace(anchor, anchor + '''
    UniXNULog ("lemonades GOP: base 0x%lx bytes 0x%lx pitch %u format %u mode %u",
               Ui->Gop->Mode->FrameBufferBase, (UINT64)Ui->Gop->Mode->FrameBufferSize,
               Ui->Gop->Mode->Info->PixelsPerScanLine,
               (UINT32)Ui->Gop->Mode->Info->PixelFormat, Ui->Gop->Mode->Mode);''')
    # Preserve each existing Blt call and return value; log bounded successes
    # and failures to distinguish menu control flow from successful GOP drawing.
    text = text.replace('#include "Internal.h"', '#include "Internal.h"\n' + '''
STATIC UINTN mLemonadesBltCalls;
STATIC UINTN mLemonadesBltErrors;

STATIC EFI_STATUS
LemonadesBltTrace (
  EFI_GRAPHICS_OUTPUT_PROTOCOL *Gop,
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL *Buffer,
  EFI_GRAPHICS_OUTPUT_BLT_OPERATION Operation,
  UINTN SourceX, UINTN SourceY, UINTN DestinationX, UINTN DestinationY,
  UINTN Width, UINTN Height, UINTN Delta)
{
  EFI_STATUS Status;
  Status = Gop->Blt (Gop, Buffer, Operation, SourceX, SourceY, DestinationX,
                     DestinationY, Width, Height, Delta);
  ++mLemonadesBltCalls;
  if (EFI_ERROR (Status)) {
    ++mLemonadesBltErrors;
  }
  if ((mLemonadesBltCalls <= 8) || (EFI_ERROR (Status) && (mLemonadesBltErrors <= 8))) {
    UniXNULog ("lemonades Blt: call %u op %u rect %u,%u %ux%u status %r errors %u",
               (UINT32)mLemonadesBltCalls, (UINT32)Operation,
               (UINT32)DestinationX, (UINT32)DestinationY,
               (UINT32)Width, (UINT32)Height, Status, (UINT32)mLemonadesBltErrors);
  }
  return Status;
}
''', 1)
    if text.count("Ui->Gop->Blt (Ui->Gop,") != 3:
        raise ValueError("unexpected UniXNU Blt call sites")
    text = text.replace("Ui->Gop->Blt (Ui->Gop,", "LemonadesBltTrace (Ui->Gop,")
    ui.write_text(text)
    # The same bounded, read-only register snapshot before and after display.
    trace = board / "overlay/Silicon/Silicium/SiliciumPkg/Sec/LemonadesSmmuTrace.h"
    shutil.copy2(trace, package / "UniXNUPkg/Library/UniXNULib/LemonadesSmmuTrace.h")
    menu = package / "UniXNUPkg/Library/UniXNULib/Menu.c"
    text = menu.read_text().replace('#include "Internal.h"', '#include "Internal.h"\n#include "LemonadesSmmuTrace.h"', 1)
    anchor = '  UniXNULog (\n    "menu: shown'
    if text.count(anchor) != 1:
        raise ValueError("unexpected UniXNU menu checkpoint anchor")
    text = text.replace(anchor, '  LemonadesSmmuSnapshot ("after-menu-draw");\n' + anchor, 1)
    menu.write_text(text)
    record = {
        "display_profile": display_profile,
        "input_profile": input_profile,
        "payload_profile": payload_profile,
        "loader_profile": loader_profile,
        "loader_sha256": loader_hashes,
        "source_pins": lock, "overlay_sha256": copied,
        "sec_sha256": sha(sec), "menu_config_sha256": sha(config),
        "menu_ui_sha256": sha(ui),
        "menu_loop_sha256": sha(menu),
        "menu_boot_sha256": sha(boot),
        "menu_library_inf_sha256": sha(package / "UniXNUPkg/Library/UniXNULib/UniXNULib.inf"),
        "import_manifest": str(binaries / "manifest.json"),
        "import_manifest_sha256": sha(binaries / "manifest.json"),
        "hardware_tested": False,
    }
    destination = ROOT / "out/lemonades/prepare.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(record, indent=2) + "\n")
    print(destination)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", required=True, type=Path)
    parser.add_argument("--display-profile", choices=("vendor", "inherited"), default="vendor")
    parser.add_argument("--input-profile", choices=("none", "buttons", "touch"), default="none")
    parser.add_argument("--payload-profile", choices=("none", "ram"), default="none")
    parser.add_argument("--loader-profile", choices=("none", "darwinboot"), default="none")
    args = parser.parse_args()
    prepare(args.binaries, args.display_profile, args.input_profile, args.payload_profile, args.loader_profile)
