/** @file
  lemonades menu input: firmware keys and absolute pointer, without upstream edits.

  Degradation rules (see README):
  - No input device: the timeout always runs (fallback_timeout replaces a
    negative timeout) and the highlight rotates through the entries.
  - Any key press stops both the countdown and the rotation.
  - The countdown always boots the default entry; rotation is display only.

  Copyright (c) 2026, UniXNU contributors. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "Internal.h"
#include <Protocol/AbsolutePointer.h>

#define TICK_MS             100
#define DEFAULT_ROTATE_SEC  2
#define LEMONADES_MAX_POINTERS    4
#define LEMONADES_INPUT_LOG_LIMIT 64
#define LEMONADES_POINTER_BURST   8
#define LEMONADES_NO_ENTRY        MAX_UINTN

#ifndef SCAN_SUSPEND
#define SCAN_SUSPEND  0x0102
#endif

// BEGIN LEMONADES_MENU_INPUT_LOGIC
// These helpers use protocol/UI data only. The host regression compiles this
// exact block; no boot services or device access is needed to exercise it.
typedef struct {
  BOOLEAN  Down;
  BOOLEAN  Eligible;
  UINTN    PressRow;
  UINTN    PressX;
  UINTN    PressY;
  UINT64   PressTick;
} LEMONADES_TOUCH_GESTURE;

STATIC
BOOLEAN
LemonadesScaleAxis (
  IN UINT64   Raw,
  IN UINT64   Minimum,
  IN UINT64   Maximum,
  IN UINT32   Pixels,
  OUT UINTN   *Pixel
  )
{
  UINT64  Position;
  UINT64  Range;
  UINT64  Remainder;
  UINTN   Result;
  UINT32  Scale;
  UINTN   Bit;

  if ((Pixels == 0) || (Maximum <= Minimum) || (Raw < Minimum) || (Raw > Maximum)) {
    return FALSE;
  }

  Position = Raw - Minimum;
  Range    = Maximum - Minimum;
  Scale    = Pixels - 1;
  if (Position == Range) {
    *Pixel = Scale;
    return TRUE;
  }

  // floor(Position * Scale / Range), without overflowing even a UINT64
  // protocol range. Binary multiply/divide tracks a bounded remainder;
  // subtract-before-add avoids a 128-bit runtime division dependency.
  Remainder = 0;
  Result    = 0;
  for (Bit = 0; Bit < 32; Bit++) {
    Result *= 2;
    if (Remainder >= Range - Remainder) {
      Remainder -= Range - Remainder;
      Result++;
    } else {
      Remainder += Remainder;
    }

    if (((Scale >> (31 - Bit)) & 1U) != 0) {
      if (Remainder >= Range - Position) {
        Remainder -= Range - Position;
        Result++;
      } else {
        Remainder += Position;
      }
    }
  }

  *Pixel = Result;
  return TRUE;
}

STATIC
UINTN
LemonadesHitEntry (
  IN CONST UNIXNU_UI  *Ui,
  IN UINTN           Count,
  IN UINTN           X,
  IN UINTN           Y
  )
{
  UINTN  Row;
  UINTN  OffsetY;
  UINTN  RowTop;
  UINTN  RowPixels;

  // Ui.c draws exactly [MenuLeft, MenuLeft + MenuWidth) horizontally,
  // RowHeight - Scale pixels per row, leaving a Scale-pixel gap. Use
  // subtraction bounds so malformed layout values cannot wrap additions.
  if ((Ui->Mode != UniXNUUiGraphics) || (Ui->RowHeight <= Ui->Scale) ||
      (X >= Ui->Width) || (Y >= Ui->Height) ||
      (X < Ui->MenuLeft) || (X - Ui->MenuLeft >= Ui->MenuWidth) ||
      (Y < Ui->MenuTop))
  {
    return LEMONADES_NO_ENTRY;
  }

  OffsetY = Y - Ui->MenuTop;
  Row     = OffsetY / Ui->RowHeight;
  if ((Row >= Count) || (Row >= Ui->VisibleRows) ||
      (OffsetY % Ui->RowHeight >= Ui->RowHeight - Ui->Scale))
  {
    return LEMONADES_NO_ENTRY;
  }

  RowTop    = Y - OffsetY % Ui->RowHeight;
  RowPixels = Ui->RowHeight - Ui->Scale;
  // A row clipped by the footer/screen cannot safely be a launch target.
  if ((Ui->FooterTop <= RowTop) || (RowPixels > Ui->FooterTop - RowTop) ||
      (RowPixels > Ui->Height - RowTop))
  {
    return LEMONADES_NO_ENTRY;
  }

  return Row;
}

STATIC
BOOLEAN
LemonadesTouchSample (
  IN OUT LEMONADES_TOUCH_GESTURE  *Gesture,
  IN CONST UNIXNU_UI       *Ui,
  IN UINTN                Count,
  IN BOOLEAN              Pressed,
  IN BOOLEAN              CoordinatesValid,
  IN UINTN                X,
  IN UINTN                Y,
  IN UINT64               Tick,
  IN OUT UINTN            *Selected,
  IN OUT UINTN            *ArmedRow
  )
{
  UINTN  Hit;
  UINTN  DistanceX;
  UINTN  DistanceY;
  UINTN  Slop;
  BOOLEAN Confirm;

  Hit = CoordinatesValid ? LemonadesHitEntry (Ui, Count, X, Y) : LEMONADES_NO_ENTRY;
  if (Pressed && !Gesture->Down) {
    Gesture->Down      = TRUE;
    Gesture->Eligible  = (Hit != LEMONADES_NO_ENTRY);
    Gesture->PressRow  = Hit;
    Gesture->PressX    = X;
    Gesture->PressY    = Y;
    Gesture->PressTick = Tick;
    if (!Gesture->Eligible) {
      *ArmedRow = LEMONADES_NO_ENTRY;
    }

    return FALSE;
  }

  if (!Gesture->Down) {
    return FALSE;
  }

  DistanceX = X > Gesture->PressX ? X - Gesture->PressX : Gesture->PressX - X;
  DistanceY = Y > Gesture->PressY ? Y - Gesture->PressY : Gesture->PressY - Y;
  Slop = Ui->Scale > MAX_UINTN / 4 ? MAX_UINTN : MAX ((UINTN)8, Ui->Scale * 4);
  if (!CoordinatesValid || (Hit != Gesture->PressRow) ||
      (DistanceX > Slop) || (DistanceY > Slop) ||
      (Tick < Gesture->PressTick) || (Tick - Gesture->PressTick > 15))
  {
    Gesture->Eligible = FALSE;
    *ArmedRow = LEMONADES_NO_ENTRY;
  }

  if (Pressed) {
    return FALSE;
  }

  Gesture->Down = FALSE;
  if (!Gesture->Eligible) {
    return FALSE;
  }

  // Never boot on finger-down, dragging, holding, or the first complete tap,
  // including the already highlighted default. A second full tap on the
  // explicitly armed row confirms. Keys and invalid gestures disarm it.
  Confirm   = (*ArmedRow == Hit) && (*Selected == Hit);
  *Selected = Hit;
  *ArmedRow = Confirm ? LEMONADES_NO_ENTRY : Hit;
  return Confirm;
}
// END LEMONADES_MENU_INPUT_LOGIC

typedef struct {
  EFI_ABSOLUTE_POINTER_PROTOCOL  *Protocol;
  LEMONADES_TOUCH_GESTURE              Gesture;
  BOOLEAN                       ErrorLogged;
} LEMONADES_POINTER;

STATIC
VOID
DiscoverPointers (
  IN OUT LEMONADES_POINTER  *Pointers,
  IN OUT UINTN        *PointerCount
  )
{
  EFI_HANDLE                     *Handles;
  UINTN                          HandleCount;
  UINTN                          Index;
  UINTN                          Existing;
  EFI_ABSOLUTE_POINTER_PROTOCOL  *Protocol;
  VOID                           *DevicePath;

  if (*PointerCount >= LEMONADES_MAX_POINTERS) {
    return;
  }

  if (EFI_ERROR (gBS->LocateHandleBuffer (ByProtocol, &gEfiAbsolutePointerProtocolGuid,
                                        NULL, &HandleCount, &Handles)))
  {
    return;
  }

  for (Index = 0; (Index < HandleCount) && (*PointerCount < LEMONADES_MAX_POINTERS); Index++) {
    // ConSplitter always publishes a virtual pointer, even without a touch
    // device. Its handle has no device path; conslemonadesng it as well as its
    // physical provider would also read the same hardware input twice.
    if (EFI_ERROR (gBS->HandleProtocol (Handles[Index], &gEfiDevicePathProtocolGuid,
                                      &DevicePath)) || (DevicePath == NULL) ||
        EFI_ERROR (gBS->HandleProtocol (Handles[Index], &gEfiAbsolutePointerProtocolGuid,
                                      (VOID **)&Protocol)) || (Protocol->Mode == NULL) ||
        (Protocol->GetState == NULL) ||
        (Protocol->Mode->AbsoluteMaxX <= Protocol->Mode->AbsoluteMinX) ||
        (Protocol->Mode->AbsoluteMaxY <= Protocol->Mode->AbsoluteMinY))
    {
      continue;
    }

    for (Existing = 0; Existing < *PointerCount; Existing++) {
      if (Pointers[Existing].Protocol == Protocol) {
        break;
      }
    }

    if (Existing != *PointerCount) {
      continue;
    }

    Pointers[*PointerCount].Protocol = Protocol;
    ZeroMem (&Pointers[*PointerCount].Gesture, sizeof (LEMONADES_TOUCH_GESTURE));
    UniXNULog ("menu input: pointer %u x=%Lu..%Lu y=%Lu..%Lu event=%a",
               (UINT32)*PointerCount, Protocol->Mode->AbsoluteMinX, Protocol->Mode->AbsoluteMaxX,
               Protocol->Mode->AbsoluteMinY, Protocol->Mode->AbsoluteMaxY,
               Protocol->WaitForInput != NULL ? "yes" : "poll");
    (*PointerCount)++;
  }

  FreePool (Handles);
}

//
// Physical input = a SimpleTextIn instance that sits on a device path; the
// ConSplitter's virtual handle has none.
//
STATIC
UINTN
CountInputDevices (
  VOID
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  *Handles;
  UINTN       Count;
  UINTN       Index;
  UINTN       Physical;
  VOID        *Path;

  if (gST->ConIn == NULL) {
    return 0;
  }

  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiSimpleTextInProtocolGuid, NULL, &Count, &Handles);
  if (EFI_ERROR (Status)) {
    return 0;
  }

  Physical = 0;
  for (Index = 0; Index < Count; Index++) {
    if (!EFI_ERROR (gBS->HandleProtocol (Handles[Index], &gEfiDevicePathProtocolGuid, &Path))) {
      Physical++;
    }
  }

  FreePool (Handles);
  return Physical;
}

STATIC
VOID
DrawCountdown (
  IN UNIXNU_UI      *Ui,
  IN UNIXNU_CONFIG  *Config,
  IN INTN       RemainingMs,
  IN BOOLEAN    HasInput
  )
{
  CHAR16  Line[128];

  if (RemainingMs >= 0) {
    UnicodeSPrint (
      Line,
      sizeof (Line),
      L"Booting %s in %u s",
      Config->Entries[Config->DefaultIndex].Title,
      (UINT32)((RemainingMs + 999) / 1000)
      );
  } else {
    UnicodeSPrint (Line, sizeof (Line), L"Select an entry");
  }

  UniXNUUiDrawStatus (Ui, 0, Line);
}

UINTN
UniXNUMenuRun (
  IN UNIXNU_UI      *Ui,
  IN UNIXNU_CONFIG  *Config,
  IN BOOLEAN        Countdown
  )
{
  EFI_STATUS                  Status;
  EFI_EVENT                   Timer;
  EFI_EVENT                   Events[2 + LEMONADES_MAX_POINTERS];
  UINTN                       EventCount;
  UINTN                       Signaled;
  EFI_INPUT_KEY               Key;
  UINTN                       Selected;
  UINTN                       Previous;
  UINTN                       Index;
  UINTN                       Other;
  UINTN                       Burst;
  BOOLEAN                     HasInput;
  BOOLEAN                     UserActive;
  BOOLEAN                     TickEvent;
  BOOLEAN                     Confirm;
  BOOLEAN                     Pressed;
  BOOLEAN                     WasDown;
  BOOLEAN                     CoordinatesValid;
  BOOLEAN                     MultipleContacts;
  INTN                        RemainingMs;
  UINTN                       RotateMs;
  UINTN                       RotateAccum;
  INTN                        LastShownSecond;
  UINTN                       Count;
  LEMONADES_POINTER                 Pointers[LEMONADES_MAX_POINTERS];
  UINTN                       PointerCount;
  EFI_ABSOLUTE_POINTER_STATE  PointerState;
  EFI_ABSOLUTE_POINTER_MODE   *PointerMode;
  UINTN                       X;
  UINTN                       Y;
  UINTN                       ArmedRow;
  UINTN                       InputLogCount;
  UINT64                      Tick;
  UINT64                      NextDiscovery;

  Count    = Config->EntryCount;
  Selected = Config->DefaultIndex;
  PointerCount = 0;
  ZeroMem (Pointers, sizeof (Pointers));
  DiscoverPointers (Pointers, &PointerCount);
  HasInput = (CountInputDevices () > 0) || (PointerCount > 0);

  if (!Countdown) {
    RemainingMs = HasInput ? -1 : (INTN)Config->FallbackTimeout * 1000;
  } else if (Config->Timeout < 0) {
    RemainingMs = HasInput ? -1 : (INTN)Config->FallbackTimeout * 1000;
  } else {
    RemainingMs = Config->Timeout * 1000;
  }

  RotateMs = Config->RotateSeconds * 1000;
  if (!HasInput && (RotateMs == 0)) {
    RotateMs = DEFAULT_ROTATE_SEC * 1000;
  }

  UniXNUUiDrawFrame (Ui, Config);
  for (Index = 0; Index < Count; Index++) {
    UniXNUUiDrawEntry (Ui, Config, Index, Index == Selected);
  }

  UniXNUUiDrawStatus (Ui, 1, PointerCount > 0 ? L"Tap select; tap again to confirm"
                                            : L"Vol +/- select; Power confirm");
  if (Ui->Notice[0] != L'\0') {
    UniXNUUiDrawStatus (Ui, 2, Ui->Notice);
  }

  UniXNULog (
    "menu: shown %u entries, default %u '%a', timeout %d ms, input %a, rotate %u ms",
    (UINT32)Count,
    (UINT32)Config->DefaultIndex,
    (Config->Entries[Config->DefaultIndex].Id != NULL) ? Config->Entries[Config->DefaultIndex].Id : "?",
    (INT32)RemainingMs,
    HasInput ? "yes" : "no",
    (UINT32)RotateMs
    );
  UniXNULog ("menu input: pointers=%u box=%u,%u %ux%u rows=%u row=%u gap=%u",
             (UINT32)PointerCount, (UINT32)Ui->MenuLeft, (UINT32)Ui->MenuTop,
             (UINT32)Ui->MenuWidth, Ui->Height, (UINT32)Ui->VisibleRows,
             (UINT32)Ui->RowHeight, (UINT32)Ui->Scale);

  if (RemainingMs == 0) {
    UniXNULog ("menu: timeout 0, booting default");
    return Config->DefaultIndex;
  }

  Status = gBS->CreateEvent (EVT_TIMER, TPL_CALLBACK, NULL, NULL, &Timer);
  if (EFI_ERROR (Status)) {
    return Config->DefaultIndex;
  }

  gBS->SetTimer (Timer, TimerPeriodic, EFI_TIMER_PERIOD_MILLISECONDS (TICK_MS));
  UserActive      = FALSE;
  RotateAccum     = 0;
  LastShownSecond = -2;
  ArmedRow        = LEMONADES_NO_ENTRY;
  InputLogCount   = 0;
  Tick            = 0;
  NextDiscovery   = 10;
  for ( ; ;) {
    INTN  Second = (RemainingMs < 0) ? -1 : (RemainingMs + 999) / 1000;

    if (Second != LastShownSecond) {
      DrawCountdown (Ui, Config, RemainingMs, HasInput);
      LastShownSecond = Second;
    }

    // Rebuild the bounded event array each pass: a pointer driver may arrive
    // after the menu. Timer polling also supports providers without events.
    EventCount = 0;
    Events[EventCount++] = Timer;
    if ((gST->ConIn != NULL) && (gST->ConIn->WaitForKey != NULL)) {
      Events[EventCount++] = gST->ConIn->WaitForKey;
    }

    for (Index = 0; Index < PointerCount; Index++) {
      if (Pointers[Index].Protocol->WaitForInput != NULL) {
        Events[EventCount++] = Pointers[Index].Protocol->WaitForInput;
      }
    }

    Status = gBS->WaitForEvent (EventCount, Events, &Signaled);
    if (EFI_ERROR (Status)) {
      UniXNULog ("menu input: WaitForEvent failed %r", Status);
      break;
    }

    TickEvent = (Signaled == 0);
    if (TickEvent) {
      Tick++;
    }

    Previous = Selected;
    Confirm  = FALSE;
    // Read pending input before acting on the same timer tick, so a touch
    // cannot lose the race against the countdown reaching zero.
    if ((gST->ConIn != NULL) &&
        !EFI_ERROR (gST->ConIn->ReadKeyStroke (gST->ConIn, &Key)))
    {
      if (InputLogCount < LEMONADES_INPUT_LOG_LIMIT) {
        UniXNULog ("menu input: key scan=%x unicode=%x selected=%u",
                   Key.ScanCode, Key.UnicodeChar, (UINT32)Selected);
        InputLogCount++;
      }

      ArmedRow = LEMONADES_NO_ENTRY;
      for (Index = 0; Index < PointerCount; Index++) {
        Pointers[Index].Gesture.Eligible = FALSE;
      }

      if (!UserActive) {
        UserActive  = TRUE;
        RemainingMs = -1;
        Selected    = Config->DefaultIndex;
      }

      LastShownSecond = -2;
      if ((Key.ScanCode == SCAN_UP) || (Key.UnicodeChar == L'k')) {
        Selected = (Selected + Count - 1) % Count;
      } else if ((Key.ScanCode == SCAN_DOWN) || (Key.UnicodeChar == L'j')) {
        Selected = (Selected + 1) % Count;
      } else if (Key.ScanCode == SCAN_HOME) {
        Selected = 0;
      } else if (Key.ScanCode == SCAN_END) {
        Selected = Count - 1;
      } else if ((Key.UnicodeChar >= L'1') && (Key.UnicodeChar <= L'9') &&
                 ((UINTN)(Key.UnicodeChar - L'1') < Count))
      {
        Selected = Key.UnicodeChar - L'1';
        Confirm  = TRUE;
      } else if ((Key.UnicodeChar == CHAR_CARRIAGE_RETURN) ||
                 (Key.UnicodeChar == CHAR_LINEFEED) || (Key.UnicodeChar == L' ') ||
                 (Key.ScanCode == SCAN_RIGHT) || (Key.ScanCode == SCAN_SUSPEND))
      {
        Confirm = TRUE;
      }

      if (Confirm) {
        UniXNULog ("menu input: key confirmed %u", (UINT32)Selected);
        break;
      }
    }

    for (Index = 0; (Index < PointerCount) && !Confirm; Index++) {
      for (Burst = 0; Burst < LEMONADES_POINTER_BURST; Burst++) {
        Status = Pointers[Index].Protocol->GetState (Pointers[Index].Protocol, &PointerState);
        if (Status == EFI_NOT_READY) {
          break;
        }

        if (EFI_ERROR (Status)) {
          Pointers[Index].Gesture.Down     = FALSE;
          Pointers[Index].Gesture.Eligible = FALSE;
          ArmedRow = LEMONADES_NO_ENTRY;
          if (!Pointers[Index].ErrorLogged && (InputLogCount < LEMONADES_INPUT_LOG_LIMIT)) {
            UniXNULog ("menu input: pointer %u read failed %r", (UINT32)Index, Status);
            InputLogCount++;
          }
          Pointers[Index].ErrorLogged = TRUE;

          break;
        }

        Pointers[Index].ErrorLogged = FALSE;
        Pressed = ((PointerState.ActiveButtons & EFI_ABSP_TouchActive) != 0);
        WasDown = Pointers[Index].Gesture.Down;
        if (Pressed && !UserActive) {
          UserActive      = TRUE;
          RemainingMs     = -1;
          Selected        = Config->DefaultIndex;
          LastShownSecond = -2;
        }

        PointerMode = Pointers[Index].Protocol->Mode;
        X = 0;
        Y = 0;
        CoordinatesValid = (PointerMode != NULL) &&
          LemonadesScaleAxis (PointerState.CurrentX, PointerMode->AbsoluteMinX, PointerMode->AbsoluteMaxX, Ui->Width, &X) &&
          LemonadesScaleAxis (PointerState.CurrentY, PointerMode->AbsoluteMinY, PointerMode->AbsoluteMaxY, Ui->Height, &Y);
        MultipleContacts = FALSE;
        if (Pressed) {
          for (Other = 0; Other < PointerCount; Other++) {
            if ((Other != Index) && Pointers[Other].Gesture.Down) {
              Pointers[Other].Gesture.Eligible = FALSE;
              MultipleContacts = TRUE;
            }
          }
        }

        Confirm = LemonadesTouchSample (&Pointers[Index].Gesture, Ui, Count, Pressed,
                                  CoordinatesValid, X, Y, Tick, &Selected, &ArmedRow);
        if (MultipleContacts) {
          Pointers[Index].Gesture.Eligible = FALSE;
          ArmedRow = LEMONADES_NO_ENTRY;
          Confirm  = FALSE;
        }

        if ((WasDown != Pressed) && (InputLogCount < LEMONADES_INPUT_LOG_LIMIT)) {
          UniXNULog ("menu input: touch %u %a raw=%Lu,%Lu pixel=%u,%u valid=%u selected=%u armed=%u",
                     (UINT32)Index, Pressed ? "down" : "up", PointerState.CurrentX, PointerState.CurrentY,
                     (UINT32)X, (UINT32)Y, CoordinatesValid, (UINT32)Selected,
                     ArmedRow == LEMONADES_NO_ENTRY ? MAX_UINT32 : (UINT32)ArmedRow);
          InputLogCount++;
        }

        if (WasDown && !Pressed) {
          UniXNUUiDrawStatus (Ui, 0, ArmedRow != LEMONADES_NO_ENTRY ? L"Tap selected item again to confirm"
                                                          : L"Select an entry");
          LastShownSecond = -1;
        }

        if (Confirm) {
          UniXNULog ("menu input: second tap confirmed %u", (UINT32)Selected);
          break;
        }
      }
    }

    if (Confirm) {
      break;
    }

    if (TickEvent) {
      if (!UserActive && (RemainingMs > 0)) {
        RemainingMs -= TICK_MS;
        if (RemainingMs <= 0) {
          UniXNULog ("menu: timeout, booting default %u", (UINT32)Config->DefaultIndex);
          Selected = Config->DefaultIndex;
          break;
        }
      }

      if (!UserActive && (RotateMs > 0) && (Count > 1)) {
        RotateAccum += TICK_MS;
        if (RotateAccum >= RotateMs) {
          RotateAccum = 0;
          Selected = (Selected + 1) % Count;
        }
      }

      if (Tick >= NextDiscovery) {
        UINTN OldPointerCount = PointerCount;
        DiscoverPointers (Pointers, &PointerCount);
        HasInput = (CountInputDevices () > 0) || (PointerCount > 0);
        NextDiscovery = Tick + 10;
        if (PointerCount != OldPointerCount) {
          UniXNUUiDrawStatus (Ui, 1, L"Tap select; tap again to confirm");
        }
      }
    }

    if (Selected != Previous) {
      UniXNUUiDrawEntry (Ui, Config, Previous, FALSE);
      UniXNUUiDrawEntry (Ui, Config, Selected, TRUE);
    }
  }

  gBS->SetTimer (Timer, TimerCancel, 0);
  gBS->CloseEvent (Timer);
  return Selected;
}
