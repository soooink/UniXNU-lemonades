// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef bool BOOLEAN;
typedef uint8_t UINT8;
typedef uint64_t UINT64;
typedef unsigned long UINTN;
#define STATIC static
#define VOID void
#define FALSE false
#define TRUE true
#include "../devices/lemonades/overlay/Platforms/OnePlus/lemonadesPkg/Drivers/LemonadesButtonsDxe/KeyFilter.h"

int main(void) {
  LEMONADES_KEY_FILTER f;
  // Bounce must not navigate. Stable press navigates once; held volume repeats.
  LemonadesKeyFilterInit(&f, 0, 0);
  assert(LemonadesKeyFilterUpdate(&f, 1, 10000) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 0, 20000) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 1, 30000) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 1, 59999) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 1, 60000) == 1);
  assert(LemonadesKeyFilterUpdate(&f, 1, 559999) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 1, 560000) == 1);
  assert(LemonadesKeyFilterUpdate(&f, 1, 709999) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 1, 710000) == 1);
  assert(LemonadesKeyFilterUpdate(&f, 0, 720000) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 0, 750000) == 0);
  // A boot-held key must be released and pressed afresh.
  LemonadesKeyFilterInit(&f, 2, 0);
  assert(LemonadesKeyFilterUpdate(&f, 2, 2000000) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 0, 2010000) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 0, 2040000) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 2, 2050000) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 2, 2080000) == 2);
  // Power only confirms on short release. Long recovery holds never confirm.
  LemonadesKeyFilterInit(&f, 0, 0);
  assert(LemonadesKeyFilterUpdate(&f, 4, 10000) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 4, 40000) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 0, 200000) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 0, 230000) == 4);
  assert(LemonadesKeyFilterUpdate(&f, 0, 260000) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 4, 300000) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 4, 330000) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 4, 20000000) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 0, 20100000) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 0, 20130000) == 0);
  // Chords cancel armed keys, including a later power release.
  LemonadesKeyFilterInit(&f, 0, 0);
  assert(LemonadesKeyFilterUpdate(&f, 4, 10000) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 4, 40000) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 5, 50000) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 5, 80000) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 0, 100000) == 0);
  assert(LemonadesKeyFilterUpdate(&f, 0, 130000) == 0);
  puts("PASS: debounce, volume repeat, boot-held suppression, short power release, long-hold recovery and chord suppression");
}
