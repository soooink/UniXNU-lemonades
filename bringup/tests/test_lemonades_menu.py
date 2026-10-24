"""Run the board menu's actual pure input helpers on host memory only."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MENU = ROOT / "devices/lemonades/menu/Menu.c"

PRELUDE = r"""
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t BOOLEAN;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef uintptr_t UINTN;
#define STATIC static
#define CONST const
#define IN
#define OUT
#define TRUE 1
#define FALSE 0
#define MAX_UINTN UINTPTR_MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#define LEMONADES_NO_ENTRY MAX_UINTN
enum {UniXNUUiGraphics,UniXNUUiText,UniXNUUiHeadless};
typedef struct {
 UINTN Mode;
 UINT32 Width,Height;
 UINTN Scale,MenuTop,RowHeight,MenuLeft,MenuWidth,FooterTop,VisibleRows;
} UNIXNU_UI;
"""

CHECKS = r"""
static uint64_t RandomState=0x3141592653589793ULL;
static uint64_t Random(void) {
 RandomState^=RandomState<<13;RandomState^=RandomState>>7;
 RandomState^=RandomState<<17;return RandomState;
}
static void CoordinateChecks(void) {
 UINTN pixel=999;
 assert(LemonadesScaleAxis(0,0,65535,1080,&pixel)&&pixel==0);
 assert(LemonadesScaleAxis(65535,0,65535,1080,&pixel)&&pixel==1079);
 assert(LemonadesScaleAxis(32768,0,65535,1080,&pixel)&&pixel==539);
 assert(LemonadesScaleAxis(600,100,1100,1080,&pixel)&&pixel==539);
 assert(LemonadesScaleAxis(UINT64_MAX,0,UINT64_MAX,1080,&pixel)&&pixel==1079);
 assert(LemonadesScaleAxis(UINT64_MAX-1,0,UINT64_MAX,1080,&pixel)&&pixel==1078);
 assert(LemonadesScaleAxis(UINT64_MAX/2,0,UINT64_MAX,1080,&pixel)&&pixel==539);
 assert(LemonadesScaleAxis(UINT64_MAX-50,UINT64_MAX-100,UINT64_MAX,1080,&pixel)&&pixel==539);
 assert(LemonadesScaleAxis(500,0,65535,1,&pixel)&&pixel==0);
 assert(!LemonadesScaleAxis(99,100,1100,1080,&pixel));
 assert(!LemonadesScaleAxis(1101,100,1100,1080,&pixel));
 assert(!LemonadesScaleAxis(0,0,0,1080,&pixel));
 assert(!LemonadesScaleAxis(0,0,100,0,&pixel));
 for(unsigned i=0;i<10000;i++) {
  uint64_t min=Random(),max=Random();
  if(min>max){uint64_t t=min;min=max;max=t;}
  if(min==max)continue;
  uint64_t raw=min+Random()%(max-min);
  uint32_t pixels=(uint32_t)Random()|1;
  uint64_t expected=(uint64_t)(((__uint128_t)(raw-min)*(pixels-1))/(max-min));
  assert(LemonadesScaleAxis(raw,min,max,pixels,&pixel)&&pixel==expected);
 }
}
static UNIXNU_UI Ui={UniXNUUiGraphics,1080,2340,4,700,114,100,880,1800,3};
static void HitChecks(void) {
 assert(LemonadesHitEntry(&Ui,4,100,700)==0);
 assert(LemonadesHitEntry(&Ui,4,979,809)==0);
 assert(LemonadesHitEntry(&Ui,4,99,700)==LEMONADES_NO_ENTRY);
 assert(LemonadesHitEntry(&Ui,4,980,700)==LEMONADES_NO_ENTRY);
 assert(LemonadesHitEntry(&Ui,4,100,699)==LEMONADES_NO_ENTRY);
 assert(LemonadesHitEntry(&Ui,4,100,810)==LEMONADES_NO_ENTRY); /* start of row gap */
 assert(LemonadesHitEntry(&Ui,4,100,813)==LEMONADES_NO_ENTRY);
 assert(LemonadesHitEntry(&Ui,4,100,814)==1);
 assert(LemonadesHitEntry(&Ui,4,100,1037)==2);
 assert(LemonadesHitEntry(&Ui,4,100,1042)==LEMONADES_NO_ENTRY); /* not visible */
 assert(LemonadesHitEntry(&Ui,2,100,928)==LEMONADES_NO_ENTRY); /* config count */
 assert(LemonadesHitEntry(&Ui,4,1080,700)==LEMONADES_NO_ENTRY);
 assert(LemonadesHitEntry(&Ui,4,100,2340)==LEMONADES_NO_ENTRY);
 UNIXNU_UI clipped=Ui;clipped.FooterTop=800;
 assert(LemonadesHitEntry(&clipped,4,100,700)==LEMONADES_NO_ENTRY);
 clipped=Ui;clipped.Mode=UniXNUUiText;
 assert(LemonadesHitEntry(&clipped,4,100,700)==LEMONADES_NO_ENTRY);
 clipped=Ui;clipped.RowHeight=0;
 assert(LemonadesHitEntry(&clipped,4,100,700)==LEMONADES_NO_ENTRY);
}
static void GestureChecks(void) {
 LEMONADES_TOUCH_GESTURE gesture={0};UINTN selected=0,armed=LEMONADES_NO_ENTRY;
 #define SAMPLE(down,valid,x,y,tick) LemonadesTouchSample(&gesture,&Ui,3,down,valid,x,y,tick,&selected,&armed)
 assert(!SAMPLE(TRUE,TRUE,150,740,0));
 assert(!SAMPLE(TRUE,TRUE,150,740,1)); /* held down is never a second tap */
 assert(!SAMPLE(FALSE,TRUE,150,740,2)&&selected==0&&armed==0);
 assert(!SAMPLE(FALSE,TRUE,150,740,3)&&armed==0); /* stray up */
 assert(!SAMPLE(TRUE,TRUE,150,740,4));
 assert(SAMPLE(FALSE,TRUE,150,740,5)&&selected==0&&armed==LEMONADES_NO_ENTRY);
 assert(!SAMPLE(TRUE,TRUE,150,850,6));
 assert(!SAMPLE(FALSE,TRUE,150,850,7)&&selected==1&&armed==1);
 assert(!SAMPLE(TRUE,TRUE,150,850,8));
 assert(!SAMPLE(TRUE,TRUE,150,740,9)); /* drag to another row */
 assert(!SAMPLE(FALSE,TRUE,150,850,10)&&armed==LEMONADES_NO_ENTRY);
 assert(!SAMPLE(TRUE,TRUE,150,850,11));
 assert(!SAMPLE(TRUE,TRUE,167,850,12)); /* beyond 16px slop */
 assert(!SAMPLE(FALSE,TRUE,150,850,13)&&armed==LEMONADES_NO_ENTRY);
 assert(!SAMPLE(TRUE,TRUE,150,850,20));
 assert(!SAMPLE(FALSE,TRUE,150,850,36)&&armed==LEMONADES_NO_ENTRY); /* long hold */
 assert(!SAMPLE(TRUE,TRUE,150,850,40));
 assert(!SAMPLE(FALSE,FALSE,150,850,41)&&armed==LEMONADES_NO_ENTRY); /* invalid up */
 assert(!SAMPLE(TRUE,TRUE,50,850,42)); /* down outside the box */
 assert(!SAMPLE(FALSE,TRUE,150,850,43)&&armed==LEMONADES_NO_ENTRY);
 assert(!SAMPLE(TRUE,TRUE,150,850,44));
 assert(!SAMPLE(FALSE,TRUE,150,850,45)&&armed==1);
 assert(!SAMPLE(TRUE,TRUE,150,850,46));
 gesture.Eligible=FALSE;armed=LEMONADES_NO_ENTRY; /* key cancels in-flight touch */
 assert(!SAMPLE(FALSE,TRUE,150,850,47)&&armed==LEMONADES_NO_ENTRY);
 assert(!SAMPLE(TRUE,TRUE,150,850,48));
 assert(!SAMPLE(FALSE,TRUE,155,854,49)&&armed==1); /* small jitter */
 assert(!SAMPLE(TRUE,TRUE,150,850,50));
 assert(SAMPLE(FALSE,TRUE,155,854,51)&&selected==1);
 #undef SAMPLE
}
int main(void) {
 CoordinateChecks();HitChecks();GestureChecks();
 puts("PASS: 10000 wide-range coordinate oracle cases, actual UI bounds/gaps/clipping, two complete taps, drag/hold/invalid-up/key cancellation");
 return 0;
}
"""


class LemonadesMenuInputTests(unittest.TestCase):
    def test_prepare_anchors_are_preserved(self):
        text = MENU.read_text()
        self.assertIn('#include "Internal.h"', text)
        self.assertEqual(text.count('  UniXNULog (\n    "menu: shown'), 1)

    @unittest.skipUnless(shutil.which("clang"), "host clang is needed for C input regression")
    def test_actual_pure_c_logic_under_sanitizers(self):
        text = MENU.read_text()
        logic = text.split("// BEGIN LEMONADES_MENU_INPUT_LOGIC\n", 1)[1].split("// END LEMONADES_MENU_INPUT_LOGIC", 1)[0]
        with tempfile.TemporaryDirectory(prefix="lemonades-menu-input-") as temporary:
            source = Path(temporary) / "input.c"
            binary = Path(temporary) / "input-check"
            source.write_text(PRELUDE + logic + CHECKS)
            subprocess.run([shutil.which("clang"), "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=address,undefined", str(source), "-o", str(binary)],
                           check=True, capture_output=True, text=True)
            result = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
            self.assertIn("PASS:", result.stdout)


if __name__ == "__main__":
    unittest.main()
