"""Exercise the production overlay callback's handoff and lock branches at EL0."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_lemonades_payload import function

ROOT = Path(__file__).resolve().parents[1]


class ScreenHandoffTests(unittest.TestCase):
    def test_no_overlay_stores_after_system_handoff(self):
        source = (ROOT / "devices/lemonades/package/boot-progress/BootProgress.c").read_text()
        # Reuse the brace extractor; its EFI-style storage token is only a
        # host alias for static and does not change the callback body.
        callback = function(source.replace("static void touch_overlay(void) {",
                                           "STATIC void touch_overlay(void) {"), "touch_overlay")
        harness = r'''
#include <assert.h>
#include <stdint.h>
#define STATIC static
static unsigned render_busy,post_scanout_overlay=1,boot_progress_display_owned;
static unsigned touch_passes,native_touch_stage_req=1,writes;
static unsigned seconds(void){return 42;}
static void ext_overlay_locked(void){++writes;}
static void crash_banner(unsigned now){assert(now==42);++writes;}
static void touch_overlay_locked(void){++writes;}
'''
        harness += callback + r'''
int main(void) {
  post_scanout_overlay=0;
  touch_overlay(); assert(writes==3 && render_busy==0 && touch_passes==1);
  boot_progress_display_owned=1;
  for(unsigned i=0;i<100;++i)touch_overlay();
  assert(writes==3 && render_busy==0 && touch_passes==101);
  post_scanout_overlay=1;
  touch_overlay();assert(writes==6 && render_busy==0);
  render_busy=1;
  touch_overlay();assert(writes==6 && render_busy==1);
  post_scanout_overlay=0;
  touch_overlay();assert(writes==6 && render_busy==1);
  render_busy=0;
  touch_overlay();assert(writes==6 && render_busy==0);
}
'''
        with tempfile.TemporaryDirectory(prefix="lemonades-screen-handoff-") as temp:
            c = Path(temp) / "callback.c"
            exe = Path(temp) / "callback"
            c.write_text(harness)
            subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-Wno-pointer-bool-conversion", "-fsanitize=address,undefined",
                            str(c), "-o", str(exe)], check=True)
            subprocess.run([str(exe)], check=True)


if __name__ == "__main__":
    unittest.main()
