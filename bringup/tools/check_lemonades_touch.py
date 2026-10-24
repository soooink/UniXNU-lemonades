#!/usr/bin/env python3
"""Host protocol tests and bounded log verification; never boots an emulator."""
import argparse,hashlib,json,subprocess,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'out/lemonades/attempt-56-preparation'
def log_budget():
 limits={k:int(v) for k,v in re.findall(r'(LEMONADES_FTS_\w+_LIMIT)=(\d+)',(ROOT/'devices/lemonades/package/touch/LemonadesFtsLogLimits.h').read_text())}
 assert limits['LEMONADES_FTS_STOP_LIMIT']==limits['LEMONADES_FTS_PROTOCOL_LIMIT']+1
 assert limits['LEMONADES_FTS_LOG_LIMIT']==limits['LEMONADES_FTS_STOP_LIMIT']+limits['LEMONADES_FTS_POINT_LIMIT']
 b=dict(log_bytes_max=1712256+30*32*42*3+limits['LEMONADES_FTS_LOG_LIMIT']*16*42*3,console_bytes=0x200000-12,log_limits=limits)
 assert b['log_bytes_max']<b['console_bytes'];return b
def main():
 global OUT
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--attempt',type=int,default=56);args=parser.parse_args()
 OUT=ROOT/f'out/lemonades/attempt-{args.attempt:02d}-preparation'
 OUT.mkdir(parents=True,exist_ok=True);commands=[
 ['xcrun','clang++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(ROOT/'tests/lemonades_board_boost.cpp'),'-o',str(OUT/'board-boost-test')],
 [str(OUT/'board-boost-test')],
 ['xcrun','clang++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(ROOT/'tests/lemonades_board_spmi.cpp'),'-o',str(OUT/'board-spmi-test')],
 [str(OUT/'board-spmi-test')],
 ['xcrun','clang++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(ROOT/'tests/lemonades_fts_gpi.cpp'),'-o',str(OUT/'fts-gpi-test')],
 [str(OUT/'fts-gpi-test')],
 ['xcrun','clang++','-std=c++17','-Wall','-Wextra','-Werror','-Wno-unused-function','-fsanitize=address,undefined',str(ROOT/'tests/lemonades_fts_gpi_transport.cpp'),'-o',str(OUT/'fts-gpi-transport-test')],
 [str(OUT/'fts-gpi-transport-test')],
 ['xcrun','clang++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(ROOT/'tests/lemonades_fts_core.cpp'),'-o',str(OUT/'fts-core-test')],
 [str(OUT/'fts-core-test')],
 ['python3','-m','unittest','discover','-s','tests','-p','test_lemonades_touch_trace.py'],
 ['xcrun','clang++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(ROOT/'tests/lemonades_touch_irq_log.cpp'),'-o',str(OUT/'fts-irq-log-test')],
 [str(OUT/'fts-irq-log-test')],
 ['xcrun','clang++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(ROOT/'tests/lemonades_fts_startup.cpp'),'-o',str(OUT/'fts-startup-test')],
 [str(OUT/'fts-startup-test')],
 ['xcrun','clang++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(ROOT/'tests/lemonades_fts_identity.cpp'),'-o',str(OUT/'fts-identity-test')],
 [str(OUT/'fts-identity-test')],
 ['xcrun','clang++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(ROOT/'tests/lemonades_fts_retry.cpp'),'-o',str(OUT/'fts-retry-test')],
 [str(OUT/'fts-retry-test')],
 ['xcrun','clang++','-std=c++17','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable','-fsanitize=address,undefined',str(ROOT/'tests/lemonades_fts_recovery.cpp'),'-o',str(OUT/'fts-recovery-test')],
 [str(OUT/'fts-recovery-test')],
 ['xcrun','clang++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(ROOT/'tests/lemonades_fts_sensing.cpp'),'-o',str(OUT/'fts-sensing-test')],
 [str(OUT/'fts-sensing-test')],
 ['xcrun','clang++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(ROOT/'tests/lemonades_fts_sysinfo.cpp'),'-o',str(OUT/'fts-sysinfo-test')],
 [str(OUT/'fts-sysinfo-test')],
 ['xcrun','clang++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(ROOT/'tests/lemonades_fts_frame_sample.cpp'),'-o',str(OUT/'fts-frame-sample-test')],
 [str(OUT/'fts-frame-sample-test')],
 ['xcrun','clang++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(ROOT/'tests/lemonades_fts_frame_probe.cpp'),'-o',str(OUT/'fts-frame-probe-test')],
 [str(OUT/'fts-frame-probe-test')],
 ['xcrun','clang++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(ROOT/'tests/lemonades_fts_sync_frame.cpp'),'-o',str(OUT/'fts-sync-frame-test')],
 [str(OUT/'fts-sync-frame-test')],
 ['xcrun','clang++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(ROOT/'tests/lemonades_fts_power_sequence.cpp'),'-o',str(OUT/'fts-power-sequence-test')],
 [str(OUT/'fts-power-sequence-test')],
 ['xcrun','clang++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(ROOT/'tests/lemonades_fts_hardware_probe.cpp'),'-o',str(OUT/'fts-hardware-probe-test')],
 [str(OUT/'fts-hardware-probe-test')],
 ['xcrun','clang++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(ROOT/'tests/lemonades_fts_scan_probe.cpp'),'-o',str(OUT/'fts-scan-probe-test')],
 [str(OUT/'fts-scan-probe-test')],
 ['xcrun','clang++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(ROOT/'tests/lemonades_fts_data_probe.cpp'),'-o',str(OUT/'fts-data-probe-test')],
 [str(OUT/'fts-data-probe-test')],
 ['xcrun','clang++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(ROOT/'tests/lemonades_fts_config_probe.cpp'),'-o',str(OUT/'fts-config-probe-test')],
 [str(OUT/'fts-config-probe-test')],
 ['python3',str(ROOT/'tools/check_lemonades_fts_sysinfo_layout.py'),'--output',str(OUT/'sysinfo-layout.json')]]
 for i,command in enumerate(commands):
  p=subprocess.run(command,cwd=ROOT,capture_output=True,text=True);(OUT/f'host-test-{i}.log').write_text(p.stdout+p.stderr)
  if p.returncode:raise SystemExit(p.stdout+p.stderr)
 inputs=['devices/lemonades/package/touch/LemonadesFtsCore.h','tests/lemonades_fts_core.cpp','tools/lemonades_touch_trace.py','tests/test_lemonades_touch_trace.py', 'tools/check_lemonades_touch.py','devices/lemonades/package/touch/LemonadesTouchLog.h','devices/lemonades/package/touch/LemonadesFtsTouch.cpp','tests/lemonades_touch_irq_log.cpp']
 inputs+=['devices/lemonades/package/touch/LemonadesFtsStartup.h','tests/lemonades_fts_startup.cpp']
 inputs+=['devices/lemonades/package/touch/LemonadesBoardBoost.h','devices/lemonades/package/touch/LemonadesSpmi.inc','tests/lemonades_board_boost.cpp']
 inputs+=['tests/lemonades_board_spmi.cpp']
 inputs+=['devices/lemonades/package/touch/LemonadesFtsIdentity.h','tests/lemonades_fts_identity.cpp','devices/lemonades/package/touch/native-startup-reference.json']
 inputs+=['devices/lemonades/package/touch/LemonadesFtsRetry.h','devices/lemonades/package/touch/LemonadesFtsBus.inc','tests/lemonades_fts_retry.cpp']
 inputs+=['devices/lemonades/package/touch/LemonadesFtsRecovery.inc','tests/lemonades_fts_recovery.cpp']
 inputs+=['devices/lemonades/package/touch/LemonadesFtsSensing.h','tests/lemonades_fts_sensing.cpp']
 inputs+=['devices/lemonades/package/touch/LemonadesFtsSysInfo.h','tests/lemonades_fts_sysinfo.cpp','tools/check_lemonades_fts_sysinfo_layout.py']
 inputs+=['devices/lemonades/package/touch/LemonadesFtsFrameSample.h','tests/lemonades_fts_frame_sample.cpp']
 inputs+=['devices/lemonades/package/touch/LemonadesFtsFrameProbe.h','devices/lemonades/package/touch/LemonadesFtsLogLimits.h','tests/lemonades_fts_frame_probe.cpp']
 inputs+=['devices/lemonades/package/touch/LemonadesFtsSyncFrame.h','tests/lemonades_fts_sync_frame.cpp','devices/lemonades/package/touch/LemonadesTouchPlatform.h','devices/lemonades/package/touch/NativeHidInput.cpp']
 inputs+=['devices/lemonades/package/touch/LemonadesRpmh.inc','devices/lemonades/package/touch/LemonadesFtsPowerSequence.h','tests/lemonades_fts_power_sequence.cpp']
 inputs+=['devices/lemonades/package/touch/LemonadesFtsHardwareProbe.h','tests/lemonades_fts_hardware_probe.cpp']
 inputs += ['devices/lemonades/package/touch/LemonadesFtsGpiCore.h','devices/lemonades/package/touch/LemonadesFtsGpi.inc','tests/lemonades_fts_gpi.cpp','tests/lemonades_fts_gpi_transport.cpp','devices/lemonades/package/touch/gpi-reference.json']
 inputs += ['devices/lemonades/package/touch/LemonadesFtsScanProbe.h','tests/lemonades_fts_scan_probe.cpp','devices/lemonades/package/touch/scan-reference.json']
 inputs += ['devices/lemonades/package/touch/LemonadesFtsDataProbe.h','devices/lemonades/package/touch/LemonadesFtsPinConfig.h','tests/lemonades_fts_data_probe.cpp','devices/lemonades/package/touch/data-reference.json']
 inputs += ['devices/lemonades/package/touch/LemonadesFtsConfigProbe.h','tests/lemonades_fts_config_probe.cpp','devices/lemonades/package/touch/config-reference.json']
 report=dict(passed=True,commands=commands,protocol_sanitizers=['address','undefined'],qemu_test_performed=False,hardware_tested=False,
  **log_budget(),frame_probe_faults_checked=True,power_sequence_faults_checked=True,
  irq_log_deferral_checked=True,ready_window_checked=True,read_retry_guards_checked=True,bus_recovery_faults_checked=True,sensing_sequence_checked=True,sysinfo_read_faults_checked=True,irq_pin_restore_checked=True,frame_sample_bounds_and_faults_checked=True,post_crc_reset_checked=True,inputs={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in inputs})
 (OUT/'host-tests.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS: FTS coordinate, multi-ID lift/reset/bounds, CRC corruption/conflicts and console budget')
if __name__=='__main__':main()
