import sys,unittest,struct,zlib
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from lemonades_touch_trace import decode_touch
from check_lemonades_touch import log_budget

def row(tag,n,f,v):
 crc=zlib.crc32(struct.pack('<BBQ',n,f,v))
 return f'\nUMI {tag} {n:02x} {f:02x} {v:016x} {crc:08x}\n'.encode()
class TouchTraceTests(unittest.TestCase):
 def test_board_boost_needs_complete_guarded_write_readback(self):
  v=[27,1,0,0,0,0,1,0,0x80,7,8000,3,0,0x0c630000,4000,0]
  def read(v):return decode_touch(b''.join(row('TCHX',1,i,x) for i,x in enumerate(v)))['board_boost_enable'][0]
  self.assertTrue(read(v)['enable_readback_verified']);self.assertFalse(read(v)['touch_fix_verified'])
  for field,value in ((3,1),(4,1),(5,1),(6,2),(7,0x80),(8,0),(9,3),(11,512),(12,1),(13,0),(14,3999),(15,1)):
   a=v.copy();a[field]=value;self.assertFalse(read(a)['enable_readback_verified'])
  a=v.copy();a[6]=0;a[7]=0x80;a[9]=15;a[11]=512;a[12]=7;a[13]=0;self.assertTrue(read(a)['enable_readback_verified'])
  for missing in range(1,16):
   r=decode_touch(b''.join(row('TCHX',1,i,x) for i,x in enumerate(v) if i!=missing))['board_boost_enable'][0];self.assertIsNone(r['enable_readback_verified'])
 def test_factory_identity_requires_echo_counter_and_profile(self):
  word=lambda s:int.from_bytes(bytes.fromhex(s),'little')
  v=[25,1,0,0,63,word('a5 01 01 00 00 00 00 00'),word('a5 70 02 00 00 02 00 00'),word('53 42 32 01 74 02 32 01'),word('43 01 a4 06 70 00 00 00'),0,0,1,12000,0x70,1,0]
  def read(v):return decode_touch(b''.join(row('TCHX',1,i,x) for i,x in enumerate(v)))['factory_identity'][0]
  self.assertTrue(read(v)['native_identity_verified'])
  for field,value in ((3,1),(4,31),(5,0),(6,v[6]^(1<<16)),(7,v[7]^1),(8,0),(9,1),(10,1),(11,0),(11,51),(13,0x71),(14,2),(15,1)):
   a=v.copy();a[field]=value;self.assertFalse(read(a)['native_identity_verified'])
  for missing in range(1,16):
   r=decode_touch(b''.join(row('TCHX',1,i,x) for i,x in enumerate(v) if i!=missing))['factory_identity'][0];self.assertIsNone(r['native_identity_verified'])
 def test_board_rail_is_readonly_and_not_voltage_evidence(self):
  data=bytes([0x51,0x20,0x10,0x11,0,1,1,5,0,0x80,3,0x80,0,0,0,0])
  v=[26,1,5,0,4095,2,5,0xc400,int.from_bytes(data[:8],'little'),int.from_bytes(data[8:],'little'),12,100,1,0x201,3,0]
  def read(v):return decode_touch(b''.join(row('TCHX',1,i,x) for i,x in enumerate(v)))['board_rail'][0]
  r=read(v);self.assertTrue(r['boost_pin_output_high']);self.assertFalse(r['analog_voltage_measured']);self.assertFalse(r['fts_supply_connection_proven'])
  for field,value in ((3,1),(4,4094),(5,3),(6,12),(7,0xcb00),(10,11),(15,1),(9,v[9]|(1<<40))):
   a=v.copy();a[field]=value;self.assertIsNone(read(a)['boost_pin_output_high'])
  for byte,value in ((5,0),(5,3),(9,0),(9,0x81),(11,0)):
   b=bytearray(data);b[byte]=value;a=v.copy();a[8]=int.from_bytes(b[:8],'little');a[9]=int.from_bytes(b[8:],'little');self.assertFalse(read(a)['boost_pin_output_high'])
  for missing in range(1,16):
   r=decode_touch(b''.join(row('TCHX',1,i,x) for i,x in enumerate(v) if i!=missing))['board_rail'][0];self.assertIsNone(r['boost_pin_output_high'])
 def test_native_modes_need_complete_success_and_seven_bytes(self):
  values=[24,1,1,3,0,0,3,int.from_bytes(bytes.fromhex('00 00 64 0f 02 0e 01 00'),'little'),0xff00,1,0,0,1000,0,0,1]
  def read(v):return decode_touch(b''.join(row('TCHX',1,i,x) for i,x in enumerate(v)))['native_modes'][0]
  r=read(values);self.assertTrue(r['mode_matches_recovery']);self.assertTrue(r['grip_matches_recovery']);self.assertTrue(r['charge_command_completed']);self.assertFalse(r['touch_fix_verified'])
  for field,value in ((4,1),(6,2),(6,4),(7,values[7]|(1<<56))):
   v=values.copy();v[field]=value;self.assertIsNone(read(v)['mode_bytes'])
  for field,value in ((5,1),(6,1),(6,4),(8,values[8]|(1<<56))):
   v=values.copy();v[field]=value;self.assertIsNone(read(v)['grip_bytes'])
  v=values.copy();v[7]^=1;self.assertFalse(read(v)['mode_matches_recovery'])
  for field,value in ((9,0),(9,2),(10,1),(11,1)):
   v=values.copy();v[field]=value;self.assertFalse(read(v)['charge_command_completed'])
  for missing in range(1,16):
   r=decode_touch(b''.join(row('TCHX',1,i,x) for i,x in enumerate(values) if i!=missing))['native_modes'][0]
   self.assertIsNone(r['mode_bytes']);self.assertIsNone(r['grip_bytes']);self.assertIsNone(r['charge_command_completed'])
 def test_native_board_requires_complete_gpio_and_ready_evidence(self):
  values=[23,1,0,3,3,0,0x201,3,0x2c3,3,0x201,3,0xc3,1,0,3]
  def read(v):return decode_touch(b''.join(row('TCHX',1,i,x) for i,x in enumerate(v)))['native_board'][0]
  r=read(values);self.assertTrue(r['gpio50_native_output_high']);self.assertTrue(r['startup_three_ready_verified']);self.assertFalse(r['gpio50_written'])
  for ctl,io in ((0x205,3),(1,3),(0x201,2),(0x201,1),(0xa01,3)):
   v=values.copy();v[6]=ctl;v[7]=io;self.assertFalse(read(v)['gpio50_native_output_high'])
  v=values.copy();v[6]=0x1a01;self.assertTrue(read(v)['gpio50_native_output_high'])
  for field,value in ((3,1),(4,2),(5,1),(14,1),(15,2)):
   v=values.copy();v[field]=value;self.assertFalse(read(v)['startup_three_ready_verified'])
  for missing in range(1,16):
   r=decode_touch(b''.join(row('TCHX',1,i,x) for i,x in enumerate(values) if i!=missing))['native_board'][0]
   self.assertIsNone(r['startup_three_ready_verified']);self.assertIsNone(r['gpio50_native_output_high'])
 def test_config_fingerprints_are_bounded_and_partial_is_not_success(self):
  values=[22,1,6,1,42,10,0,3328,*[i*2|((i*2+1)<<32) for i in range(7)],200000]
  def read(v):return decode_touch(b''.join(row('TCHX',1,i,x) for i,x in enumerate(v)))['config_pages'][0]
  r=read(values);self.assertEqual(r['crc32_blocks'],list(range(10)));self.assertTrue(r['sweep_completed']);self.assertFalse(r['bytewise_identity_proven'])
  for field,value in ((4,53),(5,15),(7,3327),(7,0)):
   v=values.copy();v[field]=value;self.assertIsNone(read(v)['crc32_blocks']);self.assertFalse(read(v)['sweep_completed'])
  v=values.copy();v[6]=7;self.assertFalse(read(v)['sweep_completed'])
  r=decode_touch(row('TCHX',1,0,22))['config_pages'][0];self.assertIsNone(r['crc32_blocks']);self.assertFalse(r['sweep_completed'])
 def test_reset_method_is_logged_without_fabricating_supply_read(self):
  for phase,method in ((2,'gpio'),(0x102,'software'),(3,None)):
   values=[9,1,0,phase,1,0,100,0,0,0,0,0,0,0,0,0]
   r=decode_touch(b''.join(row('TCHX',1,i,v) for i,v in enumerate(values)))['bringup_events'][0]
   self.assertEqual(r['reset_method'],method);self.assertIsNone(r['supply_ready'])
 def test_full_supply_cycle_requires_actual_off_and_ready(self):
  on=128|(0x84<<8)|(1800<<16)|(15<<32);off=(15<<32)
  values=[21,1,0,0,127,52000,on,off,on,0,9,0x2c3,3,0x201,3,1]
  def read(v):return decode_touch(b''.join(row('TCHX',1,i,x) for i,x in enumerate(v)))['full_power_cycles'][0]
  self.assertTrue(read(values)['supply_cycle_verified']);self.assertIsNone(read(values)['off_mv'])
  for field,value in ((7,on),(8,on&~0x8000),(9,128),(15,0),(5,49000)):
   v=values.copy();v[field]=value;self.assertFalse(read(v)['supply_cycle_verified'])
  self.assertIsNone(decode_touch(row('TCHX',1,0,21))['full_power_cycles'][0]['supply_cycle_verified'])
 def test_complete_raw(self):
  data=b''.join(row('TCHX',1,i,1 if i in (0,1) else 0) for i in range(16))
  r=decode_touch(data)['raw_events'][0];self.assertTrue(r['complete']);self.assertEqual(r['raw'],'00 00 00 00 00 00 00 00')
 def test_partial_is_not_success(self):
  r=decode_touch(row('TOUC',1,0,1))['snapshots'][0]
  self.assertFalse(r['complete']);self.assertIsNone(r['hid_last_result']);self.assertIsNone(r['hid_starts'])
 def test_bad_crc(self):
  r=decode_touch(row('TOUC',1,0,1).replace(b'0000000000000001',b'0000000000000002'))
  self.assertEqual(r['crc_rejected_records'],1);self.assertFalse(r['snapshots'])
 def test_conflict(self):
  r=decode_touch(row('TOUC',1,0,1)+row('TOUC',1,0,2));self.assertEqual(r['conflicts'],[['TOUC',1]])
 def test_budget(self):
  b=log_budget();self.assertLess(b['log_bytes_max'],b['console_bytes'])
 def test_driver_stop_without_fifo_data(self):
  values=[1,1,0,0x103,0,0,90,0,0,0,0,0,0,0,0,0]
  r=decode_touch(b''.join(row('TCHX',1,i,v) for i,v in enumerate(values)))['raw_events'][0]
  self.assertTrue(r['complete']);self.assertEqual(r['driver_stop_reason'],3)
  self.assertEqual(r['raw'],'00 00 00 00 00 00 00 00')
 def test_transport_timeout_has_own_schema(self):
  values=[2,1,51,1,7,6,9321,0,3,7,0,1,1,0,7400,1]
  r=decode_touch(b''.join(row('TCHX',1,i,v) for i,v in enumerate(values)))
  self.assertFalse(r['raw_events']);e=r['transport_events'][0]
  self.assertTrue(e['complete']);self.assertEqual(e['phase'],7);self.assertEqual(e['byte_index'],6)
  self.assertEqual(e['max_clock_gap_us'],7400);self.assertEqual(e['retry'],1)
 def test_partial_transport_does_not_imply_retry(self):
  r=decode_touch(row('TCHX',1,0,2))['transport_events'][0]
  self.assertFalse(r['complete']);self.assertIsNone(r['retry']);self.assertIsNone(r['stop_result'])
 def test_recovery_has_own_schema(self):
  values=[3,1,51,0,9,700,2,3,7,5,0,1,0,1,0,1]
  r=decode_touch(b''.join(row('TCHX',1,i,v) for i,v in enumerate(values)))
  self.assertFalse(r['raw_events']);self.assertFalse(r['transport_events'])
  e=r['recovery_events'][0];self.assertTrue(e['complete']);self.assertEqual(e['pulses'],9)
  self.assertEqual(e['lines_before'],2);self.assertEqual(e['lines_after'],3);self.assertEqual(e['retry'],1)
 def test_partial_recovery_cannot_claim_success(self):
  e=decode_touch(row('TCHX',1,0,3))['recovery_events'][0]
  self.assertFalse(e['complete']);self.assertIsNone(e['result']);self.assertIsNone(e['retry'])
 def test_sensing_has_own_schema(self):
  values=[4,1,60,1,4,0,53000,1,23,4000,4000,7,13000,13500,0,1]
  r=decode_touch(b''.join(row('TCHX',1,i,v) for i,v in enumerate(values)))
  self.assertFalse(r['raw_events']);self.assertFalse(r['transport_events']);self.assertFalse(r['recovery_events'])
  e=r['sensing_events'][0];self.assertTrue(e['complete']);self.assertEqual(e['completed_commands'],4)
  self.assertEqual(e['irq_low_polls'],23);self.assertEqual(e['fifo_nonempty'],7)
 def test_partial_sensing_cannot_claim_initialization(self):
  e=decode_touch(row('TCHX',1,0,4))['sensing_events'][0]
  self.assertFalse(e['complete']);self.assertIsNone(e['completed_commands']);self.assertIsNone(e['failure'])
 def sys_page(self,n,offset,data):
  words=struct.unpack('<11Q',data.ljust(88,b'\0'))
  return b''.join(row('TCHX',n,i,v) for i,v in enumerate([5,n,0,offset,len(data),*words]))
 def sys_data(self):
  data=bytearray(208);data[0:2]=bytes([0xa5,1]);struct.pack_into('<HHH',data,16,0x128,0x4053,0x4b)
  data[28:31]=bytes([5,6,7]);data[32:35]=bytes([0xaa,0xbb,0xcc]);struct.pack_into('<HH',data,80,1080,2340)
  data[84:86]=bytes([32,18]);return bytes(data)
 def test_system_info_pages_and_offsets(self):
  data=self.sys_data();wire=b''.join(self.sys_page(n,offset,data[offset:offset+88]) for n,offset in enumerate([176,0,88],1))
  s=decode_touch(wire)['system_info'];self.assertTrue(s['complete']);self.assertTrue(s['valid'])
  self.assertEqual((s['fw'],s['svn'],s['config']),(0x128,0x4053,0x4b));self.assertEqual((s['cfg_afe'],s['cx_afe'],s['panel_afe']),(5,6,7))
  self.assertEqual((s['res_x'],s['res_y'],s['tx'],s['rx']),(1080,2340,32,18))
 def test_missing_system_info_page(self):
  s=decode_touch(self.sys_page(1,0,self.sys_data()[:88]))['system_info'];self.assertFalse(s['complete']);self.assertFalse(s['valid']);self.assertNotIn('fw',s)
 def test_system_info_conflict(self):
  data=self.sys_data();wire=self.sys_page(1,0,data[:88])+self.sys_page(2,0,b'X'+data[1:88])
  self.assertEqual(decode_touch(wire)['system_info']['reason'],'conflicting pages')
 def test_system_info_bad_range(self):
  p=decode_touch(self.sys_page(1,200,b'X'*16))['sysinfo_pages'][0];self.assertFalse(p['valid_range']);self.assertIsNone(p['data'])
 def test_partial_page_cannot_become_system_info(self):
  r=decode_touch(row('TCHX',1,0,5));self.assertIsNone(r['sysinfo_pages'][0]['data']);self.assertFalse(r['system_info']['valid'])
 def test_controller_metadata_and_irq_are_separate(self):
  values=[6,1,0,7,0,208,0x1fff,0,3,1,0xc3,2,0x4b0128,0x4053,0x070605,120000]
  r=decode_touch(b''.join(row('TCHX',1,i,v) for i,v in enumerate(values)));self.assertEqual(r['controller_checks'][0]['crc_error_bits'],3)
  self.assertFalse(r['system_info']['complete']) # Success flags cannot manufacture missing bytes.
  values=[7,2,60,3,4,5000,1,1,0xc3,0xc3,0,1,5004,5000,8,13000]
  r=decode_touch(b''.join(row('TCHX',2,i,v) for i,v in enumerate(values)));self.assertEqual(r['irq_events'][0]['transitions'],3)
 def test_controller_crc_event_classification(self):
  raw=struct.unpack('<Q',bytes([0xf3,0xa0,0,0,0,0,0,0]))[0]
  values=[1,1,0,3,raw,7,4,0,0,0,0,0,0,0,0,0]
  e=decode_touch(b''.join(row('TCHX',1,i,v) for i,v in enumerate(values)))['raw_events'][0]
  self.assertEqual(e['controller_crc_error'],'cx_header')
 def test_signed_frame_sample_and_valid_mask(self):
  words=struct.unpack('<6Q',struct.pack('<24h',*range(-12,12)))
  values=[8,1,5,1,9,3,0x8d78,0x8878,0x88b6,*words,12000]
  r=decode_touch(b''.join(row('TCHX',1,i,v) for i,v in enumerate(values)))
  self.assertFalse(r['raw_events']);e=r['frame_samples'][0]
  self.assertTrue(e['complete']);self.assertTrue(e['rolling_sample'])
  self.assertEqual(e['ms_nodes'],list(range(-12,-4)))
  self.assertEqual(e['ss_tx_nodes'],list(range(-4,4)))
  self.assertIsNone(e['ss_rx_nodes']) # A failed plane never becomes eight fabricated zeros.
 def test_partial_or_invalid_frame_mask_never_publishes_nodes(self):
  values=[8,1,5,1,0,8,0x8d78,0x8878,0x88b6,0,0,0,0,0,0,0]
  for wire in (row('TCHX',1,0,8),b''.join(row('TCHX',1,i,v) for i,v in enumerate(values))):
   e=decode_touch(wire)['frame_samples'][0]
   for plane in ('ms','ss_tx','ss_rx'):self.assertIsNone(e[plane+'_nodes'])
 def test_reset_bringup_power_reads_require_valid_bits(self):
  values=[9,1,0,2,1,0,10050,15,128,128,1800,512,3,512,3,1]
  e=decode_touch(b''.join(row('TCHX',1,i,v) for i,v in enumerate(values)))['bringup_events'][0]
  self.assertTrue(e['supply_enabled']);self.assertTrue(e['supply_ready']);self.assertEqual(e['supply_mv'],1800)
  for mask in (0,4,8,16):
   values[7]=mask;e=decode_touch(b''.join(row('TCHX',1,i,v) for i,v in enumerate(values)))['bringup_events'][0]
   self.assertIsNone(e['supply_enabled']);self.assertIsNone(e['supply_ready']);self.assertIsNone(e['supply_mv'])
  e=decode_touch(row('TCHX',1,0,9))['bringup_events'][0];self.assertIsNone(e['supply_enabled']);self.assertIsNone(e['supply_mv'])
 def test_frozen_probe_metadata_and_failed_restore(self):
  values=[10,1,30,2,3,255,0,0,0,0,0,7,280000,1,1,0]
  frame=[8,2,30,2,0,7,0x8d78,0x8878,0x88b6,0,0,0,0,0,0,280000]
  wire=lambda tag,n,values:b''.join(row(tag,n,i,v) for i,v in enumerate(values))
  d=decode_touch(wire('TCHX',1,values)+wire('TCHX',2,frame));self.assertTrue(d['frame_probes'][0]['normal_mode_writes_succeeded'])
  self.assertFalse(d['frame_samples'][0]['rolling_sample']);self.assertEqual(d['frame_samples'][0]['sampling_mode'],'locked_frozen')
  values[10]=12;d=decode_touch(wire('TCHX',1,values));self.assertFalse(d['frame_probes'][0]['normal_mode_writes_succeeded'])
  e=decode_touch(row('TCHX',1,0,10))['frame_probes'][0];self.assertIsNone(e['normal_mode_writes_succeeded'])
 def test_sync_header_count_and_partial_records(self):
  before=int.from_bytes(bytes([0xa5,1,0xff,0xff,0,0,0,0]),'little')
  after=int.from_bytes(bytes([0xa5,0x30,0,0,0,0,0,0]),'little')
  values=[11,1,30,2,0,7,65535,0,1,0,0,before,after,15000,7,300]
  wire=lambda values:b''.join(row('TCHX',1,i,v) for i,v in enumerate(values))
  e=decode_touch(wire(values))['sync_frames'][0]
  self.assertTrue(e['host_data_loaded']);self.assertFalse(e['analog_scan_verified'])
  values[7]=1;self.assertFalse(decode_touch(wire(values))['sync_frames'][0]['host_data_loaded'])
  e=decode_touch(row('TCHX',1,0,11))['sync_frames'][0];self.assertIsNone(e['host_data_loaded'])
 def test_force_cal_is_status_not_fatal(self):
  raw=int.from_bytes(bytes([0x43,5,1,0,0,0,0,1]),'little')
  values=[1,1,0,0,raw,7,6,0,0,0,0,0,0,0,0,0]
  e=decode_touch(b''.join(row('TCHX',1,i,v) for i,v in enumerate(values)))['raw_events'][0]
  self.assertEqual(e['controller_status'],'mutual_negative_force_cal');self.assertNotIn('driver_stop_reason',e)
 def test_power_cycle_digital_not_analog_proof(self):
  values=[12,1,0,1,0,15,35100,512,2,512,2,0,3,20,15,0]
  wire=lambda values:b''.join(row('TCHX',1,i,v) for i,v in enumerate(values))
  e=decode_touch(wire(values))['power_cycles'][0]
  self.assertTrue(e['digital_sequence_verified']);self.assertFalse(e['analog_voltage_measured'])
  for i,v in [(3,0),(4,1),(5,7),(6,34000),(11,2),(12,2)]:
   bad=values.copy();bad[i]=v;self.assertFalse(decode_touch(wire(bad))['power_cycles'][0]['digital_sequence_verified'])
  self.assertIsNone(decode_touch(row('TCHX',1,0,12))['power_cycles'][0]['digital_sequence_verified'])
 def test_hardware_probe_partial_and_failed_reads(self):
  values=[13,1,5,1,0,1,0x203,0x20080000,0x20080000,0,0,0,255,0x0012020141413936,25,15000]
  wire=lambda values:b''.join(row('TCHX',1,i,v) for i,v in enumerate(values))
  e=decode_touch(wire(values))['hardware_probes'][0]
  self.assertEqual((e['chip_id_lo'],e['chip_id_hi'],e['ier']),(0x36,0x39,0x41));self.assertEqual(e['geni_protocol'],2)
  self.assertTrue(e['geni_gsi_only']);self.assertFalse(e['analog_scan_verified'])
  values[11]=7;values[12]=3;e=decode_touch(wire(values))['hardware_probes'][0]
  self.assertEqual(e['chip_id_hi'],0x39);self.assertIsNone(e['ier'])
  values[12]=256;e=decode_touch(wire(values))['hardware_probes'][0];self.assertIsNone(e['chip_id_lo'])
  e=decode_touch(row('TCHX',1,0,13))['hardware_probes'][0];self.assertIsNone(e['ier']);self.assertIsNone(e['geni_gsi_only'])
 def test_smmu_inventory_distinguishes_disabled_nonzero_and_missing(self):
  values=[17,1,0,0,0x4c017e57,0x6000004a,0x1222,72,0xe0,0x10,0x200,0,0,0xffffffffffffffff,0x3ff,0x500000004]
  e=decode_touch(b''.join(row('TCHX',1,i,v) for i,v in enumerate(values)))['gpi_smmu'][0]
  self.assertTrue(e['complete']);self.assertEqual(e['selected_bank'],72)
  self.assertEqual(e['selected_sctlr'],0xe0);self.assertEqual(e['enabled_lo'],0);self.assertEqual(e['nonzero_hi'],0x3ff)
  e=decode_touch(row('TCHX',1,0,17))['gpi_smmu'][0]
  self.assertFalse(e['complete']);self.assertIsNone(e['selected_bank']);self.assertIsNone(e['result'])
 def test_scan_probe_missing_and_failed_reads_do_not_become_zero(self):
  values=[18,1,30,2,0,31,0xdc00,0x04f90000004e,0x0008211000280000,0x7700000000000000,0x060023a8,8,0x100000004,5,(99<<32)|12,(2000<<16)|0x107]
  wire=lambda values:b''.join(row('TCHX',1,i,v) for i,v in enumerate(values))
  e=decode_touch(wire(values))['scan_probes'][0]
  self.assertEqual(e['frame_counter'],0x23a8);self.assertEqual(e['timers_bytes'],'4e 00 00 00 f9 04')
  self.assertEqual(e['supply_mode'],7);self.assertEqual((e['te_high_polls'],e['te_low_polls']),(12,99))
  self.assertFalse(e['te_pulse_absence_proven'])
  for mask in (0,15,32):
   bad=values.copy();bad[4]=7;bad[5]=mask
   self.assertIsNone(decode_touch(wire(bad))['scan_probes'][0]['frame_counter'])
  bad=values.copy();bad[15]=2000<<16
  self.assertIsNone(decode_touch(wire(bad))['scan_probes'][0]['supply_mode'])
  e=decode_touch(row('TCHX',1,0,18))['scan_probes'][0]
  self.assertFalse(e['complete']);self.assertIsNone(e['frame_counter']);self.assertIsNone(e['te_ctl'])
 def test_engine_page_missing_failed_or_out_of_range(self):
  values=[19,1,5,0x20030000,88]+[0x12345678]*11
  wire=lambda x:b''.join(row('TCHX',1,i,v) for i,v in enumerate(x))
  self.assertEqual(len(bytes.fromhex(decode_touch(wire(values))['engine_pages'][0]['data'])),88)
  for address,lr in ((0x20030000,(7<<32)|88),(0x20030000,89),(0x20030001,88)):
   bad=values.copy();bad[3]=address;bad[4]=lr
   self.assertIsNone(decode_touch(wire(bad))['engine_pages'][0]['data'])
  self.assertIsNone(decode_touch(wire(values[:-1]))['engine_pages'][0]['data'])
 def test_data_probe_missing_failure_and_rolling_comparison(self):
  values=[20,1,30,0,0,15,0x59b245348d78,2000]+[0xcb6acb6acb6acb6a]*4+[0]*4
  wire=lambda x:b''.join(row('TCHX',1,i,v) for i,v in enumerate(x))
  e=decode_touch(wire(values))['data_probes'][0]
  self.assertEqual(e['raw_a6_nodes'],[-13462]*8);self.assertTrue(e['raw_alias_equal']);self.assertEqual(e['baseline_address'],0x59b2)
  bad=values.copy();bad[10]=0;e=decode_touch(wire(bad))['data_probes'][0]
  self.assertFalse(e['raw_alias_equal']);self.assertFalse(e['alias_difference_proves_corruption'])
  for mask in (0,1,16):
   bad=values.copy();bad[4]=7;bad[5]=mask;e=decode_touch(wire(bad))['data_probes'][0]
   self.assertIsNone(e['raw_fa_nodes']);self.assertIsNone(e['raw_alias_equal'])
  self.assertIsNone(decode_touch(wire(values[:-1]))['data_probes'][0]['raw_a6_nodes'])
if __name__=='__main__':unittest.main()
