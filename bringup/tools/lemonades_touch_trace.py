"""Decode CRC-protected FTS wire events and end-to-end HID observations."""
import re,struct,zlib
FIELDS=('version','stage','failure','raw_events','point_events','controller_resets','chip_errors','transport_errors','last_transport_result','last_ack','last_raw',
 'contacts','sequence','queue_overflows','hid_stage','hid_load_result','hid_match_result','hid_resource','hid_starts','hid_attempts','hid_last_result',
 'hid_reports','polls','queued_frames','edge_installed','edge_contacts','edge_from_edge','edge_skipped','frame_sequence','raw_records','seconds','hid_start_failures')
RAW_FIELDS=('version','record','seconds','decode_result','raw','ack','stage','frame_sequence','contacts','contact_mask','id','x','y','transport_errors','queue_overflows','hid_reports')
BUS_FIELDS=('version','record','seconds','result','phase','byte_index','elapsed_us','stop_result','line_levels','ack','geni_status','pins_power_valid','consecutive_failures','contacts_cancelled','max_clock_gap_us','retry')
RECOVERY_FIELDS=('version','record','seconds','result','pulses','elapsed_us','lines_before','lines_after','failed_phase','failed_byte','irq_level','pins_power_valid','geni_status','consecutive_failures','contacts_cancelled','retry')
SENSING_FIELDS=('version','record','seconds','sensing_runs','completed_commands','failure','sensing_elapsed_us','irq_level','irq_low_polls','irq_high_polls','fifo_empty','fifo_nonempty','last_transaction_us','max_read_us','irq_gpio_ctl','irq_gpio_io')
SYS_PAGE_FIELDS=('version','record','seconds','offset','length')+tuple('word'+str(i) for i in range(11))
CHECK_FIELDS=('version','record','seconds','flags','sysinfo_result','sysinfo_bytes','sysinfo_chunk_mask','crc_result','crc_raw','irq_ctl_before','irq_ctl_after','irq_transitions','config_fw','svn','afe_versions','elapsed_us')
IRQ_FIELDS=('version','record','seconds','transitions','low_polls','high_polls','level','ctl_before','ctl_expected','ctl_current','geni_status','power_pins_valid','polls','fifo_empty','fifo_nonempty','max_read_us')
FRAME_FIELDS=('version','record','seconds','sample','result','valid_mask','ms_address','ss_tx_address','ss_rx_address','ms_word0','ms_word1','ss_tx_word0','ss_tx_word1','ss_rx_word0','ss_rx_word1','elapsed_us')
BRINGUP_FIELDS=('version','record','seconds','phase','reset_count','result','elapsed_us','pmic_valid_mask','supply_enable_raw','supply_status_raw','supply_mv_raw','reset_ctl','reset_io','avdd_ctl','avdd_io','irq_io')
PROBE_FIELDS=('version','record','seconds','sample','requested_mode','flags','start_result','off_result','frame_result','restore_on_result','restore_gesture_result','valid_mask','elapsed_us','restore_allowed','power_pins_valid','geni_status')
SYNC_FIELDS=('version','record','seconds','sample','result','flags','before_count','after_count','polls','read_result','write_result','before_word','after_word','elapsed_us','last_clock_gap_us','idle_fifo_reads')
POWER_FIELDS=('version','record','seconds','enabled','result','flags','elapsed_us','reset_ctl_before','reset_out_before','avdd_ctl_before','avdd_out_before','low_levels','high_levels','off_ms','settle_ms','geni_status')
HARDWARE_FIELDS=('version','record','seconds','sample','geni_status','fifo_disabled','fw_revision','tx_hw_param','rx_hw_param','clock_control','clock_select','result','valid_mask','register_word','last_clock_gap_us','elapsed_us')
GPI_FIELDS=('version','record','seconds','reason','phase','result','instance','dma_physical','smmu_result','smmu_route','clock_level','transactions','completed_mask','event_pointer','event_status','channel_states')
GPI_HW_FIELDS=('version','record','seconds','geni_status','se_irq','gpi_error','global_irq','general_irq','smmu_global_fault','smmu_context_fault','gcc_vote','rcg_config','dfs_enabled','se_clock_branch','all_channel_states','all_event_states')
GPI_CLOCK_FIELDS=('version','record','seconds','step','result','vote','ahb_branches','core_branches','dfs_levels01','dfs_levels23','dfs_levels45','dfs_levels67','rcg_command','rcg_config','dfs_enabled','selected_level')
GPI_SMMU_FIELDS=('version','record','seconds','result','id0','id1','id2','selected_bank','selected_sctlr','used_lo','used_hi','enabled_lo','enabled_hi','nonzero_lo','nonzero_hi','slots')
SCAN_FIELDS=('version','record','seconds','sample','result','valid_mask','clock_word','timers_word','engine_word','scan_flags_word','frame_word0','frame_word1','te_pin_word','te_transitions','te_polls_word','supply_mode_timing_word')
EXTRA_SCHEMAS={17:('gpi_smmu',GPI_SMMU_FIELDS),16:('gpi_clocks',GPI_CLOCK_FIELDS),15:('gpi_hardware',GPI_HW_FIELDS),14:('gpi_events',GPI_FIELDS),5:('sysinfo_pages',SYS_PAGE_FIELDS),6:('controller_checks',CHECK_FIELDS),7:('irq_events',IRQ_FIELDS),8:('frame_samples',FRAME_FIELDS),9:('bringup_events',BRINGUP_FIELDS),10:('frame_probes',PROBE_FIELDS),11:('sync_frames',SYNC_FIELDS),12:('power_cycles',POWER_FIELDS),13:('hardware_probes',HARDWARE_FIELDS)}
EXTRA_SCHEMAS[18]=('scan_probes',SCAN_FIELDS)
EXTRA_SCHEMAS[19]=('engine_pages',('version','record','seconds','address','length_result')+tuple('word'+str(i) for i in range(11)))
EXTRA_SCHEMAS[20]=('data_probes',('version','record','seconds','plane','result','valid_mask','addresses_word','elapsed_us')+tuple('word'+str(i) for i in range(8)))
EXTRA_SCHEMAS[21]=('full_power_cycles',('version','record','seconds','result','flags','elapsed_us','before_word','off_word','on_word','inherited_enable','supply_sid','reset_ctl','reset_io','avdd_ctl','avdd_io','vote_settled'))
EXTRA_SCHEMAS[22]=('config_pages',('version','record','seconds','sample','block_offset','block_count','result','bytes_read')+tuple('pair'+str(i) for i in range(7))+('elapsed_us',))
EXTRA_SCHEMAS[23]=('native_board',('version','record','seconds','phase','ready_count','check_result','gpio50_ctl','gpio50_io','reset_ctl','reset_io','avdd_ctl','avdd_io','irq_ctl','irq_io','power_cycle_flags','required_ready_count'))
EXTRA_SCHEMAS[24]=('native_modes',('version','record','seconds','phase','mode_result','grip_result','valid_mask','mode_word','grip_word','charge_attempted','charge_result','charge_value','elapsed_us','point_events','hid_reports','irq_level'))
EXTRA_SCHEMAS[25]=('factory_identity',('version','record','seconds','result','flags','before_word','after_word','identity_word','event_word','write_result','read_result','polls','elapsed_us','record_type','reset_count','nvm_writes'))
EXTRA_SCHEMAS[26]=('board_rail',('version','record','seconds','result','valid_mask','sid','pin','base','word0','word1','read_count','elapsed_us','phase','avdd_ctl','avdd_io','writes'))
EXTRA_SCHEMAS[27]=('board_boost_enable',('version','record','seconds','result','read_result','write_result','write_attempts','before','after','flags','elapsed_us','apid','owner','channel','delay_us','nvm_writes'))
def assemble_sysinfo(pages):
    data=bytearray(208);known=set()
    for p in pages:
        if not p.get('complete') or not p.get('valid_range') or p.get('data') is None:
            return dict(complete=False,valid=False,reason='missing or invalid page')
        for offset,value in enumerate(bytes.fromhex(p['data']),p['offset']):
            if offset in known and data[offset]!=value:return dict(complete=False,valid=False,reason='conflicting pages')
            data[offset]=value;known.add(offset)
    if len(known)!=208:return dict(complete=False,valid=False,reason='incomplete 208-byte coverage',bytes_covered=len(known))
    out=dict(complete=True,valid=data[0]==0xa5 and data[1]==1,signature=data[0],data_id=data[1],data=data.hex(' '))
    if not out['valid']:return out
    for key,offset in dict(chip0=10,chip1=14,fw=16,svn=18,config=20,cx=24,res_x=80,res_y=82,ms_raw=136,ss_tx_raw=144,ss_rx_raw=152).items():
        out[key]=struct.unpack_from('<H',data,offset)[0]
    out.update(cfg_afe=data[28],cx_afe=data[29],panel_afe=data[30],protocol=data[31],tx=data[84],rx=data[85])
    return out
def decode_touch(data):
    groups={};valid=bad=0
    for row in re.findall(rb'\nUMI (TOUC|TCHX) ([0-9a-f]{2}) ([0-9a-f]{2}) ([0-9a-f]{16}) ([0-9a-f]{8})\n',data):
        tag=row[0].decode();event,field,value,crc=(int(x,16) for x in row[1:]);count=32 if tag=='TOUC' else 16
        if not 1<=event<=255 or field>=count or zlib.crc32(struct.pack('<BBQ',event,field,value))!=crc:bad+=1;continue
        valid+=1;groups.setdefault((tag,event),{}).setdefault(field,set()).add(value)
    out=dict(engine_pages=[],data_probes=[],scan_probes=[],gpi_smmu=[],gpi_clocks=[],gpi_events=[],gpi_hardware=[],snapshots=[],raw_events=[],transport_events=[],recovery_events=[],sensing_events=[],sysinfo_pages=[],controller_checks=[],irq_events=[],frame_samples=[],bringup_events=[],frame_probes=[],sync_frames=[],power_cycles=[],hardware_probes=[],crc_valid_records=valid,crc_rejected_records=bad,conflicts=[])
    out['full_power_cycles']=[]
    out['config_pages']=[]
    out['native_board']=[]
    out['native_modes']=[]
    out['factory_identity']=[]
    out['board_rail']=[]
    out['board_boost_enable']=[]
    for (tag,event),fields in sorted(groups.items()):
        if any(len(v)!=1 for v in fields.values()):out['conflicts'].append([tag,event]);continue
        v={i:next(iter(x)) for i,x in fields.items()};names=FIELDS if tag=='TOUC' else RAW_FIELDS
        bus=tag=='TCHX' and v.get(0)==2
        recovery=tag=='TCHX' and v.get(0)==3
        sensing=tag=='TCHX' and v.get(0)==4
        extra=EXTRA_SCHEMAS.get(v.get(0)) if tag=='TCHX' else None
        if extra:names=extra[1]
        elif sensing:names=SENSING_FIELDS
        elif recovery:names=RECOVERY_FIELDS
        elif bus:names=BUS_FIELDS
        elif v.get(0)!=1:continue
        r=dict(record=event,complete=len(v)==len(names),missing_fields=sorted(set(range(len(names)))-set(v)))
        r.update({name:v.get(i) for i,name in enumerate(names)})
        if extra:
            if v[0]==27:
                valid=False
                if r['complete']:
                    written=(r['write_attempts']==1 and r['before']==0 and r['flags']==7 and r['apid']<512 and r['owner']==0 and r['channel']==0x0c600000+r['apid']*0x10000)
                    inherited=(r['write_attempts']==0 and r['before']==0x80 and r['flags']==15 and r['apid']==512 and r['owner']==7 and r['channel']==0)
                    valid=(r['result']==r['read_result']==r['write_result']==0 and r['after']==0x80 and r['delay_us']==4000 and r['nvm_writes']==0 and (written or inherited))
                r['enable_readback_verified']=valid if r['complete'] else None
                r['analog_voltage_measured']=False
                r['touch_fix_verified']=False
            if v[0]==26:
                known=(r['complete'] and r['result']==0 and r['valid_mask']==4095 and r['sid']==2 and r['pin']==5 and r['base']==0xc400 and r['read_count']==12 and r['writes']==0 and r['word1']>>32==0)
                data=struct.pack('<QQ',r['word0'],r['word1'])[:12] if known else None
                for i,name in enumerate(('pmic_type','pmic_model','gpio_type','gpio_subtype','rt_status','mode_ctl','vin_ctl','pull_ctl','in_ctl','out_source_ctl','out_ctl','enable_ctl')):
                    r[name]=data[i] if data is not None else None
                lv=known and data[2]==0x10 and data[3] in (0x10,0x11)
                r['boost_pin_output_high']=(bool(data[11]&0x80) and data[5]&3 in (1,2) and data[9]&15==0 and bool(data[9]&0x80)) if lv else None
                r['analog_voltage_measured']=False
                r['fts_supply_connection_proven']=False
            if v[0]==25:
                r['identity_bytes']=struct.pack('<Q',r['identity_word']).hex(' ') if r['complete'] and r['flags']&8 else None
                if r['complete']:
                    before=struct.pack('<Q',r['before_word']);after=struct.pack('<Q',r['after_word']);event=struct.pack('<Q',r['event_word'])
                    count=int.from_bytes(before[2:4],'little');next_count=int.from_bytes(after[2:4],'little')
                    r['native_identity_verified']=(r['result']==0 and r['flags']==63 and r['write_result']==r['read_result']==0 and 0<r['polls']<=50 and r['record_type']==0x70 and r['reset_count']==1 and r['nvm_writes']==0 and before[0]==0xa5 and before[4:]==bytes(4) and after[:2]==bytes([0xa5,0x70]) and after[4]==0 and next_count==(count+1)&65535 and event[:5]==bytes.fromhex('43 01 a4 06 70') and r['identity_bytes']=='53 42 32 01 74 02 32 01')
                else:r['native_identity_verified']=None
            if v[0]==24:
                known=r['complete'] and 0<=r['valid_mask']<=3
                for bit,name in enumerate(('mode','grip')):
                    word=r[name+'_word']
                    valid=known and bool(r['valid_mask']&(1<<bit)) and r[name+'_result']==0 and word>>56==0
                    r[name+'_bytes']=word.to_bytes(8,'little')[:7].hex(' ') if valid else None
                r['mode_matches_recovery']=(r['mode_bytes']=='00 00 64 0f 02 0e 01') if r['mode_bytes'] is not None else None
                r['grip_matches_recovery']=(r['grip_bytes']=='00 ff 00 00 00 00 00') if r['grip_bytes'] is not None else None
                r['charge_command_completed']=(r['charge_attempted']==1 and r['charge_result']==0 and r['charge_value']==0) if r['complete'] else None
                r['phone_charging_state_measured']=False
                r['touch_fix_verified']=False
            if v[0]==23:
                ctl=r['gpio50_ctl'];io=r['gpio50_io'];known=r['complete']
                r['gpio50_function']=(ctl>>2)&15 if known else None
                r['gpio50_output_enabled']=bool(ctl&0x200) if known else None
                r['gpio50_output_latch_high']=bool(io&2) if known else None
                r['gpio50_input_high']=bool(io&1) if known else None
                r['gpio50_native_output_high']=(not (ctl&0x3c) and bool(ctl&0x200) and io&3==3 and (not ctl&0x800 or bool(ctl&0x1000))) if known else None
                r['startup_three_ready_verified']=(r['phase']==3 and r['ready_count']==r['required_ready_count']==3 and r['check_result']==0 and r['power_cycle_flags']==0) if known else None
                r['gpio50_written']=False
                r['analog_voltage_measured']=False
            if v[0]==22:
                r['valid_range']=bool(r['complete'] and r['block_count']<=14 and r['block_offset']<=52 and r['block_offset']+r['block_count']<=r['bytes_read']//64<=52 and r['bytes_read']%64==0)
                r['crc32_blocks']=[(r['pair'+str(i//2)]>>((i%2)*32))&0xffffffff for i in range(r['block_count'])] if r['valid_range'] else None
                r['sweep_completed']=bool(r['valid_range'] and r['result']==0 and r['bytes_read']==3328)
                r['bytewise_identity_proven']=False
            if v[0]==21:
                for name in ('before','off','on'):
                    word=r[name+'_word'];known=r['complete'] and word is not None and (word>>32)&255==15 and word>>40==0
                    r[name+'_enable']=word&255 if known else None
                    r[name+'_ready']=bool(word&0x8000) if known else None
                    r[name+'_mv']=((word>>16)&65535) if known and word&0x8000 else None
                r['supply_cycle_verified']=(r['result']==0 and r['flags']==127 and r['inherited_enable']==0 and r['vote_settled']==1 and r['before_enable']==128 and r['before_ready'] and r['off_enable']==0 and r['off_ready'] is False and r['on_enable']==128 and r['on_ready'] and r['on_mv']==1800 and r['elapsed_us']>=50000 and r['reset_io']&3==3 and r['avdd_io']&3==3) if r['complete'] else None
                r['analog_voltage_measured']=False
            if v[0]==19:
                r['length']=r['length_result']&0xffffffff if r['length_result'] is not None else None
                r['result']=r['length_result']>>32 if r['length_result'] is not None else None
                r['valid_range']=(r['address'],r['length']) in ((0x20030000,88),(0x20030058,76))
                r['data']=b''.join(struct.pack('<Q',r['word'+str(i)]) for i in range(11))[:r['length']].hex(' ') if r['complete'] and r['valid_range'] and r['result']==0 else None
                r['asynchronous_read_only_sample']=True
            if v[0]==20:
                mask=r['valid_mask'];known=r['complete'] and r['plane'] in (0,1,2) and mask is not None and 0<=mask<=15
                for bit,name in enumerate(('raw_a6','raw_fa','filtered','baseline')):
                    r[name+'_nodes']=list(struct.unpack('<8h',struct.pack('<QQ',r['word'+str(bit*2)],r['word'+str(bit*2+1)]))) if known and mask&(1<<bit) else None
                for i,name in enumerate(('raw','filtered','baseline')):
                    r[name+'_address']=(r['addresses_word']>>(i*16))&0xffff if known else None
                r['raw_alias_equal']=r['raw_a6_nodes']==r['raw_fa_nodes'] if known and mask&3==3 else None
                r['asynchronous_read_only_sample']=True
                r['alias_difference_proves_corruption']=False
            if v[0]==18:
                mask=r['valid_mask'];known=r['complete'] and mask is not None and 0<=mask<=31
                for bit,(name,fields,length) in enumerate((('clock',['clock_word'],2),('timers',['timers_word'],6),('engine',['engine_word'],8),('scan_flags',['scan_flags_word'],8),('frame',['frame_word0','frame_word1'],16))):
                    r[name+'_bytes']=b''.join(struct.pack('<Q',r[f]) for f in fields)[:length].hex(' ') if known and mask&(1<<bit) else None
                r['frame_counter']=r['frame_word0']&0xffff if known and mask&16 else None
                r['te_ctl']=r['te_pin_word']&0xffffffff if r['complete'] else None
                r['te_io']=r['te_pin_word']>>32 if r['complete'] else None
                r['te_high_polls']=r['te_polls_word']&0xffffffff if r['complete'] else None
                r['te_low_polls']=r['te_polls_word']>>32 if r['complete'] else None
                r['supply_mode']=r['supply_mode_timing_word']&255 if r['complete'] and r['supply_mode_timing_word']&256 else None
                r['elapsed_us']=r['supply_mode_timing_word']>>16 if r['complete'] else None
                r['asynchronous_read_only_sample']=True
                r['te_pulse_absence_proven']=False
            if v[0]==5:
                r['valid_range']=r['offset'] is not None and r['length'] is not None and 0<=r['offset']<208 and 0<r['length']<=88 and r['offset']+r['length']<=208
                r['data']=b''.join(struct.pack('<Q',v[i]) for i in range(5,16))[:r['length']].hex(' ') if r['complete'] and r['valid_range'] else None
            if v[0]==6 and r['complete'] and r['crc_result']==0 and r['flags']&4 and 0<=r['crc_raw']<=255:
                r['crc_error_bits']=r['crc_raw']&3
            if v[0]==8:
                r['rolling_sample']=True
                mask=r['valid_mask'];r['valid_mask_range']=mask is not None and 0<=mask<=7
                for i,plane in enumerate(('ms','ss_tx','ss_rx')):
                    r[plane+'_nodes']=list(struct.unpack('<8h',struct.pack('<QQ',r[plane+'_word0'],r[plane+'_word1']))) if r['complete'] and r['valid_mask_range'] and mask&(1<<i) else None
            if v[0]==9:
                r['reset_method']='software' if r['phase']==0x102 else 'gpio' if r['phase']==2 else None
                mask=r['pmic_valid_mask'];valid=r['complete'] and mask is not None and 0<=mask<=15
                r['supply_enabled']=bool(r['supply_enable_raw']&0x80) if valid and mask&1 else None
                r['supply_ready']=bool(r['supply_status_raw']&0x80) if valid and mask&2 else None
                r['supply_mv']=r['supply_mv_raw'] if valid and mask&12==12 else None
            if v[0]==10:
                r['normal_mode_writes_succeeded']=(r['flags']&48==48 and r['restore_on_result']==r['restore_gesture_result']==0) if r['complete'] else None
            if v[0]==12:
                r['digital_sequence_verified']=(r['enabled']==1 and r['result']==0 and r['flags']==15 and r['low_levels']==0 and r['high_levels']==3 and r['off_ms']==20 and r['settle_ms']==15 and r['elapsed_us']>=35000) if r['complete'] else None
                r['analog_voltage_measured']=False
            if v[0]==13:
                mask=r['valid_mask'];known=r['complete'] and mask is not None and 0<=mask<=255
                for n,key in enumerate(('chip_id_lo','chip_id_hi','ier','icr','gpio_input','gpio_direction','boot_option','crc')):
                    r[key]=((r['register_word']>>(n*8))&255) if known and mask&(1<<n) else None
                r['geni_gsi_only']=bool(r['fifo_disabled']) if r['complete'] else None
                r['geni_protocol']=((r['fw_revision']>>8)&255) if r['complete'] else None
                r['analog_scan_verified']=False
            if v[0]==11:
                before=struct.pack('<Q',r['before_word']) if r['before_word'] is not None else None
                after=struct.pack('<Q',r['after_word']) if r['after_word'] is not None else None
                r['before_header']=before.hex(' ') if before is not None else None
                r['after_header']=after.hex(' ') if after is not None else None
                r['host_data_loaded']=None
                if r['complete']:
                    r['host_data_loaded']=(r['result']==0 and r['flags']==7 and r['read_result']==r['write_result']==0
                        and before[0]==0xa5 and after[:2]==b'\xa5\x30'
                        and r['before_count']==int.from_bytes(before[2:4],'little')
                        and r['after_count']==int.from_bytes(after[2:4],'little') and r['before_count']!=r['after_count'])
                r['analog_scan_verified']=False
            out[extra[0]].append(r);continue
        if bus or recovery or sensing:
            out['sensing_events' if sensing else 'recovery_events' if recovery else 'transport_events'].append(r);continue
        raw='last_raw' if tag=='TOUC' else 'raw'
        if r[raw] is not None:r[raw]=struct.pack('<Q',r[raw]).hex(' ')
        if tag=='TCHX' and r['decode_result'] is not None and r['decode_result']&0x100:
            r['driver_stop_reason']=r['decode_result']&0xff
        if tag=='TCHX' and r['decode_result']==5:r['waiting_for_ready']=True
        if tag=='TCHX' and r[raw] is not None:
            e=bytes.fromhex(r[raw]);crc_errors={0x20:'config_header',0x21:'config',0x22:'panel_header',0x23:'panel',0xa0:'cx_header',0xa1:'cx',0xa5:'cx_sub_header',0xa6:'cx_sub'}
            if e[0]==0xf3 and e[1] in crc_errors:r['controller_crc_error']=crc_errors[e[1]]
            if e[:3]==bytes([0x43,5,1]):r['controller_status']='mutual_negative_force_cal' # Also seen in working Recovery; not a fatal error.
        out['snapshots' if tag=='TOUC' else 'raw_events'].append(r)
    out['system_info']=assemble_sysinfo(out['sysinfo_pages'])
    for p in out['frame_probes']:
        if not p['complete'] or p['requested_mode'] not in (0,3) or not p['flags']&4 or p['off_result']!=0:continue
        for f in out['frame_samples']:
            if f['sample']==p['sample']:
                f['rolling_sample']=False;f['sampling_mode']='normal_frozen' if p['requested_mode']==0 else 'locked_frozen'
    return out
