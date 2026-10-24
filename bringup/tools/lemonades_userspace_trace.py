"""Read individually CRC-validated user diagnostics; retain missing fields explicitly."""
import re,struct,zlib
DATA_FIELDS=('version','sample','seconds','statfs_status','block_size','blocks','free_blocks','available_blocks','files','free_files','supported','readonly',
 'persist_state','persist_header','gpt_before','gpt_after','persist_pages','persist_reads','persist_writes','persist_syncs','persist_errors','persist_present_pages','store_first_lba',
 'logical_bytes','resident_bytes','user_events','user_dropped','enospc','access_errors','readonly_errors','quota_errors','processes')
PATHS=('containers','containers/Data/System','mobile/Containers','db/dslocal/nodes/Default/users','PersonaVolumes','mobile/Library/Preferences','containers/Bundle','containers/Temp')
KINDS={1:'stdout/stderr',2:'open',3:'mkdir',4:'process_exit'}
def signed(n):return n-(1<<32) if n is not None and n & (1<<31) else n
def text_prefix(v,start,count):
    b=bytearray()
    for i in range(start,start+count):
        if i not in v:return b.decode(errors='replace'),False
        part=struct.pack('<Q',v[i]);b.extend(part)
        if b'\0' in part:return b.split(b'\0',1)[0].decode(errors='replace'),True
    return b.decode(errors='replace'),True

def decode_userspace(data):
    groups={};valid=bad=0
    for row in re.findall(rb'\nUMI (DATA|USER) ([0-9a-f]{2}) ([0-9a-f]{2}) ([0-9a-f]{16}) ([0-9a-f]{8})\n',data):
        tag=row[0].decode();event,field,value,crc=(int(x,16) for x in row[1:])
        count=64 if tag=='DATA' else 48
        if not 1<=event<=255 or field>=count or zlib.crc32(struct.pack('<BBQ',event,field,value))!=crc:bad+=1;continue
        valid+=1;groups.setdefault((tag,event),{}).setdefault(field,set()).add(value)
    output={'data_observations':[],'user_events':[],'crc_valid_records':valid,'crc_rejected_records':bad,'conflicts':[]}
    for (tag,event),fields in sorted(groups.items()):
        if any(len(v)!=1 for v in fields.values()):output['conflicts'].append([tag,event]);continue
        v={i:next(iter(x)) for i,x in fields.items()}
        if v.get(0)!=1 or v.get(1)!=event:continue
        count=64 if tag=='DATA' else 48
        result={'record':event,'complete':len(v)==count,'missing_fields':sorted(set(range(count))-set(v))}
        if tag=='DATA':
            result.update({name:v.get(i) for i,name in enumerate(DATA_FIELDS)});result['statfs_status']=signed(result['statfs_status']);result['directories']=[]
            for i,path in enumerate(PATHS):result['directories'].append(dict(path='/private/var/'+path,lookup_status=signed(v.get(32+i*4)),uid=v.get(33+i*4),gid=v.get(34+i*4),mode=v.get(35+i*4)))
            for name,index,bit in [('filesystem_bytes',5,6),('free_bytes',6,7),('available_bytes',7,8)]:
                result[name]=(v[4]*v[index] if v.get(3)==0 and 4 in v and index in v and v.get(10,0)&(1<<4) and v.get(10,0)&(1<<bit) else None)
            output['data_observations'].append(result)
        else:
            name,nok=text_prefix(v,8,4);text,tok=text_prefix(v,12,32)
            result.update(seconds=v.get(2),kind=KINDS.get(v.get(3),'unknown'),pid=v.get(4),error=signed(v.get(5)),aux=v.get(6),copy_error=signed(v.get(7)),name_prefix=name,name_complete=nok,text_prefix=text,text_complete=tok)
            output['user_events'].append(result)
    return output
