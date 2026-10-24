#!/usr/bin/env python3
"""Exercise the real policy initializer across boots and qualify its upstream delta."""
import hashlib,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'devices/lemonades/package/boot-progress/BootWatchdogPolicy.c'
REFERENCE=ROOT/'sources/UniXNU-sheng/package/BootWatchdogPolicy.c'
OUT=ROOT/'out/lemonades/attempt-53-preparation/watchdog-policy'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
OLD=""" // Refuse existing settings and symlinks instead of replacing their contents.
 struct open_args op={.path=scratch,.flags=O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,.mode=0644};"""
NEW=""" // With persistent Data the previous boot's file is there: this policy is rewritten in place on every boot (it must follow the
 // boot arguments). Symlinks are still refused (O_NOFOLLOW) and the fstat check below insists on a root-owned regular file.
 struct open_args op={.path=scratch,.flags=O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW,.mode=0644};"""
def validate_delta():
    old=REFERENCE.read_text();new=SOURCE.read_text()
    if old.count(OLD)!=1 or new!=old.replace(OLD,NEW):
        raise ValueError('Unexpected change outside upstream persistent-policy delta')
    upstream=ROOT/'out/lemonades/attempt-53-preparation/upstream-BootWatchdogPolicy.c'
    if NEW not in upstream.read_text():raise ValueError('Delta missing from saved upstream reference')
    return dict(source_sha256=sha(SOURCE),reference_sha256=sha(REFERENCE),upstream_sha256=sha(upstream),
                upstream_commit='7562a779ebdbdedc17c4c7274ba993acbbec8188',test_sha256=sha(Path(__file__)))
def verify_report():
    expected=validate_delta();report=json.loads((OUT/'report.json').read_text())
    if not report['passed'] or not report['old_initializer_second_boot_failure_reproduced'] or any(report[k]!=v for k,v in expected.items()):
        raise ValueError('Persistent watchdog policy has no matching host qualification')
    return report

PREFIX=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#undef strlcat
#define strlcat k_strlcat
static size_t k_strlcat(char *d,const char *s,size_t n){size_t dl=strnlen(d,n),sl=strlen(s);if(dl==n)return n+sl;size_t c=sl<n-dl-1?sl:n-dl-1;memcpy(d+dl,s,c);d[dl+c]=0;return dl+sl;}
#include <fcntl.h>
#define open k_open
#define write k_write
#define mkdir k_mkdir
#define fchown k_fchown
#define fchmod k_fchmod
#define fsync k_fsync
#define printf(...) ((void)0)
#define stat64 stat
typedef void *proc_t;
#ifndef __APPLE__
typedef uintptr_t user_addr_t;
typedef long user_ssize_t;
#endif
struct mkdir_args {user_addr_t path;int mode;};
struct open_args {user_addr_t path;int flags,mode;};
struct write_args {int fd;user_addr_t cbuf;size_t nbyte;};
struct fchown_args {int fd,uid,gid;};struct fchmod_args {int fd,mode;};
struct fsync_args {int fd;};struct fstat64_args {int fd;user_addr_t ub;};struct close_args {int fd;};
static char job_args[200];static int enabled,calls,opens,closes,md_error,open_error,short_write,chown_error,bad_owner,close_error,marker_exists,plist_exists,write_error,chmod_error,sync_error,stat_error,copyin_error,bad_mode,bad_size;
static unsigned char written_data[1024];static size_t written_size;
static int PE_parse_boot_argn(const char *key,void *out,int n){if(!strcmp(key,"sheng-disable-jobs")){assert(n==200);memcpy(out,job_args,200);return job_args[0]!=0;}assert(!strcmp(key,"sheng-disable-watchdogd")&&n==4);memcpy(out,&enabled,4);return enabled!=0;}
static int copyout(const void *s,uintptr_t d,size_t n){++calls;memcpy((void *)d,s,n);return 0;}
static int copyin(uintptr_t s,void *d,size_t n){++calls;if(copyin_error)return copyin_error;memcpy(d,(void *)s,n);return 0;}
static int k_mkdir(proc_t p,struct mkdir_args *a,int32_t *r){(void)p;(void)r;++calls;assert(!strcmp((char*)a->path,"/private/var/db/com.apple.xpc.launchd")&&a->mode==0755);return md_error;}
static int k_open(proc_t p,struct open_args *a,int32_t *r){
 (void)p;++calls;++opens;assert(a->mode==0644);
 if(strstr((char*)a->path,"disabled.migrated")){
  assert(a->flags==(O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW));
  if(marker_exists)return EEXIST;marker_exists=1;*r=8;return 0;
 }
 assert(strstr((char*)a->path,"/disabled.plist"));
 assert((a->flags&(O_WRONLY|O_CREAT|O_NOFOLLOW))==(O_WRONLY|O_CREAT|O_NOFOLLOW));
 if(open_error)return open_error;
 if(plist_exists && (a->flags&O_EXCL))return EEXIST;
 if(a->flags&O_TRUNC){written_size=0;memset(written_data,0,sizeof(written_data));}
 plist_exists=1;*r=7;return 0;
}
static int k_write(proc_t p,struct write_args *a,user_ssize_t *r){(void)p;++calls;assert(a->fd==7&&a->nbyte<sizeof(written_data));if(write_error)return write_error;written_size=a->nbyte;memcpy(written_data,(void*)a->cbuf,a->nbyte);*r=(user_ssize_t)a->nbyte-short_write;return 0;}
static int k_fchown(proc_t p,struct fchown_args *a,int32_t *r){(void)p;(void)r;++calls;assert(a->fd==7&&!a->uid&&!a->gid);return chown_error;}
static int k_fchmod(proc_t p,struct fchmod_args *a,int32_t *r){(void)p;(void)r;++calls;assert(a->fd==7&&a->mode==0644);return chmod_error;}
static int k_fsync(proc_t p,struct fsync_args *a,int32_t *r){(void)p;(void)r;++calls;assert(a->fd==7);return sync_error;}
static int sys_fstat64(proc_t p,struct fstat64_args *a,int32_t *r){(void)p;(void)r;++calls;assert(a->fd==7);if(stat_error)return stat_error;struct stat st={.st_uid=bad_owner?502:0,.st_gid=0,.st_mode=bad_mode?0040644:0100644,.st_size=(off_t)written_size+bad_size};memcpy((void*)a->ub,&st,sizeof(st));return 0;}
static int sys_close(proc_t p,struct close_args *a,int32_t *r){(void)p;(void)r;++calls;++closes;assert(a->fd==7||a->fd==8);return close_error;}
'''
MAIN=r'''
static unsigned char scratch[4096];
static void reset(void){enabled=1;job_args[0]=0;calls=opens=closes=md_error=open_error=short_write=chown_error=bad_owner=close_error=marker_exists=plist_exists=write_error=chmod_error=sync_error=stat_error=copyin_error=bad_mode=bad_size=0;written_size=0;}
static int run(void){return sheng_boot_watchdog_policy(NULL,(uintptr_t)scratch);}
int main(void){
 reset();enabled=0;assert(!run()&&!calls);
 reset();enabled=0;strcpy(job_args,"com.apple.identityservicesd,com.apple.locationd");assert(!run()&&strstr((char*)written_data,"<key>com.apple.identityservicesd</key><true/><key>com.apple.locationd</key><true/>")&&!strstr((char*)written_data,"watchdogd"));
 reset();strcpy(job_args,"com.apple.locationd");assert(!run()&&strstr((char*)written_data,"watchdogd")&&strstr((char*)written_data,"com.apple.locationd"));
 reset();strcpy(job_args,"bad<label");assert(run()==EINVAL&&!opens);
 reset();memset(job_args,'a',199);assert(!run()&&written_size<sizeof(written_data));
 reset();memset(scratch+0x400,0x5a,0x400);assert(!run()&&!sheng_watchdog_policy_status&&opens==2&&closes==2&&written_size==strlen(policy)&&!memcmp(written_data,policy,written_size));
 for(unsigned i=0x400;i<0x800;++i)assert(scratch[i]==0x5a);
 reset();md_error=EEXIST;assert(!run()&&closes==2);
 reset();md_error=EACCES;assert(run()==EACCES&&!opens);
 reset();open_error=ELOOP;assert(run()==ELOOP&&!written_size&&!closes);
 reset();short_write=1;assert(run()==EIO&&closes==1&&opens==1);
 reset();chown_error=EPERM;assert(run()==EPERM&&closes==1&&opens==1);
 reset();bad_owner=1;assert(run()==EINVAL&&closes==1&&opens==1);
 reset();close_error=EIO;assert(run()==EIO&&closes==1&&opens==1);
 reset();marker_exists=1;assert(!run()&&opens==2&&closes==1);

 /* The old O_EXCL initializer fails this exact second invocation. */
 reset();assert(!run());size_t original_size=written_size;unsigned char original[1024];memcpy(original,written_data,sizeof(original));
 assert(!run()&&written_size==original_size&&!memcmp(original,written_data,original_size));
 assert(opens==4&&closes==3);
 /* A longer persisted policy followed by shorter boot args must truncate the tail. */
 strcpy(job_args,"com.apple.locationd,com.apple.identityservicesd");assert(!run()&&written_size>original_size);
 job_args[0]=0;assert(!run()&&written_size==original_size&&!memcmp(original,written_data,original_size));
 for(size_t i=original_size;i<sizeof(written_data);++i)assert(!written_data[i]);
 reset();write_error=EIO;assert(run()==EIO&&closes==1&&opens==1);
 reset();chmod_error=EPERM;assert(run()==EPERM&&closes==1&&opens==1);
 reset();sync_error=EIO;assert(run()==EIO&&closes==1&&opens==1);
 reset();stat_error=EIO;assert(run()==EIO&&closes==1&&opens==1);
 reset();copyin_error=EFAULT;assert(run()==EFAULT&&closes==1&&opens==1);
 reset();bad_mode=1;assert(run()==EINVAL&&closes==1&&opens==1);
 reset();bad_size=1;assert(run()==EINVAL&&closes==1&&opens==1);
 return 0;
}
'''

def main():
    evidence=validate_delta();OUT.mkdir(parents=True,exist_ok=True)
    for name,path in [('old',REFERENCE),('fixed',SOURCE)]:
        source=path.read_text();body=source[source.index('static const char policy'):]
        (OUT/(name+'.c')).write_text(PREFIX+body+MAIN)
        subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-O1','-g','-fsanitize=address,undefined',str(OUT/(name+'.c')),'-o',str(OUT/name)],check=True,timeout=45)
        result=subprocess.run([str(OUT/name)],capture_output=True,text=True,timeout=10)
        (OUT/(name+'.log')).write_text(result.stdout+result.stderr)
        if name=='old':
            if result.returncode==0 or 'written_size==original_size' not in result.stderr:
                raise ValueError('Old policy did not fail at the repeated boot regression assertion')
        elif result.returncode!=0:raise RuntimeError(result.stderr)
    report=dict(evidence,passed=True,old_initializer_second_boot_failure_reproduced=True,
                sanitizer='address,undefined',syscalls_substituted=True,phone_runtime_verified=False,
                checks=['first_boot','same_Data_second_boot','changed_boot_args_truncation','symlink_rejected','mkdir_error','short_write','write_error','ownership','chmod','fsync','fstat','copyin','file_type','size','close_error','environment_slots_preserved'])
    (OUT/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
