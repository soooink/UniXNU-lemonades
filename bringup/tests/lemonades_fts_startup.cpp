#include <cassert>
#include <cstdio>
#include <initializer_list>
#include "../devices/lemonades/package/touch/LemonadesFtsStartup.h"
int main() {
    // Native NO_INIT is allowed only for complete identity/CRC/AFE evidence.
    LemonadesFtsControllerRead r={};r.bytesRead=208;r.chunkMask=0x1fff;r.crc=0xc0;
    r.bytes[0]=0xa5;r.bytes[1]=1;r.bytes[10]=0x39;r.bytes[11]=0x36;
    r.bytes[16]=0x28;r.bytes[17]=1;r.bytes[18]=0x53;r.bytes[19]=0x40;
    r.bytes[20]=0x4b;r.bytes[28]=r.bytes[29]=r.bytes[30]=5;
    auto identity=lemonades_fts_sysinfo(r.bytes,r.bytesRead);
    assert(!lemonades_fts_native_identity_check(r,identity));
    for(unsigned missing=0;missing<13;++missing){auto failed=r;failed.chunkMask&=~(1U<<missing);
        assert(lemonades_fts_native_identity_check(failed,identity)==1);}
    for(unsigned n=0;n<208;++n){auto failed=r;failed.bytesRead=n;
        assert(lemonades_fts_native_identity_check(failed,identity)==1);}
    {auto failed=r;failed.sysResult=7;assert(lemonades_fts_native_identity_check(failed,identity)==1);}
    {auto failed=identity;failed.valid=false;assert(lemonades_fts_native_identity_check(r,failed)==2);}
    {auto failed=r;failed.crcResult=7;assert(lemonades_fts_native_identity_check(failed,identity)==3);}
    for(unsigned bits=1;bits<=3;++bits){auto failed=r;failed.crc|=bits;
        assert(lemonades_fts_native_identity_check(failed,identity)==4);}
    for(unsigned n=0;n<4;++n){auto failed=identity;
        uint16_t *fields[]={&failed.chip0,&failed.fw,&failed.svn,&failed.config};++*fields[n];
        assert(lemonades_fts_native_identity_check(r,failed)==5);}
    for(unsigned n=0;n<3;++n){auto failed=identity;
        uint8_t *fields[]={&failed.cfgAfe,&failed.cxAfe,&failed.panelAfe};++*fields[n];
        assert(lemonades_fts_native_identity_check(r,failed)==6);}
    for(unsigned error: {0U,1U,2U,12U}){
        unsigned calls=0,waits=0;
        auto result=lemonades_fts_software_reset([&](const uint8_t *w,unsigned n){
            ++calls;const uint8_t expected[]={0xfa,0x20,0,0,0x24,0x80};
            assert(n==sizeof(expected) && !memcmp(w,expected,n));return error;
        },[&](){++waits;});
        assert(result==error && calls==1 && waits==unsigned(error==0));
    }
    LemonadesTouchFrame f{};uint8_t e[8];
    f.points[1]={100,200,1};LemonadesTouchFrame saved=f;
    memset(e,0xff,sizeof(e));
    assert(lemonades_fts_startup_event(&f,e,true,0)==LEMONADES_FTS_WAIT_READY);
    assert(lemonades_fts_startup_event(&f,e,true,99000000)==LEMONADES_FTS_WAIT_READY);
    assert(!memcmp(&f,&saved,sizeof(f)));
    memset(e,0,sizeof(e));e[0]=0x13;e[1]=1;
    assert(lemonades_fts_startup_event(&f,e,true,2000000)==LEMONADES_FTS_WAIT_READY);
    assert(!memcmp(&f,&saved,sizeof(f))); // Never emit pre-READY coordinates.
    e[0]=3;assert(lemonades_fts_startup_event(&f,e,true,4000000)==LEMONADES_FTS_RESET);
    assert(!f.points[1].active);
    e[0]=0x13;assert(lemonades_fts_startup_event(&f,e,false,200000000)==LEMONADES_FTS_POINT);
    memset(e,0xff,sizeof(e));assert(lemonades_fts_startup_event(&f,e,false,0)==LEMONADES_FTS_BAD);
    e[0]=0xf3;assert(lemonades_fts_startup_event(&f,e,true,0)==LEMONADES_FTS_FAULT);
    e[0]=3;saved=f;
    assert(lemonades_fts_startup_event(&f,e,true,100000000)==LEMONADES_FTS_READY_TIMEOUT);
    assert(!memcmp(&f,&saved,sizeof(f)));
    assert(lemonades_fts_ready_expired(UINT64_MAX));
    // All unexpected first bytes are ignored only within the startup window.
    for(unsigned value=0;value<256;++value)if(value!=3&&value!=0xf3) {
        e[0]=(uint8_t)value;assert(lemonades_fts_startup_event(&f,e,true,99999999)==LEMONADES_FTS_WAIT_READY);
        assert(!memcmp(&f,&saved,sizeof(f)));
    }
    puts("PASS: reset-time FF/contact/unknown bytes wait, real READY/errors, deadline boundaries and strict post-READY parser");
}
