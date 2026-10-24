// SPDX-License-Identifier: MIT
// Bounded ramoops records. Caller supplies serialization and a frozen snapshot.
#ifndef LEMONADES_RUNTIME_WIRE_H
#define LEMONADES_RUNTIME_WIRE_H
#define LEMONADES_RUNTIME_FIELDS 248
#define LEMONADES_RUNTIME_SAMPLES 8
static int lemonades_runtime_write(volatile uint32_t *header,unsigned sample,
                             const uint64_t values[LEMONADES_RUNTIME_FIELDS]) {
  const uint32_t capacity=0x200000-12;
  if(!header || sample<1 || sample>LEMONADES_RUNTIME_SAMPLES || header[0]!=0x43474244 ||
     header[1]>capacity || header[2]>capacity || header[1]>header[2])return 0;
  uint32_t at=header[1]==capacity?0:header[1],size=header[2];
  volatile unsigned char *out=(volatile unsigned char *)(header+3);
  const char hex[]="0123456789abcdef";
  for(unsigned copy=0;copy<5;++copy)for(unsigned field=0;field<LEMONADES_RUNTIME_FIELDS;++field) {
    uint64_t value=values[field];uint32_t crc=0xffffffff;
    for(unsigned i=0;i<10;++i) {
      unsigned byte=i==0?sample:i==1?field:(value>>((i-2)*8))&255;
      crc^=byte;for(unsigned j=0;j<8;++j)crc=(crc>>1)^(0xedb88320u&(0u-(crc&1)));
    }
    crc^=0xffffffff;
    char row[42]="\nUMI LIVE ";unsigned n=10;
    row[n++]=hex[sample>>4];row[n++]=hex[sample&15];row[n++]=' ';
    row[n++]=hex[field>>4];row[n++]=hex[field&15];row[n++]=' ';
    for(int shift=60;shift>=0;shift-=4)row[n++]=hex[(value>>shift)&15];row[n++]=' ';
    for(int shift=28;shift>=0;shift-=4)row[n++]=hex[(crc>>shift)&15];row[n++]='\n';
    for(unsigned i=0;i<n;++i) {out[at]=row[i];at=at+1==capacity?0:at+1;if(size<capacity)++size;}
  }
  header[2]=size;header[1]=at;
  return 1;
}
#endif
