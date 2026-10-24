// SPDX-License-Identifier: BSD-2-Clause-Patent
// Actual archived phone GPT + candidate manifest, original production parser.
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/sha.h>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include "RootDiagnostics.h"
using IOReturn=uint32_t;
constexpr IOReturn kIOReturnSuccess=0;
constexpr unsigned kDataMax=131072;
static UfsRootDiagnostics gRootDiagnostic;
static std::ifstream gpt,image;
static IOReturn hostRead4k(uint8_t lun,uint64_t lba,uint32_t blocks,void *out)
{
  if(lun || !blocks || blocks>32) return 1;
  std::ifstream *input;
  uint64_t offset;
  if(lba==0x2c0000 && blocks==1) {input=&image;offset=0;}
  else if(lba>=1 && lba<=64) {input=&gpt;offset=lba*4096;}
  else return 1;
  input->clear(); input->seekg(offset);
  input->read(static_cast<char *>(out),blocks*4096);
  return input->gcount()==blocks*4096?0:1;
}
#include "RootLayout.h"
int main(int argc,char **argv)
{
  assert(argc==3);
  gpt.open(argv[1],std::ios::binary);image.open(argv[2],std::ios::binary);
  assert(gpt && image);
  RootLayout layout;
  const char *why=nullptr;
  if(!findRootLayout(&layout,&why)) {
    fprintf(stderr,"Root parser refused: %s\n",why);return 1;
  }
  assert(layout.manifestStatus==0 && layout.windows==2);
  assert(layout.userdataFirst==0x2c0000 && layout.userdataLast==0x3b51ffa);
  assert(layout.gptHeaderCrc==0x07ecf529 && layout.gptEntriesCrc==0xa6edb1e8);
  assert(!strcmp(layout.window[0].name,"OS") && !strcmp(layout.window[1].name,"SystemOS"));
  assert(layout.window[0].size==6077580800 && layout.window[1].size==3303014400);
  image.clear();image.seekg(0,std::ios::end);
  assert(uint64_t(image.tellg())==layout.imageBytes);
  printf("PASS: original root parser; real lemonades GPT CRCs; actual two-window manifest; %llu bytes\n",
         (unsigned long long)layout.imageBytes);
}
