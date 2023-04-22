#include "fuzzer/FuzzedDataProvider.h"
#include <iostream>
#include "pe-parse/parse.h"

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  peparse::parsed_pe* p = peparse::ParsePEFromPointer(data, size);
  if (p == nullptr) {
    return -1;
  }
  p->peHeader.dos.e_cblp;
  peparse::DestructParsedPE(p);
  return 0;
}
