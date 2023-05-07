#include "fuzzer/FuzzedDataProvider.h"
#include <iostream>
#include "pe-parse/parse.h"

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  peparse::parsed_pe* p = peparse::ParsePEFromPointer(data, size);
  peparse::DestructParsedPE(p);
  return 0;
}
