// libFuzzer harness for pe-parse: parse an in-memory PE image and destruct it.
#include <cstdint>
#include <cstddef>

#include <pe-parse/parse.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0 || size > (32u << 20)) {
    return 0;
  }
  peparse::parsed_pe *p = peparse::ParsePEFromPointer(
      const_cast<uint8_t *>(data), static_cast<std::uint32_t>(size));
  if (p != nullptr) {
    peparse::DestructParsedPE(p);
  }
  return 0;
}
