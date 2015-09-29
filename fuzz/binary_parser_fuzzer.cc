#include "binforge/binforge.h"
#include <cstddef>
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
  if (n > 16 * 1024 * 1024)
    return 0;
  binforge::Limits l;
  l.max_sections = 4096;
  l.max_segments = 4096;
  l.max_symbols = 100000;
  l.max_relocations = 100000;
  binforge::Error e;
  auto image = binforge::BinaryParser(l).parse(d, n, e);
  if (image) {
    auto report = binforge::BinaryValidator(l).validate(*image);
    if (!report.valid)
      __builtin_trap();
  }
  return 0;
}
