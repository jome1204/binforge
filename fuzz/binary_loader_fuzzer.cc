#include "binforge/binforge.h"
#include <cstddef>
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
  if (n > 8 * 1024 * 1024)
    return 0;
  binforge::Limits l;
  l.max_mapped_bytes = 32 * 1024 * 1024;
  l.max_sections = 2048;
  l.max_segments = 2048;
  binforge::Error e;
  auto image = binforge::BinaryParser(l).parse(d, n, e);
  if (image) {
    binforge::AddressSpace memory(l);
    binforge::LoadOptions options;
    options.preferred_base = n ? uint64_t(d[n - 1] & 0x7f) * 0x10000 : 0;
    options.resolve_imports = false;
    binforge::BinaryLoader(l).load(*image, memory, options, nullptr, e);
    memory.clear();
  }
  return 0;
}
