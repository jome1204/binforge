#include "binforge/binforge.h"
#include <cstddef>
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
  binforge::Limits l;
  l.max_mapped_bytes = 2 << 20;
  binforge::AddressSpace m(l);
  binforge::Error e;
  for (size_t i = 0; i < n && i < 10000; ++i) {
    uint64_t base = 0x1000 + uint64_t(d[i]) * 0x1000;
    switch (d[i] % 5) {
    case 0:
      m.map(base, 0x1000, 7, "fuzz", e);
      break;
    case 1:
      m.unmap(base, e);
      break;
    case 2: {
      uint8_t v = d[i];
      m.write(base, &v, 1, e);
      break;
    }
    case 3: {
      uint8_t v;
      m.read(base, &v, 1, e);
      break;
    }
    default:
      m.protect(base, 0x1000, d[i] & 7, e);
      break;
    }
    e.clear();
  }
  return 0;
}
