#include "binforge/binforge.h"
#include <cstddef>
#include <cstdint>
static uint64_t take(const uint8_t *d, size_t n, size_t &o) {
  uint64_t v = 0;
  for (unsigned i = 0; i < 8 && o < n; ++i)
    v |= uint64_t(d[o++]) << (i * 8);
  return v;
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
  if (n < 3)
    return 0;
  binforge::Limits l;
  l.max_mapped_bytes = 1 << 20;
  binforge::AddressSpace memory(l);
  binforge::Error e;
  memory.map(0x10000, 0x10000,
             binforge::permission_read | binforge::permission_write,
             "synthetic", e);
  binforge::BinaryImage image;
  image.header.byte_order =
      (d[0] & 1) ? binforge::ByteOrder::big : binforge::ByteOrder::little;
  image.symbols.push_back({});
  size_t o = 1;
  while (o < n && image.relocations.size() < 1000) {
    binforge::Relocation r;
    r.index = image.relocations.size();
    r.kind = static_cast<binforge::RelocationKind>(d[o++] % 10);
    r.offset = 0x10000 + (take(d, n, o) % 0xfff8);
    r.addend = static_cast<int64_t>(take(d, n, o));
    r.width = (d[o++ % n] & 1) ? 4 : 8;
    image.relocations.push_back(r);
  }
  uint32_t applied = 0;
  binforge::RelocationProcessor(l).apply(image, memory, 0, nullptr, applied, e);
  return 0;
}
