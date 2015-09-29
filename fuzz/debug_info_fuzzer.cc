#include "binforge/binforge.h"
#include <cstddef>
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
  if (n < 2 || n > 4 * 1024 * 1024)
    return 0;
  binforge::Limits l;
  l.max_debug_bytes = 4 * 1024 * 1024;
  l.max_line_rows = 100000;
  l.max_debug_depth = 64;
  binforge::DebugUnit unit;
  binforge::Error e;
  binforge::DebugInfoParser parser(l);
  auto order =
      (d[0] & 1) ? binforge::ByteOrder::big : binforge::ByteOrder::little;
  parser.parse_line_program(d + 1, n - 1, order, (d[0] & 2) ? 8 : 4, unit, e);
  e.clear();
  unit.entries.clear();
  parser.parse_entries(d + 1, n - 1, order, (d[0] & 2) ? 8 : 4, unit, e);
  return 0;
}
