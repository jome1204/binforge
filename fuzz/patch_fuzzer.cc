#include "binforge/binforge.h"
#include <cstddef>
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 2 * 1024 * 1024)
    return 0;
  binforge::Limits limits;
  limits.max_file_size = 2 * 1024 * 1024;
  limits.max_mapped_bytes = 4 * 1024 * 1024;
  limits.max_relocations = 10000;
  binforge::Error error;
  binforge::PatchEngine engine(limits);
  auto plan = engine.decode(data, size, error);
  if (plan) {
    binforge::AddressSpace memory(limits);
    memory.map(0x1000, 1024 * 1024,
               binforge::permission_read | binforge::permission_write, "patch",
               error);
    error.clear();
    engine.apply(*plan, memory, error);
    auto encoded = engine.encode(*plan, error);
    (void)encoded;
  }
  return 0;
}
