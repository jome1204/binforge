#include "binforge/binforge.h"
#include <cstddef>
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 8 * 1024 * 1024)
    return 0;
  binforge::Limits limits;
  limits.max_file_size = 8 * 1024 * 1024;
  limits.max_mapped_bytes = 16 * 1024 * 1024;
  limits.max_sections = 4096;
  limits.max_segments = 4096;
  limits.max_symbols = 100000;
  limits.max_relocations = 100000;
  binforge::Error error;
  binforge::ImageManifestCodec codec(limits);
  auto image = codec.decode(data, size, error);
  if (image) {
    error.clear();
    auto encoded = codec.encode(*image, binforge::ManifestOptions{}, error);
    if (!error && encoded.empty())
      __builtin_trap();
    binforge::ImageAnalyzer(limits).analyze(*image, error);
    binforge::HardeningAnalyzer(limits).analyze(*image, error);
  }
  return 0;
}
