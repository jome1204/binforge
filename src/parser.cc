#include "binforge/binforge.h"
#include <cstring>

namespace binforge {

BinaryParser::BinaryParser(Limits limits) : limits_(limits) {}

BinaryFormat BinaryParser::detect(const uint8_t *data, size_t size) const {
  if (!data || size < 4)
    return BinaryFormat::unknown;
  if (data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F')
    return BinaryFormat::elf_like;
  if (data[0] == 'M' && data[1] == 'Z')
    return BinaryFormat::pe_like;
  uint32_t magic = uint32_t(data[0]) | (uint32_t(data[1]) << 8) |
                   (uint32_t(data[2]) << 16) | (uint32_t(data[3]) << 24);
  if (magic == 0xfeedfaceu || magic == 0xfeedfacfu || magic == 0xcefaedfeu ||
      magic == 0xcffaedfeu)
    return BinaryFormat::macho_like;
  return BinaryFormat::unknown;
}

std::optional<BinaryImage> BinaryParser::parse(const uint8_t *data, size_t size,
                                               Error &error) const {
  error.clear();
  if (!data || size < 4) {
    error = {ErrorCode::truncated, 0, "binary header is truncated"};
    return std::nullopt;
  }
  if (size > limits_.max_file_size) {
    error = {ErrorCode::resource_limit, 0, "binary exceeds file limit"};
    return std::nullopt;
  }
  auto storage =
      std::make_shared<const std::vector<uint8_t>>(data, data + size);
  switch (detect(data, size)) {
  case BinaryFormat::elf_like:
    return ElfParser(limits_).parse(storage, error);
  case BinaryFormat::pe_like:
    return PeParser(limits_).parse(storage, error);
  case BinaryFormat::macho_like:
    return MachOParser(limits_).parse(storage, error);
  default:
    error = {ErrorCode::bad_magic, 0, "unknown executable signature"};
    return std::nullopt;
  }
}

} // namespace binforge
