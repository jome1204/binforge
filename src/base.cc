#include "binforge/binforge.h"
#include <algorithm>
#include <limits>

namespace binforge {

void Error::clear() {
  code = ErrorCode::none;
  offset = 0;
  message.clear();
}

bool checked_add(uint64_t left, uint64_t right, uint64_t &result) {
  if (right > std::numeric_limits<uint64_t>::max() - left)
    return false;
  result = left + right;
  return true;
}

bool checked_multiply(uint64_t left, uint64_t right, uint64_t &result) {
  if (left && right > std::numeric_limits<uint64_t>::max() / left)
    return false;
  result = left * right;
  return true;
}

bool checked_align_up(uint64_t value, uint64_t alignment, uint64_t &result) {
  if (!alignment || (alignment & (alignment - 1)) != 0)
    return false;
  uint64_t mask = alignment - 1;
  uint64_t expanded = 0;
  if (!checked_add(value, mask, expanded))
    return false;
  result = expanded & ~mask;
  return true;
}

bool range_inside(uint64_t offset, uint64_t length, uint64_t container_size) {
  return offset <= container_size && length <= container_size - offset;
}

uint32_t crc32(const uint8_t *data, size_t size) {
  uint32_t value = 0xffffffffu;
  for (size_t i = 0; i < size; ++i) {
    value ^= data[i];
    for (int bit = 0; bit < 8; ++bit)
      value = (value >> 1) ^ (0xedb88320u & (0u - (value & 1u)));
  }
  return ~value;
}

std::string error_code_name(ErrorCode code) {
  switch (code) {
  case ErrorCode::none:
    return "none";
  case ErrorCode::truncated:
    return "truncated";
  case ErrorCode::bad_magic:
    return "bad_magic";
  case ErrorCode::unsupported_format:
    return "unsupported_format";
  case ErrorCode::unsupported_class:
    return "unsupported_class";
  case ErrorCode::unsupported_endian:
    return "unsupported_endian";
  case ErrorCode::invalid_header:
    return "invalid_header";
  case ErrorCode::invalid_offset:
    return "invalid_offset";
  case ErrorCode::invalid_count:
    return "invalid_count";
  case ErrorCode::invalid_alignment:
    return "invalid_alignment";
  case ErrorCode::invalid_string:
    return "invalid_string";
  case ErrorCode::invalid_section:
    return "invalid_section";
  case ErrorCode::invalid_segment:
    return "invalid_segment";
  case ErrorCode::invalid_symbol:
    return "invalid_symbol";
  case ErrorCode::invalid_relocation:
    return "invalid_relocation";
  case ErrorCode::invalid_debug_info:
    return "invalid_debug_info";
  case ErrorCode::address_overflow:
    return "address_overflow";
  case ErrorCode::file_range_overflow:
    return "file_range_overflow";
  case ErrorCode::mapping_overlap:
    return "mapping_overlap";
  case ErrorCode::mapping_missing:
    return "mapping_missing";
  case ErrorCode::permission_denied:
    return "permission_denied";
  case ErrorCode::unresolved_import:
    return "unresolved_import";
  case ErrorCode::duplicate_export:
    return "duplicate_export";
  case ErrorCode::resource_limit:
    return "resource_limit";
  case ErrorCode::internal_error:
    return "internal_error";
  }
  return "unknown";
}

const Section *BinaryImage::section(uint32_t index) const {
  return index < sections.size() ? &sections[index] : nullptr;
}

const Symbol *BinaryImage::symbol(uint32_t index) const {
  return index < symbols.size() ? &symbols[index] : nullptr;
}

const Section *BinaryImage::section_named(std::string_view name) const {
  auto it = std::find_if(sections.begin(), sections.end(),
                         [&](const Section &s) { return s.name == name; });
  return it == sections.end() ? nullptr : &*it;
}

} // namespace binforge
