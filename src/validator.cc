#include "binforge/binforge.h"
#include <algorithm>
namespace binforge {
BinaryValidator::BinaryValidator(Limits l) : limits_(l) {}
ValidationReport BinaryValidator::validate(const BinaryImage &i) const {
  ValidationReport r;
  if (!i.file_data) {
    r.errors.push_back(
        {ErrorCode::invalid_header, 0, "image does not retain file bytes"});
    return r;
  }
  if (i.file_data->size() > limits_.max_file_size)
    r.errors.push_back({ErrorCode::resource_limit, 0, "file size limit"});
  if (i.sections.size() > limits_.max_sections)
    r.errors.push_back({ErrorCode::resource_limit, 0, "section count limit"});
  if (i.segments.size() > limits_.max_segments)
    r.errors.push_back({ErrorCode::resource_limit, 0, "segment count limit"});
  if (i.symbols.size() > limits_.max_symbols)
    r.errors.push_back({ErrorCode::resource_limit, 0, "symbol count limit"});
  if (i.relocations.size() > limits_.max_relocations)
    r.errors.push_back(
        {ErrorCode::resource_limit, 0, "relocation count limit"});
  for (size_t n = 0; n < i.sections.size(); ++n) {
    auto &s = i.sections[n];
    if (s.index != n)
      r.errors.push_back(
          {ErrorCode::invalid_section, n, "section index mismatch"});
    if (s.kind != SectionKind::no_bits &&
        !range_inside(s.file_offset, s.file_size, i.file_data->size()))
      r.errors.push_back({ErrorCode::file_range_overflow, s.file_offset,
                          "section file range invalid"});
    if (!s.alignment || (s.alignment & (s.alignment - 1)))
      r.errors.push_back({ErrorCode::invalid_alignment, s.file_offset,
                          "section alignment invalid"});
    checked_add(r.file_bytes_referenced, s.file_size, r.file_bytes_referenced);
    checked_add(r.virtual_bytes_referenced, s.memory_size,
                r.virtual_bytes_referenced);
  }
  for (auto &s : i.segments) {
    if (s.file_size > s.memory_size ||
        !range_inside(s.file_offset, s.file_size, i.file_data->size()))
      r.errors.push_back(
          {ErrorCode::invalid_segment, s.file_offset, "segment range invalid"});
    uint64_t end;
    if (!checked_add(s.virtual_address, s.memory_size, end))
      r.errors.push_back({ErrorCode::address_overflow, s.virtual_address,
                          "segment virtual range overflow"});
  }
  for (size_t n = 0; n < i.symbols.size(); ++n)
    if (i.symbols[n].index != n)
      r.errors.push_back(
          {ErrorCode::invalid_symbol, n, "symbol index mismatch"});
  for (auto &rel : i.relocations)
    if (rel.symbol_index >= i.symbols.size() && rel.symbol_index)
      r.errors.push_back({ErrorCode::invalid_symbol, rel.offset,
                          "relocation symbol out of range"});
  r.valid = r.errors.empty();
  return r;
}
} // namespace binforge
