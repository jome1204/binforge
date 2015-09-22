#include "binforge/binforge.h"

#include <algorithm>

namespace binforge {
namespace {

constexpr int64_t dynamic_null = 0;
constexpr int64_t dynamic_needed = 1;
constexpr int64_t dynamic_plt_relocation_size = 2;
constexpr int64_t dynamic_plt_got = 3;
constexpr int64_t dynamic_hash = 4;
constexpr int64_t dynamic_string_table = 5;
constexpr int64_t dynamic_symbol_table = 6;
constexpr int64_t dynamic_relocation = 7;
constexpr int64_t dynamic_relocation_size = 8;
constexpr int64_t dynamic_relocation_entry = 9;
constexpr int64_t dynamic_string_size = 10;
constexpr int64_t dynamic_symbol_entry = 11;
constexpr int64_t dynamic_init = 12;
constexpr int64_t dynamic_fini = 13;
constexpr int64_t dynamic_soname = 14;
constexpr int64_t dynamic_rpath = 15;
constexpr int64_t dynamic_symbolic = 16;
constexpr int64_t dynamic_rel = 17;
constexpr int64_t dynamic_rel_size = 18;
constexpr int64_t dynamic_rel_entry = 19;
constexpr int64_t dynamic_plt_relocation = 20;
constexpr int64_t dynamic_debug = 21;
constexpr int64_t dynamic_text_rel = 22;
constexpr int64_t dynamic_jump_relocation = 23;
constexpr int64_t dynamic_bind_now = 24;
constexpr int64_t dynamic_init_array = 25;
constexpr int64_t dynamic_fini_array = 26;
constexpr int64_t dynamic_init_array_size = 27;
constexpr int64_t dynamic_fini_array_size = 28;
constexpr int64_t dynamic_run_path = 29;
constexpr int64_t dynamic_flags = 30;

bool dynamic_string(const BinaryImage &image, uint64_t table_address,
                    uint64_t table_size, uint64_t string_offset,
                    uint64_t maximum, std::string &output) {
  if (string_offset >= table_size)
    return false;
  AddressTranslator translator(image);
  auto file = translator.virtual_to_file(table_address + string_offset, 1);
  if (!file || !image.file_data)
    return false;
  uint64_t remaining = table_size - string_offset;
  remaining = std::min<uint64_t>(remaining, maximum);
  remaining = std::min<uint64_t>(remaining, file->available);
  ByteReader reader(image.file_data->data(), image.file_data->size(),
                    image.header.byte_order);
  return reader.read_c_string(file->file_offset, remaining, output);
}

} // namespace

ElfDynamicParser::ElfDynamicParser(Limits limits) : limits_(limits) {}

std::optional<DynamicReport>
ElfDynamicParser::parse(const BinaryImage &image,
                        const Section &dynamic_section, Error &error) const {
  error.clear();
  if (image.header.format != BinaryFormat::elf_like || !image.file_data) {
    error = {ErrorCode::invalid_header, dynamic_section.file_offset,
             "dynamic parser requires an ELF image"};
    return std::nullopt;
  }
  if (!range_inside(dynamic_section.file_offset, dynamic_section.file_size,
                    image.file_data->size())) {
    error = {ErrorCode::invalid_section, dynamic_section.file_offset,
             "dynamic section is outside the file"};
    return std::nullopt;
  }
  bool wide = image.header.word_size == WordSize::bits64;
  uint64_t entry_size =
      dynamic_section.entry_size ? dynamic_section.entry_size : (wide ? 16 : 8);
  uint64_t minimum = wide ? 16 : 8;
  if (entry_size < minimum || dynamic_section.file_size % entry_size != 0) {
    error = {ErrorCode::invalid_section, dynamic_section.file_offset,
             "dynamic section entry size is invalid"};
    return std::nullopt;
  }
  uint64_t count = dynamic_section.file_size / entry_size;
  if (count > limits_.max_symbols) {
    error = {ErrorCode::resource_limit, dynamic_section.file_offset,
             "dynamic entry limit exceeded"};
    return std::nullopt;
  }

  DynamicReport report;
  std::vector<uint64_t> needed_offsets;
  std::optional<uint64_t> soname_offset;
  std::optional<uint64_t> run_path_offset;
  std::optional<uint64_t> rpath_offset;
  ByteReader reader(image.file_data->data(), image.file_data->size(),
                    image.header.byte_order);

  for (uint64_t index = 0; index < count; ++index) {
    uint64_t position = dynamic_section.file_offset + index * entry_size;
    if (!reader.seek(position))
      return std::nullopt;
    int64_t tag = 0;
    uint64_t value = 0;
    if (wide) {
      if (!reader.read_i64(tag) || !reader.read_u64(value)) {
        error = {ErrorCode::truncated, position,
                 "ELF64 dynamic entry is truncated"};
        return std::nullopt;
      }
    } else {
      int32_t small_tag = 0;
      uint32_t small_value = 0;
      if (!reader.read_i32(small_tag) || !reader.read_u32(small_value)) {
        error = {ErrorCode::truncated, position,
                 "ELF32 dynamic entry is truncated"};
        return std::nullopt;
      }
      tag = small_tag;
      value = small_value;
    }
    report.entries.push_back({tag, value});
    switch (tag) {
    case dynamic_null:
      index = count;
      break;
    case dynamic_needed:
      needed_offsets.push_back(value);
      break;
    case dynamic_string_table:
      report.string_table_address = value;
      break;
    case dynamic_string_size:
      report.string_table_size = value;
      break;
    case dynamic_symbol_table:
      report.symbol_table_address = value;
      break;
    case dynamic_relocation:
    case dynamic_rel:
      report.relocation_address = value;
      break;
    case dynamic_relocation_size:
    case dynamic_rel_size:
      report.relocation_size = value;
      break;
    case dynamic_soname:
      soname_offset = value;
      break;
    case dynamic_run_path:
      run_path_offset = value;
      break;
    case dynamic_rpath:
      rpath_offset = value;
      break;
    case dynamic_bind_now:
      report.bind_now = true;
      break;
    case dynamic_symbolic:
      report.symbolic = true;
      break;
    case dynamic_flags:
      report.bind_now = report.bind_now || (value & 8u) != 0;
      report.symbolic = report.symbolic || (value & 2u) != 0;
      break;
    case dynamic_plt_relocation_size:
    case dynamic_plt_got:
    case dynamic_hash:
    case dynamic_relocation_entry:
    case dynamic_symbol_entry:
    case dynamic_init:
    case dynamic_fini:
    case dynamic_rel_entry:
    case dynamic_plt_relocation:
    case dynamic_debug:
    case dynamic_text_rel:
    case dynamic_jump_relocation:
    case dynamic_init_array:
    case dynamic_fini_array:
    case dynamic_init_array_size:
    case dynamic_fini_array_size:
      break;
    default:
      break;
    }
  }

  if ((!needed_offsets.empty() || soname_offset || run_path_offset ||
       rpath_offset) &&
      (!report.string_table_address || !report.string_table_size)) {
    error = {ErrorCode::invalid_string, dynamic_section.file_offset,
             "dynamic strings referenced without a string table"};
    return std::nullopt;
  }
  if (report.string_table_size > limits_.max_string_bytes) {
    error = {ErrorCode::resource_limit, report.string_table_address,
             "dynamic string table exceeds limit"};
    return std::nullopt;
  }

  for (uint64_t offset : needed_offsets) {
    std::string library;
    if (!dynamic_string(image, report.string_table_address,
                        report.string_table_size, offset,
                        limits_.max_string_bytes, library)) {
      error = {ErrorCode::invalid_string, offset,
               "needed-library string is invalid"};
      return std::nullopt;
    }
    report.needed_libraries.push_back(std::move(library));
  }
  if (soname_offset) {
    std::string value;
    if (!dynamic_string(image, report.string_table_address,
                        report.string_table_size, *soname_offset,
                        limits_.max_string_bytes, value)) {
      error = {ErrorCode::invalid_string, *soname_offset,
               "shared-object name is invalid"};
      return std::nullopt;
    }
    report.soname = std::move(value);
  }
  std::optional<uint64_t> effective_path =
      run_path_offset ? run_path_offset : rpath_offset;
  if (effective_path) {
    std::string value;
    if (!dynamic_string(image, report.string_table_address,
                        report.string_table_size, *effective_path,
                        limits_.max_string_bytes, value)) {
      error = {ErrorCode::invalid_string, *effective_path,
               "dynamic search path is invalid"};
      return std::nullopt;
    }
    report.run_path = std::move(value);
  }
  return report;
}

} // namespace binforge
