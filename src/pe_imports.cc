#include "binforge/binforge.h"

#include <algorithm>
#include <cctype>

namespace binforge {
namespace {

bool read_rva_string(const BinaryImage &image,
                     const AddressTranslator &translator, uint64_t rva,
                     uint64_t maximum, std::string &value) {
  auto location = translator.rva_to_file(rva, 1);
  if (!location || !image.file_data)
    return false;
  uint64_t available = std::min<uint64_t>(location->available, maximum);
  ByteReader reader(image.file_data->data(), image.file_data->size());
  return reader.read_c_string(location->file_offset, available, value);
}

bool normalize_library(std::string &library) {
  if (library.empty())
    return false;
  for (char &character : library) {
    unsigned char value = static_cast<unsigned char>(character);
    if (value < 0x20 || value == 0x7f)
      return false;
    character = static_cast<char>(std::tolower(value));
  }
  return true;
}

} // namespace

PeImportExportParser::PeImportExportParser(Limits limits) : limits_(limits) {}

bool PeImportExportParser::parse_imports(const BinaryImage &image,
                                         const ImportTableOptions &options,
                                         std::vector<Import> &imports,
                                         Error &error) const {
  error.clear();
  if (!image.file_data || image.header.format != BinaryFormat::pe_like) {
    error = {ErrorCode::invalid_header, options.directory_rva,
             "PE import parser requires a PE image"};
    return false;
  }
  if (!options.directory_size)
    return true;

  AddressTranslator translator(image);
  auto directory =
      translator.rva_to_file(options.directory_rva, options.directory_size);
  if (!directory ||
      !range_inside(directory->file_offset, options.directory_size,
                    image.file_data->size())) {
    error = {ErrorCode::invalid_offset, options.directory_rva,
             "PE import directory is outside file-backed sections"};
    return false;
  }

  ByteReader reader(image.file_data->data(), image.file_data->size(),
                    ByteOrder::little);
  uint64_t cursor = directory->file_offset;
  uint64_t directory_end = cursor + options.directory_size;
  uint64_t pointer_width = static_cast<uint8_t>(options.word_size);
  uint64_t ordinal_flag =
      pointer_width == 8 ? (uint64_t{1} << 63) : (uint64_t{1} << 31);

  while (cursor < directory_end) {
    if (!range_inside(cursor, 20, directory_end)) {
      error = {ErrorCode::truncated, cursor,
               "PE import descriptor is truncated"};
      return false;
    }
    if (!reader.seek(cursor))
      return false;
    uint32_t lookup_rva = 0;
    uint32_t timestamp = 0;
    uint32_t forwarder = 0;
    uint32_t name_rva = 0;
    uint32_t address_rva = 0;
    if (!reader.read_u32(lookup_rva) || !reader.read_u32(timestamp) ||
        !reader.read_u32(forwarder) || !reader.read_u32(name_rva) ||
        !reader.read_u32(address_rva)) {
      error = {ErrorCode::truncated, cursor,
               "PE import descriptor fields are truncated"};
      return false;
    }
    cursor += 20;
    if (!lookup_rva && !timestamp && !forwarder && !name_rva && !address_rva)
      break;
    if (imports.size() >= limits_.max_imports) {
      error = {ErrorCode::resource_limit, cursor,
               "PE import descriptor limit exceeded"};
      return false;
    }

    std::string library;
    if (!read_rva_string(image, translator, name_rva, limits_.max_string_bytes,
                         library) ||
        !normalize_library(library)) {
      error = {ErrorCode::invalid_string, name_rva,
               "PE import library name is invalid"};
      return false;
    }

    uint64_t table_rva = lookup_rva ? lookup_rva : address_rva;
    for (uint64_t entry_index = 0; entry_index < limits_.max_imports;
         ++entry_index) {
      uint64_t entry_delta = 0;
      uint64_t entry_rva = 0;
      if (!checked_multiply(entry_index, pointer_width, entry_delta) ||
          !checked_add(table_rva, entry_delta, entry_rva)) {
        error = {ErrorCode::address_overflow, table_rva,
                 "PE import lookup address overflows"};
        return false;
      }
      auto entry_file = translator.rva_to_file(entry_rva, pointer_width);
      if (!entry_file) {
        error = {ErrorCode::invalid_offset, entry_rva,
                 "PE import lookup entry is not file-backed"};
        return false;
      }
      if (!reader.seek(entry_file->file_offset))
        return false;
      uint64_t value = 0;
      if (pointer_width == 8) {
        if (!reader.read_u64(value))
          return false;
      } else {
        uint32_t small = 0;
        if (!reader.read_u32(small))
          return false;
        value = small;
      }
      if (!value)
        break;
      if (imports.size() >= limits_.max_imports) {
        error = {ErrorCode::resource_limit, entry_rva,
                 "PE imported symbol limit exceeded"};
        return false;
      }

      Import imported;
      imported.library = library;
      uint64_t slot_rva = 0;
      if (!checked_add(address_rva, entry_delta, slot_rva) ||
          !checked_add(options.image_base, slot_rva, imported.slot_address)) {
        error = {ErrorCode::address_overflow, address_rva,
                 "PE import slot address overflows"};
        return false;
      }
      if (value & ordinal_flag) {
        imported.ordinal = value & 0xffffu;
      } else {
        auto name_file = translator.rva_to_file(value, 3);
        if (!name_file || !reader.seek(name_file->file_offset)) {
          error = {ErrorCode::invalid_offset, value,
                   "PE import-by-name record is invalid"};
          return false;
        }
        uint16_t hint = 0;
        if (!reader.read_u16(hint) ||
            !reader.read_c_string(reader.position(),
                                  std::min<uint64_t>(name_file->available - 2,
                                                     limits_.max_string_bytes),
                                  imported.name)) {
          error = {ErrorCode::invalid_string, value,
                   "PE imported symbol name is invalid"};
          return false;
        }
        imported.ordinal = hint;
      }
      imports.push_back(std::move(imported));
    }
  }
  return true;
}

bool PeImportExportParser::parse_exports(const BinaryImage &image,
                                         uint64_t directory_rva,
                                         uint64_t directory_size,
                                         std::vector<Export> &exports,
                                         Error &error) const {
  error.clear();
  if (!image.file_data || image.header.format != BinaryFormat::pe_like) {
    error = {ErrorCode::invalid_header, directory_rva,
             "PE export parser requires a PE image"};
    return false;
  }
  if (!directory_size)
    return true;
  AddressTranslator translator(image);
  auto directory = translator.rva_to_file(directory_rva, 40);
  if (!directory) {
    error = {ErrorCode::invalid_offset, directory_rva,
             "PE export directory is not file-backed"};
    return false;
  }
  ByteReader reader(image.file_data->data(), image.file_data->size(),
                    ByteOrder::little);
  if (!reader.seek(directory->file_offset))
    return false;
  uint32_t characteristics, timestamp;
  uint16_t major, minor;
  uint32_t name_rva, ordinal_base, function_count, name_count;
  uint32_t functions_rva, names_rva, ordinals_rva;
  if (!reader.read_u32(characteristics) || !reader.read_u32(timestamp) ||
      !reader.read_u16(major) || !reader.read_u16(minor) ||
      !reader.read_u32(name_rva) || !reader.read_u32(ordinal_base) ||
      !reader.read_u32(function_count) || !reader.read_u32(name_count) ||
      !reader.read_u32(functions_rva) || !reader.read_u32(names_rva) ||
      !reader.read_u32(ordinals_rva)) {
    error = {ErrorCode::truncated, directory->file_offset,
             "PE export directory is truncated"};
    return false;
  }
  (void)characteristics;
  (void)timestamp;
  (void)major;
  (void)minor;
  (void)name_rva;
  if (function_count > limits_.max_exports || name_count > function_count) {
    error = {ErrorCode::resource_limit, directory_rva,
             "PE export table count is invalid"};
    return false;
  }
  auto functions =
      translator.rva_to_file(functions_rva, uint64_t(function_count) * 4);
  auto names = translator.rva_to_file(names_rva, uint64_t(name_count) * 4);
  auto ordinals =
      translator.rva_to_file(ordinals_rva, uint64_t(name_count) * 2);
  if (!functions || (name_count && (!names || !ordinals))) {
    error = {ErrorCode::invalid_offset, directory_rva,
             "PE export arrays are not file-backed"};
    return false;
  }

  exports.resize(function_count);
  reader.seek(functions->file_offset);
  for (uint32_t index = 0; index < function_count; ++index) {
    uint32_t function_rva = 0;
    if (!reader.read_u32(function_rva))
      return false;
    Export &symbol = exports[index];
    symbol.ordinal = uint64_t(ordinal_base) + index;
    if (!checked_add(image.header.image_base, function_rva, symbol.address)) {
      error = {ErrorCode::address_overflow, function_rva,
               "PE exported function address overflows"};
      return false;
    }
    if (function_rva >= directory_rva &&
        function_rva < directory_rva + directory_size) {
      symbol.forwarded = true;
      if (!read_rva_string(image, translator, function_rva,
                           limits_.max_string_bytes, symbol.forward_target)) {
        error = {ErrorCode::invalid_string, function_rva,
                 "PE forwarder string is invalid"};
        return false;
      }
    }
  }

  for (uint32_t index = 0; index < name_count; ++index) {
    uint32_t symbol_name_rva = 0;
    uint16_t ordinal_index = 0;
    reader.seek(names->file_offset + uint64_t(index) * 4);
    if (!reader.read_u32(symbol_name_rva))
      return false;
    reader.seek(ordinals->file_offset + uint64_t(index) * 2);
    if (!reader.read_u16(ordinal_index) || ordinal_index >= exports.size()) {
      error = {ErrorCode::invalid_symbol, ordinals_rva + index * 2,
               "PE export ordinal index is invalid"};
      return false;
    }
    if (!read_rva_string(image, translator, symbol_name_rva,
                         limits_.max_string_bytes,
                         exports[ordinal_index].name)) {
      error = {ErrorCode::invalid_string, symbol_name_rva,
               "PE export name is invalid"};
      return false;
    }
  }
  return true;
}

} // namespace binforge
