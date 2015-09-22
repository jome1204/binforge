#include "binforge/binforge.h"

#include <algorithm>
#include <functional>

namespace binforge {
namespace {

ResourceKind resource_kind(const ResourceIdentifier &identifier) {
  if (!identifier.integer)
    return ResourceKind::unknown;
  switch (*identifier.integer) {
  case 1:
    return ResourceKind::cursor;
  case 2:
    return ResourceKind::bitmap;
  case 3:
    return ResourceKind::icon;
  case 4:
    return ResourceKind::menu;
  case 5:
    return ResourceKind::dialog;
  case 6:
    return ResourceKind::string_table;
  case 8:
    return ResourceKind::font;
  case 9:
    return ResourceKind::accelerator;
  case 10:
    return ResourceKind::raw_data;
  case 11:
    return ResourceKind::message_table;
  case 16:
    return ResourceKind::version;
  case 24:
    return ResourceKind::manifest;
  default:
    return ResourceKind::unknown;
  }
}

bool resource_name(const BinaryImage &image, uint64_t base_file,
                   uint64_t directory_size, uint32_t encoded, uint64_t maximum,
                   ResourceIdentifier &identifier, Error &error) {
  if (!(encoded & 0x80000000u)) {
    identifier.integer = encoded;
    return true;
  }
  uint64_t relative = encoded & 0x7fffffffu;
  if (!range_inside(relative, 2, directory_size)) {
    error = {ErrorCode::invalid_string, relative,
             "resource name length is outside directory"};
    return false;
  }
  ByteReader reader(image.file_data->data(), image.file_data->size(),
                    ByteOrder::little);
  if (!reader.seek(base_file + relative))
    return false;
  uint16_t characters = 0;
  if (!reader.read_u16(characters))
    return false;
  uint64_t bytes = uint64_t(characters) * 2;
  if (bytes > maximum || !range_inside(relative + 2, bytes, directory_size)) {
    error = {ErrorCode::resource_limit, relative,
             "resource UTF-16 name exceeds limit"};
    return false;
  }
  identifier.name.reserve(characters);
  for (uint16_t index = 0; index < characters; ++index) {
    uint16_t code_unit = 0;
    if (!reader.read_u16(code_unit))
      return false;
    if (code_unit < 0x80) {
      identifier.name.push_back(static_cast<char>(code_unit));
    } else if (code_unit < 0x800) {
      identifier.name.push_back(static_cast<char>(0xc0 | (code_unit >> 6)));
      identifier.name.push_back(static_cast<char>(0x80 | (code_unit & 0x3f)));
    } else if (code_unit < 0xd800 || code_unit > 0xdfff) {
      identifier.name.push_back(static_cast<char>(0xe0 | (code_unit >> 12)));
      identifier.name.push_back(
          static_cast<char>(0x80 | ((code_unit >> 6) & 0x3f)));
      identifier.name.push_back(static_cast<char>(0x80 | (code_unit & 0x3f)));
    } else {
      error = {ErrorCode::invalid_string, relative + 2 + index * 2,
               "resource name contains an unpaired surrogate"};
      return false;
    }
  }
  return true;
}

} // namespace

bool ResourceIdentifier::operator<(const ResourceIdentifier &other) const {
  if (integer != other.integer)
    return integer < other.integer;
  return name < other.name;
}

PeResourceParser::PeResourceParser(Limits limits) : limits_(limits) {}

std::optional<ResourceReport> PeResourceParser::parse(const BinaryImage &image,
                                                      uint64_t directory_rva,
                                                      uint64_t directory_size,
                                                      Error &error) const {
  error.clear();
  if (!image.file_data || image.header.format != BinaryFormat::pe_like) {
    error = {ErrorCode::invalid_header, directory_rva,
             "resource parser requires a PE image"};
    return std::nullopt;
  }
  if (!directory_size)
    return ResourceReport{};
  if (directory_size > limits_.max_section_bytes) {
    error = {ErrorCode::resource_limit, directory_rva,
             "resource directory exceeds byte limit"};
    return std::nullopt;
  }
  AddressTranslator translator(image);
  auto root = translator.rva_to_file(directory_rva, directory_size);
  if (!root || !range_inside(root->file_offset, directory_size,
                             image.file_data->size())) {
    error = {ErrorCode::invalid_offset, directory_rva,
             "resource directory is outside file-backed data"};
    return std::nullopt;
  }

  ResourceReport report;
  std::set<uint64_t> active_directories;
  ByteReader reader(image.file_data->data(), image.file_data->size(),
                    ByteOrder::little);
  uint64_t base_file = root->file_offset;

  std::function<bool(uint64_t, uint32_t, std::vector<ResourceIdentifier>)> walk;
  walk = [&](uint64_t relative, uint32_t depth,
             std::vector<ResourceIdentifier> path) -> bool {
    if (depth > limits_.max_debug_depth) {
      error = {ErrorCode::resource_limit, relative,
               "resource directory depth limit exceeded"};
      return false;
    }
    report.maximum_depth = std::max(report.maximum_depth, depth);
    if (!active_directories.insert(relative).second) {
      error = {ErrorCode::invalid_section, relative,
               "resource directory contains a cycle"};
      return false;
    }
    if (!range_inside(relative, 16, directory_size) ||
        !reader.seek(base_file + relative)) {
      error = {ErrorCode::truncated, relative,
               "resource directory header is truncated"};
      active_directories.erase(relative);
      return false;
    }
    uint32_t characteristics = 0, timestamp = 0;
    uint16_t major = 0, minor = 0, named = 0, integer = 0;
    if (!reader.read_u32(characteristics) || !reader.read_u32(timestamp) ||
        !reader.read_u16(major) || !reader.read_u16(minor) ||
        !reader.read_u16(named) || !reader.read_u16(integer)) {
      error = {ErrorCode::truncated, relative,
               "resource directory fields are truncated"};
      active_directories.erase(relative);
      return false;
    }
    (void)characteristics;
    (void)timestamp;
    (void)major;
    (void)minor;
    uint32_t count = uint32_t(named) + integer;
    if (count > limits_.max_sections ||
        !range_inside(relative + 16, uint64_t(count) * 8, directory_size)) {
      error = {ErrorCode::resource_limit, relative,
               "resource directory entry count is invalid"};
      active_directories.erase(relative);
      return false;
    }

    for (uint32_t index = 0; index < count; ++index) {
      uint64_t entry_relative = relative + 16 + uint64_t(index) * 8;
      if (!reader.seek(base_file + entry_relative))
        return false;
      uint32_t encoded_name = 0, encoded_target = 0;
      if (!reader.read_u32(encoded_name) || !reader.read_u32(encoded_target)) {
        error = {ErrorCode::truncated, entry_relative,
                 "resource directory entry is truncated"};
        active_directories.erase(relative);
        return false;
      }
      ResourceIdentifier identifier;
      if (!resource_name(image, base_file, directory_size, encoded_name,
                         limits_.max_string_bytes, identifier, error)) {
        active_directories.erase(relative);
        return false;
      }
      auto child_path = path;
      child_path.push_back(std::move(identifier));
      uint64_t target = encoded_target & 0x7fffffffu;
      if (encoded_target & 0x80000000u) {
        if (!walk(target, depth + 1, std::move(child_path))) {
          active_directories.erase(relative);
          return false;
        }
        continue;
      }

      if (!range_inside(target, 16, directory_size) ||
          !reader.seek(base_file + target)) {
        error = {ErrorCode::invalid_offset, target,
                 "resource data entry is outside directory"};
        active_directories.erase(relative);
        return false;
      }
      uint32_t data_rva = 0, data_size = 0, code_page = 0, reserved = 0;
      if (!reader.read_u32(data_rva) || !reader.read_u32(data_size) ||
          !reader.read_u32(code_page) || !reader.read_u32(reserved)) {
        error = {ErrorCode::truncated, target,
                 "resource data descriptor is truncated"};
        active_directories.erase(relative);
        return false;
      }
      (void)reserved;
      auto data_file = translator.rva_to_file(data_rva, data_size);
      if (!data_file) {
        error = {ErrorCode::invalid_offset, data_rva,
                 "resource payload is not file-backed"};
        active_directories.erase(relative);
        return false;
      }
      if (report.entries.size() >= limits_.max_sections) {
        error = {ErrorCode::resource_limit, target,
                 "resource entry limit exceeded"};
        active_directories.erase(relative);
        return false;
      }
      ResourceEntry entry;
      if (!child_path.empty())
        entry.type = child_path[0];
      if (child_path.size() > 1)
        entry.name = child_path[1];
      if (child_path.size() > 2)
        entry.language = child_path[2];
      entry.kind = resource_kind(entry.type);
      entry.file_offset = data_file->file_offset;
      entry.size = data_size;
      entry.code_page = code_page;
      entry.checksum = crc32(image.file_data->data() + entry.file_offset,
                             static_cast<size_t>(entry.size));
      uint64_t total = 0;
      if (!checked_add(report.total_bytes, entry.size, total)) {
        error = {ErrorCode::address_overflow, entry.file_offset,
                 "resource byte total overflows"};
        active_directories.erase(relative);
        return false;
      }
      report.total_bytes = total;
      report.entries.push_back(std::move(entry));
    }
    active_directories.erase(relative);
    return true;
  };

  if (!walk(0, 0, {}))
    return std::nullopt;
  return report;
}

} // namespace binforge
