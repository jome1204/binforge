#include "binforge/binforge.h"

#include <algorithm>
#include <cctype>

namespace binforge {
namespace {

bool note_text(const std::vector<uint8_t> &bytes) {
  if (bytes.empty())
    return false;
  for (uint8_t value : bytes) {
    if (value == 0)
      continue;
    if (!std::isprint(value) && !std::isspace(value))
      return false;
  }
  return true;
}

bool aligned_advance(ByteReader &reader, uint64_t consumed,
                     uint64_t alignment) {
  uint64_t aligned = 0;
  return checked_align_up(consumed, alignment, aligned) &&
         reader.skip(aligned - consumed);
}

} // namespace

NoteParser::NoteParser(Limits limits) : limits_(limits) {}

bool NoteParser::parse_elf(const uint8_t *data, size_t size, ByteOrder order,
                           std::vector<BinaryNote> &notes, Error &error) const {
  error.clear();
  if (size > limits_.max_debug_bytes) {
    error = {ErrorCode::resource_limit, 0, "ELF note data exceeds limit"};
    return false;
  }
  ByteReader reader(data, size, order);
  while (reader.remaining()) {
    size_t note_offset = reader.position();
    uint32_t name_size = 0, descriptor_size = 0, type = 0;
    if (!reader.read_u32(name_size) || !reader.read_u32(descriptor_size) ||
        !reader.read_u32(type)) {
      error = {ErrorCode::truncated, note_offset,
               "ELF note header is truncated"};
      return false;
    }
    if (name_size > limits_.max_string_bytes ||
        descriptor_size > limits_.max_debug_bytes ||
        name_size > reader.remaining()) {
      error = {ErrorCode::resource_limit, note_offset,
               "ELF note sizes are invalid"};
      return false;
    }
    std::vector<uint8_t> name_bytes;
    if (!reader.read_bytes(name_size, name_bytes) ||
        !aligned_advance(reader, name_size, 4)) {
      error = {ErrorCode::truncated, note_offset,
               "ELF note owner is truncated"};
      return false;
    }
    while (!name_bytes.empty() && name_bytes.back() == 0)
      name_bytes.pop_back();
    if (!note_text(name_bytes)) {
      error = {ErrorCode::invalid_string, note_offset,
               "ELF note owner is not printable"};
      return false;
    }
    if (descriptor_size > reader.remaining()) {
      error = {ErrorCode::truncated, reader.position(),
               "ELF note descriptor is truncated"};
      return false;
    }
    std::vector<uint8_t> descriptor;
    if (!reader.read_bytes(descriptor_size, descriptor) ||
        !aligned_advance(reader, descriptor_size, 4)) {
      error = {ErrorCode::truncated, reader.position(),
               "ELF note descriptor padding is truncated"};
      return false;
    }
    if (notes.size() >= limits_.max_debug_units) {
      error = {ErrorCode::resource_limit, note_offset,
               "ELF note record limit exceeded"};
      return false;
    }
    BinaryNote note;
    note.owner.assign(name_bytes.begin(), name_bytes.end());
    note.type = type;
    note.file_offset = note_offset;
    if (descriptor.size() <= 8 &&
        (note.owner == "GNU" || note.owner == "CORE")) {
      uint64_t integer = 0;
      if (order == ByteOrder::little) {
        for (size_t index = 0; index < descriptor.size(); ++index)
          integer |= uint64_t(descriptor[index]) << (index * 8);
      } else {
        for (uint8_t value : descriptor)
          integer = (integer << 8) | value;
      }
      note.value_kind = NoteValueKind::integer;
      note.value = integer;
    } else if (note_text(descriptor)) {
      while (!descriptor.empty() && descriptor.back() == 0)
        descriptor.pop_back();
      note.value_kind = NoteValueKind::text;
      note.value = std::string(descriptor.begin(), descriptor.end());
    } else {
      note.value_kind = NoteValueKind::bytes;
      note.value = std::move(descriptor);
    }
    notes.push_back(std::move(note));
  }
  return true;
}

bool NoteParser::parse_macho_commands(const uint8_t *data, size_t size,
                                      ByteOrder order,
                                      std::vector<BinaryNote> &notes,
                                      Error &error) const {
  error.clear();
  if (size > limits_.max_debug_bytes) {
    error = {ErrorCode::resource_limit, 0, "Mach-O note commands exceed limit"};
    return false;
  }
  ByteReader reader(data, size, order);
  while (reader.remaining()) {
    size_t command_offset = reader.position();
    uint32_t command = 0, command_size = 0;
    if (!reader.read_u32(command) || !reader.read_u32(command_size) ||
        command_size < 8 || command_size > size - command_offset) {
      error = {ErrorCode::invalid_header, command_offset,
               "Mach-O load command is invalid"};
      return false;
    }
    if (command == 0x31) {
      if (command_size < 40) {
        error = {ErrorCode::truncated, command_offset,
                 "Mach-O note command is truncated"};
        return false;
      }
      BinaryNote note;
      note.type = command;
      note.file_offset = command_offset;
      if (!reader.read_fixed_string(16, note.owner))
        return false;
      uint64_t file_offset = 0, note_size = 0;
      if (!reader.read_u64(file_offset) || !reader.read_u64(note_size) ||
          !range_inside(file_offset, note_size, size) ||
          note_size > limits_.max_debug_bytes) {
        error = {ErrorCode::invalid_offset, command_offset,
                 "Mach-O note payload range is invalid"};
        return false;
      }
      note.value_kind = NoteValueKind::bytes;
      note.value = std::vector<uint8_t>(data + file_offset,
                                        data + file_offset + note_size);
      notes.push_back(std::move(note));
    }
    if (!reader.seek(command_offset + command_size))
      return false;
  }
  return true;
}

} // namespace binforge
