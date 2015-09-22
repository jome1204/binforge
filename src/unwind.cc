#include "binforge/binforge.h"

#include <algorithm>

namespace binforge {
namespace {

bool read_address(ByteReader &reader, WordSize size, uint64_t &value) {
  if (size == WordSize::bits64)
    return reader.read_u64(value);
  uint32_t small = 0;
  if (!reader.read_u32(small))
    return false;
  value = small;
  return true;
}

bool append_unwind_instruction(UnwindRecord &record,
                               UnwindInstruction instruction,
                               const Limits &limits, Error &error,
                               uint64_t offset) {
  if (record.instructions.size() >= limits.max_disassembly_instructions) {
    error = {ErrorCode::resource_limit, offset,
             "unwind instruction limit exceeded"};
    return false;
  }
  record.instructions.push_back(std::move(instruction));
  return true;
}

bool parse_cfi_instructions(ByteReader &reader, size_t end,
                            UnwindRecord &record, const Limits &limits,
                            Error &error) {
  while (reader.position() < end) {
    size_t offset = reader.position();
    uint8_t opcode = 0;
    if (!reader.read_u8(opcode))
      return false;
    UnwindInstruction instruction;
    uint8_t primary = opcode & 0xc0;
    if (primary == 0x40) {
      instruction.operation = UnwindOperation::none;
      instruction.value = opcode & 0x3f;
    } else if (primary == 0x80) {
      uint64_t displacement = 0;
      if (!reader.read_uleb128(displacement))
        return false;
      instruction.operation = UnwindOperation::save_register;
      instruction.register_number = opcode & 0x3f;
      instruction.offset = displacement;
    } else if (primary == 0xc0) {
      instruction.operation = UnwindOperation::restore_state;
      instruction.register_number = opcode & 0x3f;
    } else {
      switch (opcode) {
      case 0:
        instruction.operation = UnwindOperation::none;
        break;
      case 1: {
        instruction.operation = UnwindOperation::set_frame_pointer;
        uint64_t location = 0;
        if (!reader.read_u64(location))
          return false;
        instruction.offset = location;
        break;
      }
      case 2: {
        uint8_t delta = 0;
        if (!reader.read_u8(delta))
          return false;
        instruction.operation = UnwindOperation::none;
        instruction.value = delta;
        break;
      }
      case 3: {
        uint16_t delta = 0;
        if (!reader.read_u16(delta))
          return false;
        instruction.operation = UnwindOperation::none;
        instruction.value = delta;
        break;
      }
      case 4: {
        uint32_t delta = 0;
        if (!reader.read_u32(delta))
          return false;
        instruction.operation = UnwindOperation::none;
        instruction.value = delta;
        break;
      }
      case 5: {
        uint64_t reg = 0, displacement = 0;
        if (!reader.read_uleb128(reg) || !reader.read_uleb128(displacement) ||
            reg > UINT32_MAX)
          return false;
        instruction.operation = UnwindOperation::save_register;
        instruction.register_number = static_cast<uint32_t>(reg);
        instruction.offset = displacement;
        break;
      }
      case 10:
        instruction.operation = UnwindOperation::restore_state;
        break;
      case 12: {
        uint64_t reg = 0, displacement = 0;
        if (!reader.read_uleb128(reg) || !reader.read_uleb128(displacement) ||
            reg > UINT32_MAX)
          return false;
        instruction.operation = UnwindOperation::set_frame_pointer;
        instruction.register_number = static_cast<uint32_t>(reg);
        instruction.offset = displacement;
        break;
      }
      case 14: {
        uint64_t displacement = 0;
        if (!reader.read_uleb128(displacement))
          return false;
        instruction.operation = UnwindOperation::allocate_stack;
        instruction.offset = displacement;
        break;
      }
      default:
        error = {ErrorCode::invalid_debug_info, offset,
                 "unsupported call-frame opcode"};
        return false;
      }
    }
    if (!append_unwind_instruction(record, instruction, limits, error, offset))
      return false;
  }
  return reader.position() == end;
}

} // namespace

UnwindParser::UnwindParser(Limits limits) : limits_(limits) {}

std::optional<UnwindReport>
UnwindParser::parse_eh_frame(const uint8_t *data, size_t size,
                             uint64_t section_address, WordSize word_size,
                             ByteOrder order, Error &error) const {
  error.clear();
  if (size > limits_.max_debug_bytes) {
    error = {ErrorCode::resource_limit, 0, "call-frame section exceeds limit"};
    return std::nullopt;
  }
  ByteReader reader(data, size, order);
  UnwindReport report;
  std::map<uint64_t, uint64_t> cie_offsets;
  while (reader.remaining()) {
    size_t record_offset = reader.position();
    uint32_t small_length = 0;
    if (!reader.read_u32(small_length)) {
      error = {ErrorCode::truncated, record_offset,
               "call-frame record length is truncated"};
      return std::nullopt;
    }
    if (!small_length)
      break;
    uint64_t length = small_length;
    if (small_length == 0xffffffffu && !reader.read_u64(length)) {
      error = {ErrorCode::truncated, record_offset,
               "extended call-frame length is truncated"};
      return std::nullopt;
    }
    size_t content_start = reader.position();
    if (length > reader.remaining()) {
      error = {ErrorCode::truncated, record_offset,
               "call-frame record exceeds section"};
      return std::nullopt;
    }
    size_t record_end = content_start + static_cast<size_t>(length);
    uint32_t identifier = 0;
    if (!reader.read_u32(identifier))
      return std::nullopt;
    if (identifier == 0) {
      cie_offsets[record_offset] = record_end;
      if (!reader.seek(record_end))
        return std::nullopt;
      continue;
    }
    uint64_t cie_address = content_start - identifier;
    if (!cie_offsets.count(cie_address)) {
      report.warnings.push_back("frame record references unknown CIE");
    }
    UnwindRecord record;
    if (!read_address(reader, word_size, record.start_address)) {
      error = {ErrorCode::truncated, reader.position(),
               "frame start address is truncated"};
      return std::nullopt;
    }
    uint64_t range = 0;
    if (!read_address(reader, word_size, range) ||
        !checked_add(record.start_address, range, record.end_address)) {
      error = {ErrorCode::address_overflow, reader.position(),
               "frame address range is invalid"};
      return std::nullopt;
    }
    if (!checked_add(record.start_address, section_address,
                     record.start_address) ||
        !checked_add(record.end_address, section_address, record.end_address)) {
      error = {ErrorCode::address_overflow, record_offset,
               "relocated frame range overflows"};
      return std::nullopt;
    }
    if (!parse_cfi_instructions(reader, record_end, record, limits_, error))
      return std::nullopt;
    uint64_t covered = record.end_address - record.start_address;
    uint64_t total = 0;
    if (!checked_add(report.covered_bytes, covered, total)) {
      error = {ErrorCode::address_overflow, record.start_address,
               "unwind coverage total overflows"};
      return std::nullopt;
    }
    report.covered_bytes = total;
    report.records.push_back(std::move(record));
    if (report.records.size() > limits_.max_debug_units) {
      error = {ErrorCode::resource_limit, record_offset,
               "unwind record limit exceeded"};
      return std::nullopt;
    }
  }
  return report;
}

std::optional<UnwindReport>
UnwindParser::parse_pe_functions(const uint8_t *data, size_t size,
                                 uint64_t image_base, Error &error) const {
  error.clear();
  if (size % 12 != 0 || size / 12 > limits_.max_debug_units) {
    error = {ErrorCode::invalid_debug_info, 0,
             "PE runtime-function table size is invalid"};
    return std::nullopt;
  }
  ByteReader reader(data, size, ByteOrder::little);
  UnwindReport report;
  for (size_t index = 0; index < size / 12; ++index) {
    uint32_t begin = 0, end = 0, unwind = 0;
    if (!reader.read_u32(begin) || !reader.read_u32(end) ||
        !reader.read_u32(unwind)) {
      error = {ErrorCode::truncated, reader.position(),
               "PE runtime-function entry is truncated"};
      return std::nullopt;
    }
    if (end < begin) {
      error = {ErrorCode::invalid_debug_info, index * 12,
               "PE runtime-function range is reversed"};
      return std::nullopt;
    }
    UnwindRecord record;
    if (!checked_add(image_base, begin, record.start_address) ||
        !checked_add(image_base, end, record.end_address) ||
        !checked_add(image_base, unwind, record.personality)) {
      error = {ErrorCode::address_overflow, index * 12,
               "PE runtime-function address overflows"};
      return std::nullopt;
    }
    record.instructions.push_back({UnwindOperation::finish, 0, unwind, 0});
    report.covered_bytes += end - begin;
    report.records.push_back(std::move(record));
  }
  return report;
}

} // namespace binforge
