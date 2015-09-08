#include "binforge/binforge.h"
namespace binforge {
DebugInfoParser::DebugInfoParser(Limits l) : limits_(l) {}
bool DebugInfoParser::parse_line_program(const uint8_t *data, size_t size,
                                         ByteOrder order, uint8_t address_size,
                                         DebugUnit &unit, Error &error) const {
  if (!data || size < 10 || size > limits_.max_debug_bytes ||
      (address_size != 4 && address_size != 8)) {
    error = {ErrorCode::invalid_debug_info, 0, "invalid line program input"};
    return false;
  }
  ByteReader r(data, size, order);
  uint32_t unit_length;
  if (!r.read_u32(unit_length) || unit_length > r.remaining()) {
    error = {ErrorCode::truncated, 0, "line unit truncated"};
    return false;
  }
  uint16_t version;
  if (!r.read_u16(version) || version < 2 || version > 5) {
    error = {ErrorCode::invalid_debug_info, 4, "unsupported line version"};
    return false;
  }
  uint32_t header_length;
  if (!r.read_u32(header_length) || header_length > r.remaining()) {
    error = {ErrorCode::truncated, 6, "line header truncated"};
    return false;
  }
  size_t program_start = r.position() + header_length;
  uint8_t minimum_instruction, default_statement, line_base, line_range,
      opcode_base;
  if (!r.read_u8(minimum_instruction) || !r.read_u8(default_statement) ||
      !r.read_u8(line_base) || !r.read_u8(line_range) ||
      !r.read_u8(opcode_base) || !minimum_instruction || !line_range) {
    error = {ErrorCode::invalid_debug_info, r.position(),
             "invalid line header"};
    return false;
  }
  if (opcode_base && !r.skip(opcode_base - 1)) {
    error = {ErrorCode::truncated, r.position(), "opcode lengths truncated"};
    return false;
  }
  while (r.position() < program_start) {
    std::string file;
    if (!r.read_c_string(r.position(), program_start - r.position(), file))
      break;
    r.skip(file.size() + 1);
    if (file.empty())
      break;
    unit.files.push_back(std::move(file));
    if (unit.files.size() > limits_.max_string_bytes) {
      error = {ErrorCode::resource_limit, r.position(), "file table limit"};
      return false;
    }
  }
  if (!r.seek(program_start))
    return false;
  uint64_t address = 0;
  int64_t line = 1;
  uint32_t file = 1;
  bool statement = default_statement != 0;
  while (r.remaining() && unit.lines.size() < limits_.max_line_rows) {
    uint8_t op;
    if (!r.read_u8(op))
      break;
    if (op == 0) {
      uint64_t length;
      if (!r.read_uleb128(length) || !length || length > r.remaining()) {
        error = {ErrorCode::truncated, r.position(),
                 "extended line opcode truncated"};
        return false;
      }
      uint8_t extended;
      r.read_u8(extended);
      if (extended == 1) {
        unit.lines.push_back(
            {address, file, static_cast<uint32_t>(line), 0, statement, true});
        address = 0;
        line = 1;
        file = 1;
        statement = default_statement != 0;
        r.skip(length - 1);
      } else if (extended == 2) {
        if (length - 1 != address_size) {
          error = {ErrorCode::invalid_debug_info, r.position(),
                   "invalid set-address width"};
          return false;
        }
        uint64_t value = 0;
        if (address_size == 4) {
          uint32_t v;
          if (!r.read_u32(v))
            return false;
          value = v;
        } else if (!r.read_u64(value))
          return false;
        address = value;
      } else
        r.skip(length - 1);
    } else if (op < opcode_base) {
      switch (op) {
      case 1:
        unit.lines.push_back(
            {address, file, static_cast<uint32_t>(line), 0, statement, false});
        break;
      case 2: {
        uint64_t advance;
        if (!r.read_uleb128(advance) ||
            !checked_add(address, advance * minimum_instruction, address)) {
          error = {ErrorCode::address_overflow, r.position(),
                   "line address overflow"};
          return false;
        }
        break;
      }
      case 3: {
        int64_t advance;
        if (!r.read_sleb128(advance))
          return false;
        line += advance;
        if (line < 0) {
          error = {ErrorCode::invalid_debug_info, r.position(),
                   "negative source line"};
          return false;
        }
        break;
      }
      case 4: {
        uint64_t f;
        if (!r.read_uleb128(f) || f > UINT32_MAX)
          return false;
        file = f;
        break;
      }
      case 6:
        statement = !statement;
        break;
      default:
        break;
      }
    } else {
      uint8_t adjusted = op - opcode_base;
      uint64_t address_delta = (adjusted / line_range) * minimum_instruction;
      int64_t line_delta = int8_t(line_base) + (adjusted % line_range);
      if (!checked_add(address, address_delta, address)) {
        error = {ErrorCode::address_overflow, r.position(),
                 "special opcode overflow"};
        return false;
      }
      line += line_delta;
      if (line < 0)
        return false;
      unit.lines.push_back(
          {address, file, static_cast<uint32_t>(line), 0, statement, false});
    }
  }
  if (unit.lines.size() >= limits_.max_line_rows) {
    error = {ErrorCode::resource_limit, r.position(), "line row limit"};
    return false;
  }
  unit.version = version;
  unit.length = unit_length;
  unit.address_size = address_size;
  return true;
}
bool DebugInfoParser::parse_entries(const uint8_t *data, size_t size,
                                    ByteOrder order, uint8_t address_size,
                                    DebugUnit &unit, Error &error) const {
  (void)address_size;
  if (!data || size > limits_.max_debug_bytes) {
    error = {ErrorCode::resource_limit, 0, "debug entry input limit"};
    return false;
  }
  ByteReader r(data, size, order);
  std::vector<std::vector<DebugEntry> *> levels{&unit.entries};
  while (r.remaining()) {
    uint64_t tag;
    if (!r.read_uleb128(tag)) {
      error = {ErrorCode::truncated, r.position(), "debug tag truncated"};
      return false;
    }
    if (tag == 0) {
      if (levels.size() == 1)
        break;
      levels.pop_back();
      continue;
    }
    if (levels.size() > limits_.max_debug_depth) {
      error = {ErrorCode::resource_limit, r.position(), "debug nesting limit"};
      return false;
    }
    uint8_t children, attributes;
    if (!r.read_u8(children) || !r.read_u8(attributes)) {
      error = {ErrorCode::truncated, r.position(),
               "debug entry header truncated"};
      return false;
    }
    DebugEntry entry;
    entry.offset = r.position();
    entry.tag = tag;
    entry.has_children = children != 0;
    for (uint8_t a = 0; a < attributes; ++a) {
      DebugAttribute attr;
      uint64_t name, form;
      if (!r.read_uleb128(name) || !r.read_uleb128(form)) {
        error = {ErrorCode::truncated, r.position(),
                 "debug attribute truncated"};
        return false;
      }
      attr.name = name;
      attr.form = form;
      if (form == 1) {
        uint64_t v;
        if (!r.read_uleb128(v))
          return false;
        attr.value = v;
      } else if (form == 2) {
        int64_t v;
        if (!r.read_sleb128(v))
          return false;
        attr.value = v;
      } else if (form == 3) {
        uint64_t length;
        if (!r.read_uleb128(length) || length > r.remaining() ||
            length > limits_.max_string_bytes)
          return false;
        std::vector<uint8_t> bytes;
        if (!r.read_bytes(length, bytes))
          return false;
        attr.value = std::string(bytes.begin(), bytes.end());
      } else {
        error = {ErrorCode::invalid_debug_info, r.position(),
                 "unknown debug attribute form"};
        return false;
      }
      entry.attributes.push_back(std::move(attr));
    }
    levels.back()->push_back(std::move(entry));
    if (children)
      levels.push_back(&levels.back()->back().children);
  }
  return true;
}
} // namespace binforge
