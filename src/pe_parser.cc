#include "binforge/binforge.h"
#include <algorithm>

namespace binforge {
namespace {
Architecture pe_arch(uint16_t machine) {
  switch (machine) {
  case 0x14c:
    return Architecture::x86;
  case 0x8664:
    return Architecture::x86_64;
  case 0x1c0:
  case 0x1c4:
    return Architecture::arm;
  case 0xaa64:
    return Architecture::arm64;
  case 0x5032:
    return Architecture::riscv32;
  case 0x5064:
    return Architecture::riscv64;
  default:
    return Architecture::unknown;
  }
}
uint8_t pe_permissions(uint32_t flags) {
  uint8_t p = permission_none;
  if (flags & 0x40000000u)
    p |= permission_read;
  if (flags & 0x80000000u)
    p |= permission_write;
  if (flags & 0x20000000u)
    p |= permission_execute;
  return p;
}
SectionKind pe_section_kind(std::string_view name, uint32_t flags) {
  if (name == ".debug" || name.rfind(".debug", 0) == 0)
    return SectionKind::debug;
  if (name == ".idata")
    return SectionKind::imports;
  if (name == ".edata")
    return SectionKind::exports;
  if (name == ".reloc")
    return SectionKind::relocations;
  if (name == ".rsrc")
    return SectionKind::resources;
  if (flags & 0x80u)
    return SectionKind::no_bits;
  return SectionKind::program_bits;
}
bool rva_to_file(const std::vector<Section> &sections, uint64_t rva,
                 uint64_t size, uint64_t &offset) {
  for (auto &s : sections) {
    uint64_t span = std::max(s.file_size, s.memory_size);
    if (rva >= s.virtual_address &&
        range_inside(rva - s.virtual_address, size, span)) {
      uint64_t delta = rva - s.virtual_address;
      if (delta > s.file_size || size > s.file_size - delta)
        return false;
      return checked_add(s.file_offset, delta, offset);
    }
  }
  return false;
}
} // namespace
PeParser::PeParser(Limits l) : limits_(l) {}
std::optional<BinaryImage>
PeParser::parse(std::shared_ptr<const std::vector<uint8_t>> data,
                Error &error) const {
  if (!data || data->size() < 64 || (*data)[0] != 'M' || (*data)[1] != 'Z') {
    error = {ErrorCode::bad_magic, 0, "invalid DOS signature"};
    return std::nullopt;
  }
  ByteReader r(data->data(), data->size());
  if (!r.seek(0x3c)) {
    error = {ErrorCode::truncated, 0x3c, "missing PE pointer"};
    return std::nullopt;
  }
  uint32_t peoff;
  if (!r.read_u32(peoff) || !range_inside(peoff, 24, data->size())) {
    error = {ErrorCode::invalid_offset, 0x3c, "PE header offset outside file"};
    return std::nullopt;
  }
  r.seek(peoff);
  uint32_t signature;
  uint16_t machine, sections;
  uint32_t timestamp, symbol_offset, symbol_count;
  uint16_t optional_size, characteristics;
  if (!r.read_u32(signature) || signature != 0x00004550u ||
      !r.read_u16(machine) || !r.read_u16(sections) || !r.read_u32(timestamp) ||
      !r.read_u32(symbol_offset) || !r.read_u32(symbol_count) ||
      !r.read_u16(optional_size) || !r.read_u16(characteristics)) {
    error = {ErrorCode::invalid_header, peoff, "truncated PE file header"};
    return std::nullopt;
  }
  if (sections > limits_.max_sections) {
    error = {ErrorCode::resource_limit, peoff, "PE section count limit"};
    return std::nullopt;
  }
  uint64_t optional_offset = peoff + 24;
  if (!range_inside(optional_offset, optional_size, data->size())) {
    error = {ErrorCode::truncated, optional_offset,
             "PE optional header truncated"};
    return std::nullopt;
  }
  r.seek(optional_offset);
  uint16_t magic;
  if (!r.read_u16(magic) || (magic != 0x10b && magic != 0x20b)) {
    error = {ErrorCode::unsupported_class, optional_offset,
             "unknown PE optional header"};
    return std::nullopt;
  }
  bool wide = magic == 0x20b;
  uint8_t linker_major, linker_minor;
  uint32_t code_size, initialized_size, uninitialized_size, entry, code_base;
  if (!r.read_u8(linker_major) || !r.read_u8(linker_minor) ||
      !r.read_u32(code_size) || !r.read_u32(initialized_size) ||
      !r.read_u32(uninitialized_size) || !r.read_u32(entry) ||
      !r.read_u32(code_base)) {
    error = {ErrorCode::truncated, r.position(),
             "PE optional header fields truncated"};
    return std::nullopt;
  }
  uint64_t image_base;
  if (wide) {
    if (!r.read_u64(image_base))
      return std::nullopt;
  } else {
    uint32_t data_base, base;
    if (!r.read_u32(data_base) || !r.read_u32(base))
      return std::nullopt;
    image_base = base;
  }
  uint32_t section_alignment, file_alignment;
  if (!r.read_u32(section_alignment) || !r.read_u32(file_alignment) ||
      !section_alignment || !file_alignment) {
    error = {ErrorCode::invalid_alignment, r.position(),
             "invalid PE alignment"};
    return std::nullopt;
  }
  uint64_t section_table = optional_offset + optional_size, table_bytes;
  if (!checked_multiply(sections, 40, table_bytes) ||
      !range_inside(section_table, table_bytes, data->size())) {
    error = {ErrorCode::invalid_section, section_table,
             "PE section table outside file"};
    return std::nullopt;
  }
  BinaryImage image;
  image.file_data = data;
  image.header.format = BinaryFormat::pe_like;
  image.header.word_size = wide ? WordSize::bits64 : WordSize::bits32;
  image.header.byte_order = ByteOrder::little;
  image.header.kind = (characteristics & 0x2000) ? BinaryKind::shared_library
                                                 : BinaryKind::executable;
  image.header.architecture = pe_arch(machine);
  image.header.entry_point = image_base + entry;
  image.header.image_base = image_base;
  image.header.section_table_offset = section_table;
  image.header.section_count = sections;
  image.header.flags = characteristics;
  for (uint32_t i = 0; i < sections; ++i) {
    r.seek(section_table + uint64_t(i) * 40);
    Section s;
    s.index = i;
    if (!r.read_fixed_string(8, s.name))
      return std::nullopt;
    uint32_t virtual_size, rva, raw_size, raw_offset, reloc, line, reloc_count,
        line_count, flags;
    if (!r.read_u32(virtual_size) || !r.read_u32(rva) ||
        !r.read_u32(raw_size) || !r.read_u32(raw_offset) ||
        !r.read_u32(reloc) || !r.read_u32(line) || !r.read_u32(reloc_count) ||
        !r.read_u32(line_count) || !r.read_u32(flags)) {
      error = {ErrorCode::truncated, r.position(),
               "PE section header truncated"};
      return std::nullopt;
    }
    if (raw_size && !range_inside(raw_offset, raw_size, data->size())) {
      error = {ErrorCode::file_range_overflow, raw_offset,
               "PE section outside file"};
      return std::nullopt;
    }
    s.file_offset = raw_offset;
    s.file_size = raw_size;
    s.virtual_address = rva;
    s.memory_size = std::max<uint64_t>(virtual_size, raw_size);
    s.alignment = section_alignment;
    s.permissions = pe_permissions(flags);
    s.kind = pe_section_kind(s.name, flags);
    image.sections.push_back(s);
    Segment seg;
    seg.index = i;
    seg.file_offset = s.file_offset;
    seg.file_size = s.file_size;
    seg.virtual_address = s.virtual_address;
    seg.memory_size = s.memory_size;
    seg.alignment = s.alignment;
    seg.permissions = s.permissions;
    seg.sections = {i};
    image.segments.push_back(std::move(seg));
  }
  if (symbol_count && symbol_count <= limits_.max_symbols &&
      range_inside(symbol_offset, uint64_t(symbol_count) * 18, data->size())) {
    uint64_t string_base = symbol_offset + uint64_t(symbol_count) * 18;
    uint32_t string_size = 0;
    if (range_inside(string_base, 4, data->size())) {
      r.seek(string_base);
      r.read_u32(string_size);
    }
    for (uint32_t i = 0; i < symbol_count;) {
      r.seek(symbol_offset + uint64_t(i) * 18);
      uint32_t zero, name_offset;
      std::string name;
      r.read_u32(zero);
      r.read_u32(name_offset);
      if (zero == 0 && name_offset < string_size) {
        ByteReader sr(data->data(), data->size());
        sr.read_c_string(string_base + name_offset, string_size - name_offset,
                         name);
      } else {
        r.seek(symbol_offset + uint64_t(i) * 18);
        r.read_fixed_string(8, name);
      }
      uint32_t value;
      uint16_t section_index, type;
      uint8_t storage, aux;
      r.read_u32(value);
      r.read_u16(section_index);
      r.read_u16(type);
      r.read_u8(storage);
      r.read_u8(aux);
      Symbol symbol;
      symbol.index = image.symbols.size();
      symbol.name = std::move(name);
      symbol.value = value;
      symbol.section_index = section_index;
      symbol.kind = (type & 0x20) ? SymbolKind::function : SymbolKind::unknown;
      symbol.binding =
          storage == 2 ? SymbolBinding::global : SymbolBinding::local;
      image.symbols.push_back(std::move(symbol));
      uint32_t step = uint32_t(aux) + 1;
      if (step > symbol_count - i)
        break;
      i += step;
    }
  }
  return image;
}
} // namespace binforge
