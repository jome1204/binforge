#include "binforge/binforge.h"
#include <algorithm>

namespace binforge {
namespace {

Architecture elf_arch(uint16_t machine) {
  switch (machine) {
  case 3:
    return Architecture::x86;
  case 62:
    return Architecture::x86_64;
  case 40:
    return Architecture::arm;
  case 183:
    return Architecture::arm64;
  case 243:
    return Architecture::riscv64;
  default:
    return Architecture::unknown;
  }
}

BinaryKind elf_kind(uint16_t type) {
  switch (type) {
  case 1:
    return BinaryKind::relocatable;
  case 2:
    return BinaryKind::executable;
  case 3:
    return BinaryKind::shared_library;
  case 4:
    return BinaryKind::core;
  default:
    return BinaryKind::unknown;
  }
}

SectionKind elf_section_kind(uint32_t type, std::string_view name) {
  switch (type) {
  case 1:
    return name.rfind(".debug", 0) == 0 ? SectionKind::debug
                                        : SectionKind::program_bits;
  case 2:
    return SectionKind::symbol_table;
  case 3:
    return SectionKind::string_table;
  case 4:
    return SectionKind::relocation_addends;
  case 7:
    return SectionKind::notes;
  case 8:
    return SectionKind::no_bits;
  case 9:
    return SectionKind::relocations;
  case 11:
    return SectionKind::dynamic_symbols;
  default:
    return name.rfind(".debug", 0) == 0 ? SectionKind::debug
                                        : SectionKind::unknown;
  }
}

SymbolKind elf_symbol_kind(uint8_t info) {
  switch (info & 0xf) {
  case 1:
    return SymbolKind::object;
  case 2:
    return SymbolKind::function;
  case 3:
    return SymbolKind::section;
  case 4:
    return SymbolKind::file;
  case 5:
    return SymbolKind::common;
  case 6:
    return SymbolKind::tls_object;
  default:
    return SymbolKind::unknown;
  }
}

SymbolBinding elf_binding(uint8_t info, uint16_t section) {
  if (section == 0)
    return SymbolBinding::import_symbol;
  switch (info >> 4) {
  case 1:
    return SymbolBinding::global;
  case 2:
    return SymbolBinding::weak;
  default:
    return SymbolBinding::local;
  }
}

struct RawSection {
  uint32_t name = 0, type = 0;
  uint64_t flags = 0, address = 0, offset = 0, size = 0;
  uint32_t link = 0, info = 0;
  uint64_t alignment = 1, entry_size = 0;
};

bool read_section(ByteReader &r, bool wide, RawSection &s) {
  if (!r.read_u32(s.name) || !r.read_u32(s.type))
    return false;
  if (wide)
    return r.read_u64(s.flags) && r.read_u64(s.address) &&
           r.read_u64(s.offset) && r.read_u64(s.size) && r.read_u32(s.link) &&
           r.read_u32(s.info) && r.read_u64(s.alignment) &&
           r.read_u64(s.entry_size);
  uint32_t flags, address, offset, size, alignment, entry_size;
  if (!r.read_u32(flags) || !r.read_u32(address) || !r.read_u32(offset) ||
      !r.read_u32(size) || !r.read_u32(s.link) || !r.read_u32(s.info) ||
      !r.read_u32(alignment) || !r.read_u32(entry_size))
    return false;
  s.flags = flags;
  s.address = address;
  s.offset = offset;
  s.size = size;
  s.alignment = alignment;
  s.entry_size = entry_size;
  return true;
}

bool table_string(const std::vector<uint8_t> &data, const RawSection &table,
                  uint32_t offset, uint64_t maximum, std::string &value) {
  if (offset >= table.size || table.size > maximum)
    return false;
  ByteReader reader(data.data(), data.size());
  return reader.read_c_string(table.offset + offset, table.size - offset,
                              value);
}

} // namespace

ElfParser::ElfParser(Limits limits) : limits_(limits) {}

std::optional<BinaryImage>
ElfParser::parse(std::shared_ptr<const std::vector<uint8_t>> data,
                 Error &error) const {
  if (!data || data->size() < 52 || (*data)[4] < 1 || (*data)[4] > 2) {
    error = {ErrorCode::truncated, 0, "ELF identification is truncated"};
    return std::nullopt;
  }
  bool wide = (*data)[4] == 2;
  ByteOrder order;
  if ((*data)[5] == 1)
    order = ByteOrder::little;
  else if ((*data)[5] == 2)
    order = ByteOrder::big;
  else {
    error = {ErrorCode::unsupported_endian, 5, "invalid ELF encoding"};
    return std::nullopt;
  }
  ByteReader reader(data->data(), data->size(), order);
  BinaryImage image;
  uint64_t table_bytes = 0;
  std::vector<RawSection> raw;
  if (!reader.seek(16))
    return std::nullopt;
  uint16_t type, machine;
  uint32_t version;
  if (!reader.read_u16(type) || !reader.read_u16(machine) ||
      !reader.read_u32(version) || version != 1) {
    error = {ErrorCode::invalid_header, 16, "invalid ELF common header"};
    return std::nullopt;
  }
  uint64_t entry = 0, program_offset = 0, section_offset = 0;
  uint32_t flags = 0;
  uint16_t header_size, program_entry_size, program_count;
  uint16_t section_entry_size, section_count, names_index;
  if (wide) {
    if (!reader.read_u64(entry) || !reader.read_u64(program_offset) ||
        !reader.read_u64(section_offset))
      goto truncated;
  } else {
    uint32_t a, b, c;
    if (!reader.read_u32(a) || !reader.read_u32(b) || !reader.read_u32(c))
      goto truncated;
    entry = a;
    program_offset = b;
    section_offset = c;
  }
  if (!reader.read_u32(flags) || !reader.read_u16(header_size) ||
      !reader.read_u16(program_entry_size) || !reader.read_u16(program_count) ||
      !reader.read_u16(section_entry_size) || !reader.read_u16(section_count) ||
      !reader.read_u16(names_index))
    goto truncated;
  if (section_count > limits_.max_sections ||
      program_count > limits_.max_segments) {
    error = {ErrorCode::resource_limit, 0, "ELF table count exceeds limits"};
    return std::nullopt;
  }
  if (!checked_multiply(section_entry_size, section_count, table_bytes) ||
      !range_inside(section_offset, table_bytes, data->size()) ||
      (section_count && section_entry_size < (wide ? 64u : 40u))) {
    error = {ErrorCode::invalid_section, section_offset,
             "ELF section table is invalid"};
    return std::nullopt;
  }
  raw.resize(section_count);
  for (uint32_t i = 0; i < section_count; ++i) {
    if (!reader.seek(section_offset + uint64_t(i) * section_entry_size) ||
        !read_section(reader, wide, raw[i]))
      goto truncated;
    if (raw[i].type != 8 &&
        !range_inside(raw[i].offset, raw[i].size, data->size())) {
      error = {ErrorCode::file_range_overflow, raw[i].offset,
               "ELF section data is outside file"};
      return std::nullopt;
    }
  }
  image.file_data = data;
  image.header.format = BinaryFormat::elf_like;
  image.header.word_size = wide ? WordSize::bits64 : WordSize::bits32;
  image.header.byte_order = order;
  image.header.kind = elf_kind(type);
  image.header.architecture = elf_arch(machine);
  image.header.entry_point = entry;
  image.header.section_table_offset = section_offset;
  image.header.segment_table_offset = program_offset;
  image.header.section_count = section_count;
  image.header.segment_count = program_count;
  image.header.flags = flags;
  for (uint32_t i = 0; i < section_count; ++i) {
    Section section;
    section.index = i;
    section.file_offset = raw[i].offset;
    section.file_size = raw[i].size;
    section.virtual_address = raw[i].address;
    section.memory_size = raw[i].size;
    section.alignment = raw[i].alignment ? raw[i].alignment : 1;
    section.entry_size = raw[i].entry_size;
    section.link = raw[i].link;
    section.info = raw[i].info;
    section.permissions = permission_read;
    if (raw[i].flags & 1)
      section.permissions |= permission_write;
    if (raw[i].flags & 4)
      section.permissions |= permission_execute;
    if (names_index < section_count)
      table_string(*data, raw[names_index], raw[i].name,
                   limits_.max_string_bytes, section.name);
    section.kind = elf_section_kind(raw[i].type, section.name);
    image.sections.push_back(std::move(section));
  }
  if (!checked_multiply(program_entry_size, program_count, table_bytes) ||
      !range_inside(program_offset, table_bytes, data->size()) ||
      (program_count && program_entry_size < (wide ? 56u : 32u))) {
    error = {ErrorCode::invalid_segment, program_offset,
             "ELF program table is invalid"};
    return std::nullopt;
  }
  for (uint32_t i = 0; i < program_count; ++i) {
    reader.seek(program_offset + uint64_t(i) * program_entry_size);
    uint32_t kind, pflags = 0;
    Segment segment;
    segment.index = i;
    if (!reader.read_u32(kind))
      goto truncated;
    if (wide) {
      if (!reader.read_u32(pflags) || !reader.read_u64(segment.file_offset) ||
          !reader.read_u64(segment.virtual_address))
        goto truncated;
      uint64_t physical;
      if (!reader.read_u64(physical) || !reader.read_u64(segment.file_size) ||
          !reader.read_u64(segment.memory_size) ||
          !reader.read_u64(segment.alignment))
        goto truncated;
    } else {
      uint32_t off, va, physical, fs, ms, align;
      if (!reader.read_u32(off) || !reader.read_u32(va) ||
          !reader.read_u32(physical) || !reader.read_u32(fs) ||
          !reader.read_u32(ms) || !reader.read_u32(pflags) ||
          !reader.read_u32(align))
        goto truncated;
      segment.file_offset = off;
      segment.virtual_address = va;
      segment.file_size = fs;
      segment.memory_size = ms;
      segment.alignment = align;
    }
    if (kind != 1)
      continue;
    if (segment.file_size > segment.memory_size ||
        !range_inside(segment.file_offset, segment.file_size, data->size())) {
      error = {ErrorCode::invalid_segment, segment.file_offset,
               "ELF load segment range is invalid"};
      return std::nullopt;
    }
    if (pflags & 4)
      segment.permissions |= permission_read;
    if (pflags & 2)
      segment.permissions |= permission_write;
    if (pflags & 1)
      segment.permissions |= permission_execute;
    image.segments.push_back(std::move(segment));
  }
  for (uint32_t si = 0; si < raw.size(); ++si) {
    const auto &s = raw[si];
    if (s.type != 2 && s.type != 11)
      continue;
    if (!s.entry_size || s.link >= raw.size())
      continue;
    uint64_t count = s.size / s.entry_size;
    if (count > limits_.max_symbols) {
      error = {ErrorCode::resource_limit, s.offset, "ELF symbol limit"};
      return std::nullopt;
    }
    for (uint64_t j = 0; j < count; ++j) {
      reader.seek(s.offset + j * s.entry_size);
      uint32_t name;
      uint8_t info, other;
      uint16_t shndx;
      uint64_t value, size;
      if (wide) {
        if (!reader.read_u32(name) || !reader.read_u8(info) ||
            !reader.read_u8(other) || !reader.read_u16(shndx) ||
            !reader.read_u64(value) || !reader.read_u64(size))
          goto truncated;
      } else {
        uint32_t v, z;
        if (!reader.read_u32(name) || !reader.read_u32(v) ||
            !reader.read_u32(z) || !reader.read_u8(info) ||
            !reader.read_u8(other) || !reader.read_u16(shndx))
          goto truncated;
        value = v;
        size = z;
      }
      Symbol symbol;
      symbol.index = image.symbols.size();
      symbol.value = value;
      symbol.size = size;
      symbol.section_index = shndx;
      symbol.visibility = other & 3;
      symbol.kind = elf_symbol_kind(info);
      symbol.binding = elf_binding(info, shndx);
      table_string(*data, raw[s.link], name, limits_.max_string_bytes,
                   symbol.name);
      image.symbols.push_back(std::move(symbol));
    }
  }
  for (uint32_t section_index = 0; section_index < raw.size();
       ++section_index) {
    const RawSection &section = raw[section_index];
    if (section.type != 4 && section.type != 9)
      continue;
    if (!section.size)
      continue;
    RelocationDecodeOptions options;
    options.architecture = image.header.architecture;
    options.word_size = image.header.word_size;
    options.byte_order = image.header.byte_order;
    options.target_section = section.info;
    options.entry_size = section.entry_size;
    options.explicit_addends = section.type == 4;
    if (image.header.kind == BinaryKind::relocatable &&
        section.info < image.sections.size())
      options.base_address = image.sections[section.info].virtual_address;
    RelocationTableDecoder decoder(limits_);
    Error relocation_error;
    if (!decoder.decode_elf(data->data() + section.offset, section.size,
                            options, image.relocations, relocation_error)) {
      error = relocation_error;
      return std::nullopt;
    }
  }
  return image;
truncated:
  error = {ErrorCode::truncated, reader.position(),
           "ELF structure is truncated"};
  return std::nullopt;
}

} // namespace binforge
