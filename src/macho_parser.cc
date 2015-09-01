#include "binforge/binforge.h"
#include <algorithm>
namespace binforge {
namespace {
Architecture macho_arch(uint32_t cpu) {
  switch (cpu) {
  case 7:
    return Architecture::x86;
  case 0x01000007:
    return Architecture::x86_64;
  case 12:
    return Architecture::arm;
  case 0x0100000c:
    return Architecture::arm64;
  default:
    return Architecture::unknown;
  }
}
BinaryKind macho_kind(uint32_t k) {
  switch (k) {
  case 1:
    return BinaryKind::relocatable;
  case 2:
    return BinaryKind::executable;
  case 4:
    return BinaryKind::core;
  case 6:
  case 8:
    return BinaryKind::shared_library;
  default:
    return BinaryKind::unknown;
  }
}
uint8_t macho_protection(uint32_t p) {
  uint8_t out = 0;
  if (p & 1)
    out |= permission_read;
  if (p & 2)
    out |= permission_write;
  if (p & 4)
    out |= permission_execute;
  return out;
}
} // namespace
MachOParser::MachOParser(Limits l) : limits_(l) {}
std::optional<BinaryImage>
MachOParser::parse(std::shared_ptr<const std::vector<uint8_t>> data,
                   Error &error) const {
  if (!data || data->size() < 28) {
    error = {ErrorCode::truncated, 0, "Mach-O header truncated"};
    return std::nullopt;
  }
  uint32_t raw = uint32_t((*data)[0]) | (uint32_t((*data)[1]) << 8) |
                 (uint32_t((*data)[2]) << 16) | (uint32_t((*data)[3]) << 24);
  bool wide = raw == 0xfeedfacfu || raw == 0xcffaedfeu;
  ByteOrder order = (raw == 0xcefaedfeu || raw == 0xcffaedfeu)
                        ? ByteOrder::big
                        : ByteOrder::little;
  if (raw != 0xfeedfaceu && raw != 0xfeedfacfu && raw != 0xcefaedfeu &&
      raw != 0xcffaedfeu) {
    error = {ErrorCode::bad_magic, 0, "invalid Mach-O magic"};
    return std::nullopt;
  }
  ByteReader r(data->data(), data->size(), order);
  uint32_t magic, cpu, subcpu, file_type, command_count, command_bytes, flags,
      reserved;
  if (!r.read_u32(magic) || !r.read_u32(cpu) || !r.read_u32(subcpu) ||
      !r.read_u32(file_type) || !r.read_u32(command_count) ||
      !r.read_u32(command_bytes) || !r.read_u32(flags) ||
      (wide && !r.read_u32(reserved))) {
    error = {ErrorCode::truncated, 0, "Mach-O header truncated"};
    return std::nullopt;
  }
  uint64_t commands_offset = wide ? 32 : 28;
  if (command_count > limits_.max_sections ||
      !range_inside(commands_offset, command_bytes, data->size())) {
    error = {ErrorCode::invalid_count, commands_offset,
             "Mach-O load commands invalid"};
    return std::nullopt;
  }
  BinaryImage image;
  image.file_data = data;
  image.header.format = BinaryFormat::macho_like;
  image.header.word_size = wide ? WordSize::bits64 : WordSize::bits32;
  image.header.byte_order = order;
  image.header.kind = macho_kind(file_type);
  image.header.architecture = macho_arch(cpu);
  image.header.segment_table_offset = commands_offset;
  image.header.segment_count = command_count;
  image.header.flags = flags;
  uint64_t cursor = commands_offset;
  for (uint32_t ci = 0; ci < command_count; ++ci) {
    r.seek(cursor);
    uint32_t command, size;
    if (!r.read_u32(command) || !r.read_u32(size) || size < 8 ||
        !range_inside(cursor, size, data->size())) {
      error = {ErrorCode::invalid_segment, cursor, "Mach-O command invalid"};
      return std::nullopt;
    }
    bool segment32 = command == 1, segment64 = command == 0x19;
    if (segment32 || segment64) {
      Segment segment;
      segment.index = image.segments.size();
      std::string segname;
      if (!r.read_fixed_string(16, segname))
        return std::nullopt;
      uint64_t vmaddr, vmsize, fileoff, filesize;
      uint32_t maxprot, initprot, nsects, segflags;
      if (segment64) {
        if (!r.read_u64(vmaddr) || !r.read_u64(vmsize) ||
            !r.read_u64(fileoff) || !r.read_u64(filesize))
          return std::nullopt;
      } else {
        uint32_t a, b, c, d;
        if (!r.read_u32(a) || !r.read_u32(b) || !r.read_u32(c) ||
            !r.read_u32(d))
          return std::nullopt;
        vmaddr = a;
        vmsize = b;
        fileoff = c;
        filesize = d;
      }
      if (!r.read_u32(maxprot) || !r.read_u32(initprot) ||
          !r.read_u32(nsects) || !r.read_u32(segflags)) {
        error = {ErrorCode::truncated, r.position(),
                 "Mach-O segment truncated"};
        return std::nullopt;
      }
      if (nsects > limits_.max_sections - image.sections.size() ||
          filesize > vmsize || !range_inside(fileoff, filesize, data->size())) {
        error = {ErrorCode::invalid_segment, cursor,
                 "Mach-O segment ranges invalid"};
        return std::nullopt;
      }
      segment.file_offset = fileoff;
      segment.file_size = filesize;
      segment.virtual_address = vmaddr;
      segment.memory_size = vmsize;
      segment.alignment = limits_.page_size;
      segment.permissions = macho_protection(initprot);
      for (uint32_t si = 0; si < nsects; ++si) {
        Section section;
        section.index = image.sections.size();
        std::string parent;
        if (!r.read_fixed_string(16, section.name) ||
            !r.read_fixed_string(16, parent))
          return std::nullopt;
        uint64_t addr, sz;
        uint32_t offset, align, reloff, nreloc, sflags, res1, res2, res3 = 0;
        if (segment64) {
          if (!r.read_u64(addr) || !r.read_u64(sz))
            return std::nullopt;
        } else {
          uint32_t a, b;
          if (!r.read_u32(a) || !r.read_u32(b))
            return std::nullopt;
          addr = a;
          sz = b;
        }
        if (!r.read_u32(offset) || !r.read_u32(align) || !r.read_u32(reloff) ||
            !r.read_u32(nreloc) || !r.read_u32(sflags) || !r.read_u32(res1) ||
            !r.read_u32(res2) || (segment64 && !r.read_u32(res3)))
          return std::nullopt;
        if ((sflags & 0xff) != 1 && !range_inside(offset, sz, data->size())) {
          error = {ErrorCode::invalid_section, offset,
                   "Mach-O section outside file"};
          return std::nullopt;
        }
        section.file_offset = offset;
        section.file_size = (sflags & 0xff) == 1 ? 0 : sz;
        section.virtual_address = addr;
        section.memory_size = sz;
        section.alignment = align < 63 ? (uint64_t{1} << align) : 1;
        section.permissions = segment.permissions;
        section.kind = section.name.rfind("__debug", 0) == 0
                           ? SectionKind::debug
                           : ((sflags & 0xff) == 1 ? SectionKind::no_bits
                                                   : SectionKind::program_bits);
        segment.sections.push_back(section.index);
        image.sections.push_back(std::move(section));
      }
      image.segments.push_back(std::move(segment));
    }
    cursor += size;
  }
  image.header.section_count = image.sections.size();
  return image;
}
} // namespace binforge
