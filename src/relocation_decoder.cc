#include "binforge/binforge.h"

#include <limits>

namespace binforge {
namespace {

RelocationKind elf_kind(Architecture architecture, uint32_t type) {
  switch (architecture) {
  case Architecture::x86:
    switch (type) {
    case 1:
      return RelocationKind::absolute32;
    case 2:
      return RelocationKind::pc_relative32;
    case 8:
      return RelocationKind::relative32;
    default:
      return RelocationKind::none;
    }
  case Architecture::x86_64:
    switch (type) {
    case 1:
      return RelocationKind::absolute64;
    case 2:
      return RelocationKind::pc_relative32;
    case 8:
      return RelocationKind::relative64;
    case 9:
      return RelocationKind::got_relative;
    default:
      return RelocationKind::none;
    }
  case Architecture::arm:
    switch (type) {
    case 2:
      return RelocationKind::absolute32;
    case 3:
      return RelocationKind::pc_relative32;
    case 23:
      return RelocationKind::relative32;
    default:
      return RelocationKind::none;
    }
  case Architecture::arm64:
    switch (type) {
    case 257:
      return RelocationKind::absolute64;
    case 260:
      return RelocationKind::pc_relative32;
    case 1027:
      return RelocationKind::relative64;
    default:
      return RelocationKind::none;
    }
  case Architecture::riscv32:
  case Architecture::riscv64:
    switch (type) {
    case 1:
      return RelocationKind::absolute32;
    case 2:
      return RelocationKind::absolute64;
    case 3:
      return RelocationKind::relative64;
    default:
      return RelocationKind::none;
    }
  default:
    return RelocationKind::none;
  }
}

RelocationKind macho_kind(uint8_t type, bool external, bool pc_relative,
                          uint8_t width) {
  if (pc_relative)
    return RelocationKind::pc_relative32;
  if (type == 0)
    return width == 8 ? RelocationKind::absolute64 : RelocationKind::absolute32;
  if (type == 1 && !external)
    return width == 8 ? RelocationKind::relative64 : RelocationKind::relative32;
  if (type == 3)
    return RelocationKind::got_relative;
  if (type == 4)
    return RelocationKind::plt_relative;
  return RelocationKind::none;
}

bool append_relocation(const Relocation &relocation,
                       std::vector<Relocation> &output, const Limits &limits,
                       Error &error) {
  if (output.size() >= limits.max_relocations) {
    error = {ErrorCode::resource_limit, relocation.offset,
             "relocation output limit exceeded"};
    return false;
  }
  output.push_back(relocation);
  return true;
}

} // namespace

RelocationTableDecoder::RelocationTableDecoder(Limits limits)
    : limits_(limits) {}

bool RelocationTableDecoder::decode_elf(const uint8_t *data, size_t size,
                                        const RelocationDecodeOptions &options,
                                        std::vector<Relocation> &output,
                                        Error &error) const {
  error.clear();
  if (!data && size) {
    error = {ErrorCode::invalid_relocation, 0, "ELF relocation input is null"};
    return false;
  }

  bool wide = options.word_size == WordSize::bits64;
  uint64_t minimum =
      options.explicit_addends ? (wide ? 24 : 12) : (wide ? 16 : 8);
  uint64_t entry_size = options.entry_size ? options.entry_size : minimum;
  if (entry_size < minimum || entry_size > size || size % entry_size != 0) {
    error = {ErrorCode::invalid_relocation, 0,
             "ELF relocation entry size is invalid"};
    return false;
  }

  uint64_t count = size / entry_size;
  if (count > limits_.max_relocations - output.size()) {
    error = {ErrorCode::resource_limit, 0,
             "ELF relocation table exceeds record limit"};
    return false;
  }

  ByteReader reader(data, size, options.byte_order);
  for (uint64_t index = 0; index < count; ++index) {
    if (!reader.seek(index * entry_size)) {
      error = {ErrorCode::truncated, index * entry_size,
               "ELF relocation entry is truncated"};
      return false;
    }

    uint64_t offset = 0;
    uint64_t information = 0;
    int64_t addend = 0;
    if (wide) {
      if (!reader.read_u64(offset) || !reader.read_u64(information) ||
          (options.explicit_addends && !reader.read_i64(addend))) {
        error = {ErrorCode::truncated, reader.position(),
                 "ELF64 relocation entry is truncated"};
        return false;
      }
    } else {
      uint32_t small_offset = 0;
      uint32_t small_information = 0;
      int32_t small_addend = 0;
      if (!reader.read_u32(small_offset) ||
          !reader.read_u32(small_information) ||
          (options.explicit_addends && !reader.read_i32(small_addend))) {
        error = {ErrorCode::truncated, reader.position(),
                 "ELF32 relocation entry is truncated"};
        return false;
      }
      offset = small_offset;
      information = small_information;
      addend = small_addend;
    }

    uint64_t symbol = wide ? information >> 32 : information >> 8;
    uint32_t type = wide ? static_cast<uint32_t>(information)
                         : static_cast<uint8_t>(information);
    if (symbol > std::numeric_limits<uint32_t>::max()) {
      error = {ErrorCode::invalid_symbol, index * entry_size,
               "ELF relocation symbol index does not fit"};
      return false;
    }

    uint64_t target = 0;
    if (!checked_add(options.base_address, offset, target)) {
      error = {ErrorCode::address_overflow, index * entry_size,
               "ELF relocation target overflows"};
      return false;
    }

    Relocation relocation;
    relocation.index = static_cast<uint32_t>(output.size());
    relocation.kind = elf_kind(options.architecture, type);
    relocation.target_section = options.target_section;
    relocation.symbol_index = static_cast<uint32_t>(symbol);
    relocation.offset = target;
    relocation.addend = addend;
    relocation.width = (relocation.kind == RelocationKind::absolute64 ||
                        relocation.kind == RelocationKind::relative64)
                           ? 8
                           : 4;
    if (!append_relocation(relocation, output, limits_, error))
      return false;
  }
  return true;
}

bool RelocationTableDecoder::decode_pe_base(const uint8_t *data, size_t size,
                                            uint64_t image_base,
                                            std::vector<Relocation> &output,
                                            Error &error) const {
  error.clear();
  ByteReader reader(data, size, ByteOrder::little);
  while (reader.remaining()) {
    size_t block_offset = reader.position();
    uint32_t page_rva = 0;
    uint32_t block_size = 0;
    if (!reader.read_u32(page_rva) || !reader.read_u32(block_size)) {
      error = {ErrorCode::truncated, block_offset,
               "PE relocation block header is truncated"};
      return false;
    }
    if (block_size < 8 || block_size > size - block_offset ||
        (block_size - 8) % 2 != 0) {
      error = {ErrorCode::invalid_relocation, block_offset,
               "PE relocation block size is invalid"};
      return false;
    }

    uint32_t records = (block_size - 8) / 2;
    for (uint32_t index = 0; index < records; ++index) {
      uint16_t encoded = 0;
      if (!reader.read_u16(encoded)) {
        error = {ErrorCode::truncated, reader.position(),
                 "PE relocation record is truncated"};
        return false;
      }
      uint8_t type = encoded >> 12;
      uint16_t offset = encoded & 0xfff;
      if (type == 0)
        continue;

      uint64_t target = 0;
      uint64_t page = 0;
      if (!checked_add(image_base, page_rva, page) ||
          !checked_add(page, offset, target)) {
        error = {ErrorCode::address_overflow, block_offset,
                 "PE relocation target overflows"};
        return false;
      }

      Relocation relocation;
      relocation.index = static_cast<uint32_t>(output.size());
      relocation.offset = target;
      if (type == 3) {
        relocation.kind = RelocationKind::relative32;
        relocation.width = 4;
      } else if (type == 10) {
        relocation.kind = RelocationKind::relative64;
        relocation.width = 8;
      } else if (type == 1) {
        relocation.kind = RelocationKind::high16;
        relocation.width = 2;
      } else if (type == 2) {
        relocation.kind = RelocationKind::low16;
        relocation.width = 2;
      } else {
        relocation.kind = RelocationKind::none;
      }
      if (!append_relocation(relocation, output, limits_, error))
        return false;
    }
    if (!reader.seek(block_offset + block_size)) {
      error = {ErrorCode::truncated, block_offset,
               "PE relocation block extends beyond input"};
      return false;
    }
  }
  return true;
}

bool RelocationTableDecoder::decode_macho(
    const uint8_t *data, size_t size, const RelocationDecodeOptions &options,
    std::vector<Relocation> &output, Error &error) const {
  error.clear();
  if (size % 8 != 0) {
    error = {ErrorCode::invalid_relocation, 0,
             "Mach-O relocation table is not record aligned"};
    return false;
  }
  if (size / 8 > limits_.max_relocations - output.size()) {
    error = {ErrorCode::resource_limit, 0,
             "Mach-O relocation table exceeds record limit"};
    return false;
  }

  ByteReader reader(data, size, options.byte_order);
  for (size_t record = 0; record < size / 8; ++record) {
    int32_t signed_address = 0;
    uint32_t information = 0;
    if (!reader.read_i32(signed_address) || !reader.read_u32(information)) {
      error = {ErrorCode::truncated, record * 8,
               "Mach-O relocation entry is truncated"};
      return false;
    }

    if (signed_address < 0) {
      error = {ErrorCode::invalid_relocation, record * 8,
               "scattered Mach-O relocation is unsupported"};
      return false;
    }
    uint32_t symbol = information & 0x00ffffffu;
    bool pc_relative = (information >> 24) & 1u;
    uint8_t encoded_length = (information >> 25) & 3u;
    bool external = (information >> 27) & 1u;
    uint8_t type = information >> 28;
    uint8_t width = static_cast<uint8_t>(1u << encoded_length);

    uint64_t target = 0;
    if (!checked_add(options.base_address,
                     static_cast<uint32_t>(signed_address), target)) {
      error = {ErrorCode::address_overflow, record * 8,
               "Mach-O relocation target overflows"};
      return false;
    }

    Relocation relocation;
    relocation.index = static_cast<uint32_t>(output.size());
    relocation.kind = macho_kind(type, external, pc_relative, width);
    relocation.target_section = options.target_section;
    relocation.symbol_index = external ? symbol : 0;
    relocation.offset = target;
    relocation.width = width;
    if (!append_relocation(relocation, output, limits_, error))
      return false;
  }
  return true;
}

} // namespace binforge
