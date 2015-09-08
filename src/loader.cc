#include "binforge/binforge.h"
#include <algorithm>
#include <cstring>
namespace binforge {
BinaryLoader::BinaryLoader(Limits l) : limits_(l) {}
std::optional<LoadResult> BinaryLoader::load(const BinaryImage &image,
                                             AddressSpace &memory,
                                             const LoadOptions &options,
                                             const SymbolResolver *resolver,
                                             Error &error) const {
  auto report = BinaryValidator(limits_).validate(image);
  if (!report.valid) {
    error = report.errors.front();
    return std::nullopt;
  }
  uint64_t original_base = image.header.image_base;
  if (!original_base && !image.segments.empty())
    original_base =
        std::min_element(image.segments.begin(), image.segments.end(),
                         [](auto &a, auto &b) {
                           return a.virtual_address < b.virtual_address;
                         })
            ->virtual_address;
  uint64_t base =
      options.preferred_base ? options.preferred_base : original_base;
  uint64_t bias = base - original_base;
  LoadResult result;
  result.load_base = base;
  for (auto &segment : image.segments) {
    if (!segment.memory_size)
      continue;
    uint64_t address;
    if (!checked_add(segment.virtual_address, bias, address)) {
      error = {ErrorCode::address_overflow, segment.virtual_address,
               "segment load address overflow"};
      return std::nullopt;
    }
    uint64_t aligned_base = address & ~uint64_t(limits_.page_size - 1);
    uint64_t prefix = address - aligned_base, total, aligned_size;
    if (!checked_add(prefix, segment.memory_size, total) ||
        !checked_align_up(total, limits_.page_size, aligned_size)) {
      error = {ErrorCode::address_overflow, address,
               "aligned segment size overflow"};
      return std::nullopt;
    }
    uint8_t initial = segment.permissions | permission_write;
    if (options.enforce_wx && (initial & permission_write) &&
        (initial & permission_execute))
      initial &= ~permission_execute;
    if (!memory.map(aligned_base, aligned_size, initial,
                    "segment." + std::to_string(segment.index), error))
      return std::nullopt;
    if (segment.file_size) {
      if (!image.file_data ||
          !range_inside(segment.file_offset, segment.file_size,
                        image.file_data->size())) {
        error = {ErrorCode::file_range_overflow, segment.file_offset,
                 "segment data unavailable"};
        return std::nullopt;
      }
      if (!memory.write(address, image.file_data->data() + segment.file_offset,
                        segment.file_size, error, true))
        return std::nullopt;
    }
    result.mapped_bytes += aligned_size;
  }
  if (options.apply_relocations) {
    RelocationProcessor processor(limits_);
    if (!processor.apply(image, memory, bias, resolver,
                         result.relocations_applied, error))
      return std::nullopt;
  }
  if (options.resolve_imports) {
    for (auto &import : image.imports) {
      if (!resolver) {
        if (import.weak)
          continue;
        error = {ErrorCode::unresolved_import, import.slot_address,
                 "no import resolver"};
        return std::nullopt;
      }
      auto target =
          resolver->resolve(import.library, import.name, import.ordinal);
      if (!target) {
        if (import.weak)
          continue;
        error = {ErrorCode::unresolved_import, import.slot_address,
                 "unresolved import: " + import.name};
        return std::nullopt;
      }
      uint64_t slot;
      if (!checked_add(import.slot_address, bias, slot) ||
          !memory.write_integer(slot,
                                static_cast<uint8_t>(image.header.word_size),
                                image.header.byte_order, *target, error, true))
        return std::nullopt;
      ++result.imports_resolved;
    }
  }
  uint64_t entry = image.header.entry_point;
  if (entry && original_base && entry >= original_base) {
    if (!checked_add(entry, bias, result.entry_point)) {
      error = {ErrorCode::address_overflow, entry, "entry point overflow"};
      return std::nullopt;
    }
  } else
    result.entry_point = entry;
  return result;
}
RelocationProcessor::RelocationProcessor(Limits l) : limits_(l) {}
bool RelocationProcessor::apply(const BinaryImage &i, AddressSpace &m,
                                uint64_t b, const SymbolResolver *r,
                                uint32_t &applied, Error &e) const {
  applied = 0;
  if (i.relocations.size() > limits_.max_relocations) {
    e = {ErrorCode::resource_limit, 0, "relocation count limit"};
    return false;
  }
  for (auto &rel : i.relocations) {
    if (!apply_one(rel, i, m, b, r, e))
      return false;
    ++applied;
  }
  return true;
}
bool RelocationProcessor::apply_one(const Relocation &rel,
                                    const BinaryImage &image,
                                    AddressSpace &memory, uint64_t bias,
                                    const SymbolResolver *resolver,
                                    Error &error) const {
  uint64_t target;
  if (!checked_add(rel.offset, bias, target)) {
    error = {ErrorCode::address_overflow, rel.offset,
             "relocation target overflow"};
    return false;
  }
  uint8_t width = rel.width ? rel.width
                            : ((rel.kind == RelocationKind::absolute64 ||
                                rel.kind == RelocationKind::relative64)
                                   ? 8
                                   : 4);
  uint64_t symbol_value = 0;
  if (rel.symbol_index) {
    auto *symbol = image.symbol(rel.symbol_index);
    if (!symbol) {
      error = {ErrorCode::invalid_symbol, target,
               "relocation symbol index invalid"};
      return false;
    }
    if (symbol->binding == SymbolBinding::import_symbol && resolver) {
      auto value = resolver->resolve(symbol->library, symbol->name, 0);
      if (!value) {
        error = {ErrorCode::unresolved_import, target,
                 "relocation import unresolved"};
        return false;
      }
      symbol_value = *value;
    } else if (!checked_add(symbol->value, bias, symbol_value)) {
      error = {ErrorCode::address_overflow, target, "symbol address overflow"};
      return false;
    }
  }
  uint64_t value;
  switch (rel.kind) {
  case RelocationKind::relative32:
  case RelocationKind::relative64:
    value = bias + static_cast<uint64_t>(rel.addend);
    break;
  case RelocationKind::pc_relative32:
    value = symbol_value + static_cast<uint64_t>(rel.addend) - target;
    break;
  case RelocationKind::absolute32:
  case RelocationKind::absolute64:
    value = symbol_value + static_cast<uint64_t>(rel.addend);
    break;
  case RelocationKind::high16:
    value = (symbol_value + static_cast<uint64_t>(rel.addend)) >> 16;
    width = 2;
    break;
  case RelocationKind::low16:
    value = (symbol_value + static_cast<uint64_t>(rel.addend)) & 0xffff;
    width = 2;
    break;
  case RelocationKind::none:
    return true;
  default:
    error = {ErrorCode::invalid_relocation, target,
             "unsupported relocation kind"};
    return false;
  }
  if (width < 8 && value >= (uint64_t{1} << (width * 8))) {
    error = {ErrorCode::address_overflow, target,
             "relocation result does not fit"};
    return false;
  }
  return memory.write_integer(target, width, image.header.byte_order, value,
                              error, true);
}
} // namespace binforge
