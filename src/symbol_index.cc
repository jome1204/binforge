#include "binforge/binforge.h"

#include <algorithm>

namespace binforge {

AddressTranslator::AddressTranslator(const BinaryImage &image)
    : image_(image) {}

std::optional<FileAddress>
AddressTranslator::virtual_to_file(uint64_t address, uint64_t length) const {
  for (const Section &section : image_.sections) {
    if (address < section.virtual_address)
      continue;
    uint64_t displacement = address - section.virtual_address;
    if (!range_inside(displacement, length, section.memory_size))
      continue;
    if (!range_inside(displacement, length, section.file_size))
      return std::nullopt;
    uint64_t offset = 0;
    if (!checked_add(section.file_offset, displacement, offset))
      return std::nullopt;
    return FileAddress{offset, section.file_size - displacement, section.index};
  }

  for (const Segment &segment : image_.segments) {
    if (address < segment.virtual_address)
      continue;
    uint64_t displacement = address - segment.virtual_address;
    if (!range_inside(displacement, length, segment.file_size))
      continue;
    uint64_t offset = 0;
    if (!checked_add(segment.file_offset, displacement, offset))
      return std::nullopt;
    return FileAddress{offset, segment.file_size - displacement, UINT32_MAX};
  }
  return std::nullopt;
}

std::optional<uint64_t>
AddressTranslator::file_to_virtual(uint64_t offset, uint64_t length) const {
  for (const Section &section : image_.sections) {
    if (offset < section.file_offset)
      continue;
    uint64_t displacement = offset - section.file_offset;
    if (!range_inside(displacement, length, section.file_size))
      continue;
    uint64_t address = 0;
    if (checked_add(section.virtual_address, displacement, address))
      return address;
    return std::nullopt;
  }
  for (const Segment &segment : image_.segments) {
    if (offset < segment.file_offset)
      continue;
    uint64_t displacement = offset - segment.file_offset;
    if (!range_inside(displacement, length, segment.file_size))
      continue;
    uint64_t address = 0;
    if (checked_add(segment.virtual_address, displacement, address))
      return address;
    return std::nullopt;
  }
  return std::nullopt;
}

std::optional<FileAddress>
AddressTranslator::rva_to_file(uint64_t rva, uint64_t length) const {
  uint64_t address = rva;
  if (image_.header.image_base) {
    if (!checked_add(image_.header.image_base, rva, address))
      return std::nullopt;
    if (auto translated = virtual_to_file(address, length))
      return translated;
  }

  for (const Section &section : image_.sections) {
    if (rva < section.virtual_address)
      continue;
    uint64_t displacement = rva - section.virtual_address;
    if (!range_inside(displacement, length, section.file_size))
      continue;
    uint64_t offset = 0;
    if (!checked_add(section.file_offset, displacement, offset))
      return std::nullopt;
    return FileAddress{offset, section.file_size - displacement, section.index};
  }
  return std::nullopt;
}

SymbolIndex::SymbolIndex(Limits limits) : limits_(limits) {}

bool SymbolIndex::build(const BinaryImage &image, Error &error) {
  clear();
  if (image.symbols.size() > limits_.max_symbols) {
    error = {ErrorCode::resource_limit, 0, "symbol index limit exceeded"};
    return false;
  }

  for (const Symbol &symbol : image.symbols) {
    if (!symbol.name.empty()) {
      auto inserted = names_.emplace(symbol.name, &symbol);
      if (!inserted.second) {
        const Symbol *existing = inserted.first->second;
        if (existing->binding == SymbolBinding::local &&
            symbol.binding != SymbolBinding::local)
          inserted.first->second = &symbol;
      }
      qualified_.emplace(std::make_pair(symbol.library, symbol.name), &symbol);
    }
    if (symbol.value && symbol.kind != SymbolKind::file &&
        symbol.kind != SymbolKind::section) {
      auto inserted = addresses_.emplace(symbol.value, &symbol);
      if (!inserted.second && inserted.first->second->size == 0 &&
          symbol.size != 0)
        inserted.first->second = &symbol;
    }
  }
  return true;
}

const Symbol *SymbolIndex::by_name(std::string_view name) const {
  auto found = names_.find(std::string(name));
  return found == names_.end() ? nullptr : found->second;
}

const Symbol *SymbolIndex::by_qualified_name(std::string_view library,
                                             std::string_view name) const {
  auto found = qualified_.find({std::string(library), std::string(name)});
  return found == qualified_.end() ? nullptr : found->second;
}

SymbolLookupResult SymbolIndex::nearest(uint64_t address) const {
  SymbolLookupResult result;
  auto next = addresses_.upper_bound(address);
  if (next == addresses_.begin())
    return result;
  auto found = std::prev(next);
  result.symbol = found->second;
  result.displacement = address - found->first;
  result.exact = result.displacement == 0;
  if (result.symbol->size && result.displacement >= result.symbol->size)
    result.symbol = nullptr;
  return result;
}

std::vector<const Symbol *> SymbolIndex::prefix(std::string_view prefix_value,
                                                size_t maximum) const {
  std::vector<const Symbol *> result;
  if (!maximum)
    return result;
  auto found = names_.lower_bound(std::string(prefix_value));
  while (found != names_.end() && result.size() < maximum) {
    if (found->first.compare(0, prefix_value.size(), prefix_value) != 0)
      break;
    result.push_back(found->second);
    ++found;
  }
  return result;
}

void SymbolIndex::clear() {
  names_.clear();
  qualified_.clear();
  addresses_.clear();
}

} // namespace binforge
