#include "binforge/binforge.h"
#include <algorithm>
#include <cstring>

namespace binforge {

bool MemoryRegion::contains(uint64_t address, uint64_t length) const {
  if (address < base)
    return false;
  return range_inside(address - base, length, size);
}

AddressSpace::AddressSpace(Limits limits) : limits_(limits) {}

bool AddressSpace::map(uint64_t base, uint64_t size, uint8_t permissions,
                       std::string name, Error &error) {
  if (!size) {
    error = {ErrorCode::invalid_segment, base, "cannot map an empty region"};
    return false;
  }
  uint64_t end = 0;
  if (!checked_add(base, size, end)) {
    error = {ErrorCode::address_overflow, base, "mapping address overflows"};
    return false;
  }
  uint64_t total = 0;
  if (!checked_add(mapped_bytes_, size, total) ||
      total > limits_.max_mapped_bytes || size > SIZE_MAX) {
    error = {ErrorCode::resource_limit, base, "mapped byte limit exceeded"};
    return false;
  }
  auto next = regions_.lower_bound(base);
  if (next != regions_.end() && end > next->second.base) {
    error = {ErrorCode::mapping_overlap, base, "mapping overlaps next region"};
    return false;
  }
  if (next != regions_.begin()) {
    auto previous = std::prev(next);
    uint64_t previous_end = 0;
    if (!checked_add(previous->second.base, previous->second.size,
                     previous_end) ||
        previous_end > base) {
      error = {ErrorCode::mapping_overlap, base,
               "mapping overlaps previous region"};
      return false;
    }
  }
  MemoryRegion region;
  region.base = base;
  region.size = size;
  region.permissions = permissions;
  region.name = std::move(name);
  region.bytes.resize(static_cast<size_t>(size), 0);
  regions_.emplace(base, std::move(region));
  mapped_bytes_ = total;
  return true;
}

bool AddressSpace::unmap(uint64_t base, Error &error) {
  auto found = regions_.find(base);
  if (found == regions_.end()) {
    error = {ErrorCode::mapping_missing, base, "mapping does not exist"};
    return false;
  }
  mapped_bytes_ -= found->second.size;
  regions_.erase(found);
  return true;
}

bool AddressSpace::protect(uint64_t base, uint64_t size, uint8_t permissions,
                           Error &error) {
  auto *region = region_at(base);
  if (!region || region->base != base || region->size != size) {
    error = {ErrorCode::mapping_missing, base,
             "protection range must match a complete mapping"};
    return false;
  }
  region->permissions = permissions;
  return true;
}

const MemoryRegion *AddressSpace::region_at(uint64_t address) const {
  auto next = regions_.upper_bound(address);
  if (next == regions_.begin())
    return nullptr;
  auto candidate = std::prev(next);
  return candidate->second.contains(address) ? &candidate->second : nullptr;
}

MemoryRegion *AddressSpace::region_at(uint64_t address) {
  return const_cast<MemoryRegion *>(
      static_cast<const AddressSpace *>(this)->region_at(address));
}

bool AddressSpace::read(uint64_t address, uint8_t *output, size_t size,
                        Error &error) const {
  if (!size)
    return true;
  auto *region = region_at(address);
  if (!region || !region->contains(address, size)) {
    error = {ErrorCode::mapping_missing, address,
             "read crosses an unmapped boundary"};
    return false;
  }
  if (!(region->permissions & permission_read)) {
    error = {ErrorCode::permission_denied, address, "mapping is not readable"};
    return false;
  }
  std::memcpy(output, region->bytes.data() + (address - region->base), size);
  return true;
}

bool AddressSpace::write(uint64_t address, const uint8_t *input, size_t size,
                         Error &error, bool ignore_permissions) {
  if (!size)
    return true;
  auto *region = region_at(address);
  if (!region || !region->contains(address, size)) {
    error = {ErrorCode::mapping_missing, address,
             "write crosses an unmapped boundary"};
    return false;
  }
  if (!ignore_permissions && !(region->permissions & permission_write)) {
    error = {ErrorCode::permission_denied, address, "mapping is not writable"};
    return false;
  }
  std::memcpy(region->bytes.data() + (address - region->base), input, size);
  return true;
}

bool AddressSpace::read_integer(uint64_t address, uint8_t width,
                                ByteOrder order, uint64_t &value,
                                Error &error) const {
  if (width != 1 && width != 2 && width != 4 && width != 8) {
    error = {ErrorCode::invalid_relocation, address,
             "integer width is unsupported"};
    return false;
  }
  uint8_t bytes[8]{};
  if (!read(address, bytes, width, error))
    return false;
  value = 0;
  if (order == ByteOrder::little) {
    for (int i = width - 1; i >= 0; --i)
      value = (value << 8) | bytes[i];
  } else {
    for (uint8_t i = 0; i < width; ++i)
      value = (value << 8) | bytes[i];
  }
  return true;
}

bool AddressSpace::write_integer(uint64_t address, uint8_t width,
                                 ByteOrder order, uint64_t value, Error &error,
                                 bool ignore_permissions) {
  if (width != 1 && width != 2 && width != 4 && width != 8) {
    error = {ErrorCode::invalid_relocation, address,
             "integer width is unsupported"};
    return false;
  }
  uint8_t bytes[8]{};
  for (uint8_t i = 0; i < width; ++i) {
    uint8_t destination = order == ByteOrder::little ? i : width - i - 1;
    bytes[destination] = static_cast<uint8_t>(value >> (i * 8));
  }
  return write(address, bytes, width, error, ignore_permissions);
}

void AddressSpace::clear() {
  regions_.clear();
  mapped_bytes_ = 0;
}

bool SymbolResolver::add_export(std::string library, Export symbol,
                                Error &error) {
  auto name_key = std::make_pair(library, symbol.name);
  auto ordinal_key = std::make_pair(std::move(library), symbol.ordinal);
  if ((!symbol.name.empty() && named_.count(name_key)) ||
      ordinal_.count(ordinal_key)) {
    error = {ErrorCode::duplicate_export, 0, "duplicate exported symbol"};
    return false;
  }
  if (!symbol.name.empty())
    named_.emplace(std::move(name_key), symbol.address);
  ordinal_.emplace(std::move(ordinal_key), symbol.address);
  return true;
}

std::optional<uint64_t> SymbolResolver::resolve(std::string_view library,
                                                std::string_view name,
                                                uint64_t ordinal) const {
  if (!name.empty()) {
    auto found = named_.find({std::string(library), std::string(name)});
    if (found != named_.end())
      return found->second;
  }
  auto found = ordinal_.find({std::string(library), ordinal});
  if (found != ordinal_.end())
    return found->second;
  return std::nullopt;
}

void SymbolResolver::clear() {
  named_.clear();
  ordinal_.clear();
}

} // namespace binforge
