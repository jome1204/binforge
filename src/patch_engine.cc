#include "binforge/binforge.h"

#include <algorithm>
#include <cstring>

namespace binforge {
namespace {

void append_u32(std::vector<uint8_t> &output, uint32_t value) {
  for (unsigned shift = 0; shift < 32; shift += 8)
    output.push_back(static_cast<uint8_t>(value >> shift));
}

void append_u64(std::vector<uint8_t> &output, uint64_t value) {
  for (unsigned shift = 0; shift < 64; shift += 8)
    output.push_back(static_cast<uint8_t>(value >> shift));
}

bool operation_size(const PatchOperation &operation, uint64_t &size) {
  switch (operation.kind) {
  case PatchOperationKind::write_bytes:
  case PatchOperationKind::assert_bytes:
    size = operation.bytes.size();
    return operation.length == 0 || operation.length == size;
  case PatchOperationKind::fill_bytes:
  case PatchOperationKind::copy_bytes:
    size = operation.length;
    return true;
  case PatchOperationKind::write_integer:
    size = operation.width;
    return size == 1 || size == 2 || size == 4 || size == 8;
  }
  return false;
}

uint32_t memory_checksum(const AddressSpace &memory) {
  uint32_t combined = 0;
  for (const auto &item : memory.regions()) {
    const MemoryRegion &region = item.second;
    uint32_t region_checksum = crc32(region.bytes.data(), region.bytes.size());
    combined ^=
        region_checksum + 0x9e3779b9u + (combined << 6) + (combined >> 2);
  }
  return combined;
}

} // namespace

PatchEngine::PatchEngine(Limits limits) : limits_(limits) {}

bool PatchEngine::validate(const PatchPlan &plan, const AddressSpace &memory,
                           Error &error) const {
  error.clear();
  if (plan.operations.size() > limits_.max_relocations) {
    error = {ErrorCode::resource_limit, 0, "patch operation limit exceeded"};
    return false;
  }
  uint64_t total_written = 0;
  for (size_t index = 0; index < plan.operations.size(); ++index) {
    const PatchOperation &operation = plan.operations[index];
    uint64_t size = 0;
    if (!operation_size(operation, size) || !size) {
      error = {ErrorCode::invalid_relocation, index,
               "patch operation has an invalid size"};
      return false;
    }
    uint64_t end = 0;
    if (!checked_add(operation.address, size, end)) {
      error = {ErrorCode::address_overflow, operation.address,
               "patch destination range overflows"};
      return false;
    }
    const MemoryRegion *region = memory.region_at(operation.address);
    if (!region || !region->contains(operation.address, size)) {
      error = {ErrorCode::mapping_missing, operation.address,
               "patch destination is not fully mapped"};
      return false;
    }
    if (operation.kind == PatchOperationKind::copy_bytes) {
      uint64_t source_end = 0;
      if (!checked_add(operation.source_address, size, source_end)) {
        error = {ErrorCode::address_overflow, operation.source_address,
                 "patch source range overflows"};
        return false;
      }
      const MemoryRegion *source = memory.region_at(operation.source_address);
      if (!source || !source->contains(operation.source_address, size)) {
        error = {ErrorCode::mapping_missing, operation.source_address,
                 "patch source is not fully mapped"};
        return false;
      }
    }
    if (operation.kind != PatchOperationKind::assert_bytes) {
      uint64_t next = 0;
      if (!checked_add(total_written, size, next) ||
          next > limits_.max_mapped_bytes) {
        error = {ErrorCode::resource_limit, operation.address,
                 "patch write-byte limit exceeded"};
        return false;
      }
      total_written = next;
    }
  }
  if (plan.bytes_written && plan.bytes_written != total_written) {
    error = {ErrorCode::invalid_relocation, 0,
             "patch declared write count does not match operations"};
    return false;
  }
  return true;
}

std::optional<PatchResult> PatchEngine::apply(const PatchPlan &plan,
                                              AddressSpace &memory,
                                              Error &error) const {
  if (!validate(plan, memory, error))
    return std::nullopt;
  if (plan.expected_checksum &&
      memory_checksum(memory) != plan.expected_checksum) {
    error = {ErrorCode::invalid_header, 0,
             "patch precondition checksum does not match"};
    return std::nullopt;
  }

  struct Undo {
    uint64_t address;
    std::vector<uint8_t> bytes;
  };
  std::vector<Undo> undo;
  PatchResult result;
  for (const PatchOperation &operation : plan.operations) {
    uint64_t size = 0;
    operation_size(operation, size);
    std::vector<uint8_t> before(static_cast<size_t>(size));
    if (!memory.read(operation.address, before.data(), before.size(), error)) {
      for (auto iterator = undo.rbegin(); iterator != undo.rend(); ++iterator) {
        Error ignored;
        memory.write(iterator->address, iterator->bytes.data(),
                     iterator->bytes.size(), ignored, true);
      }
      return std::nullopt;
    }
    if (operation.kind == PatchOperationKind::assert_bytes) {
      if (before != operation.bytes) {
        error = {ErrorCode::invalid_header, operation.address,
                 "patch byte assertion failed"};
        for (auto iterator = undo.rbegin(); iterator != undo.rend();
             ++iterator) {
          Error ignored;
          memory.write(iterator->address, iterator->bytes.data(),
                       iterator->bytes.size(), ignored, true);
        }
        return std::nullopt;
      }
      ++result.operations_applied;
      continue;
    }
    undo.push_back({operation.address, std::move(before)});
    bool success = false;
    switch (operation.kind) {
    case PatchOperationKind::write_bytes:
      success = memory.write(operation.address, operation.bytes.data(),
                             operation.bytes.size(), error, true);
      break;
    case PatchOperationKind::fill_bytes: {
      std::vector<uint8_t> fill(static_cast<size_t>(size), operation.fill);
      success = memory.write(operation.address, fill.data(), fill.size(), error,
                             true);
      break;
    }
    case PatchOperationKind::write_integer:
      success = memory.write_integer(operation.address, operation.width,
                                     operation.byte_order, operation.integer,
                                     error, true);
      break;
    case PatchOperationKind::copy_bytes: {
      std::vector<uint8_t> copy(static_cast<size_t>(size));
      success = memory.read(operation.source_address, copy.data(), copy.size(),
                            error) &&
                memory.write(operation.address, copy.data(), copy.size(), error,
                             true);
      break;
    }
    case PatchOperationKind::assert_bytes:
      break;
    }
    if (!success) {
      for (auto iterator = undo.rbegin(); iterator != undo.rend(); ++iterator) {
        Error ignored;
        memory.write(iterator->address, iterator->bytes.data(),
                     iterator->bytes.size(), ignored, true);
      }
      return std::nullopt;
    }
    ++result.operations_applied;
    result.bytes_written += size;
  }
  result.resulting_checksum = memory_checksum(memory);
  return result;
}

std::vector<uint8_t> PatchEngine::encode(const PatchPlan &plan,
                                         Error &error) const {
  error.clear();
  if (plan.name.size() > limits_.max_string_bytes ||
      plan.operations.size() > limits_.max_relocations) {
    error = {ErrorCode::resource_limit, 0, "patch plan exceeds encode limits"};
    return {};
  }
  std::vector<uint8_t> output = {'B', 'F', 'P', 'T'};
  append_u32(output, 1);
  append_u32(output, static_cast<uint32_t>(plan.name.size()));
  output.insert(output.end(), plan.name.begin(), plan.name.end());
  append_u32(output, plan.expected_checksum);
  append_u64(output, plan.bytes_written);
  append_u32(output, static_cast<uint32_t>(plan.operations.size()));
  for (const PatchOperation &operation : plan.operations) {
    output.push_back(static_cast<uint8_t>(operation.kind));
    append_u64(output, operation.address);
    append_u64(output, operation.source_address);
    append_u64(output, operation.length);
    append_u64(output, operation.integer);
    output.push_back(operation.width);
    output.push_back(operation.fill);
    output.push_back(static_cast<uint8_t>(operation.byte_order));
    append_u32(output, static_cast<uint32_t>(operation.bytes.size()));
    output.insert(output.end(), operation.bytes.begin(), operation.bytes.end());
    if (output.size() > limits_.max_file_size) {
      error = {ErrorCode::resource_limit, output.size(),
               "encoded patch exceeds size limit"};
      return {};
    }
  }
  append_u32(output, crc32(output.data(), output.size()));
  return output;
}

std::optional<PatchPlan> PatchEngine::decode(const uint8_t *data, size_t size,
                                             Error &error) const {
  error.clear();
  if (!data || size < 28 || size > limits_.max_file_size ||
      std::memcmp(data, "BFPT", 4) != 0) {
    error = {ErrorCode::bad_magic, 0, "patch container is invalid"};
    return std::nullopt;
  }
  uint32_t stored = uint32_t(data[size - 4]) | (uint32_t(data[size - 3]) << 8) |
                    (uint32_t(data[size - 2]) << 16) |
                    (uint32_t(data[size - 1]) << 24);
  if (stored != crc32(data, size - 4)) {
    error = {ErrorCode::invalid_header, size - 4,
             "patch checksum does not match"};
    return std::nullopt;
  }
  ByteReader reader(data + 4, size - 8, ByteOrder::little);
  uint32_t version = 0, name_size = 0, operation_count = 0;
  PatchPlan plan;
  if (!reader.read_u32(version) || version != 1 ||
      !reader.read_u32(name_size) || name_size > limits_.max_string_bytes ||
      name_size > reader.remaining()) {
    error = {ErrorCode::invalid_header, 4, "patch header is invalid"};
    return std::nullopt;
  }
  std::vector<uint8_t> name;
  if (!reader.read_bytes(name_size, name))
    return std::nullopt;
  plan.name.assign(name.begin(), name.end());
  if (!reader.read_u32(plan.expected_checksum) ||
      !reader.read_u64(plan.bytes_written) ||
      !reader.read_u32(operation_count) ||
      operation_count > limits_.max_relocations) {
    error = {ErrorCode::resource_limit, reader.position(),
             "patch operation count is invalid"};
    return std::nullopt;
  }
  for (uint32_t index = 0; index < operation_count; ++index) {
    PatchOperation operation;
    uint8_t kind = 0, order = 0;
    uint32_t byte_count = 0;
    if (!reader.read_u8(kind) || !reader.read_u64(operation.address) ||
        !reader.read_u64(operation.source_address) ||
        !reader.read_u64(operation.length) ||
        !reader.read_u64(operation.integer) ||
        !reader.read_u8(operation.width) || !reader.read_u8(operation.fill) ||
        !reader.read_u8(order) || !reader.read_u32(byte_count) ||
        byte_count > limits_.max_section_bytes ||
        byte_count > reader.remaining()) {
      error = {ErrorCode::truncated, reader.position(),
               "patch operation is truncated"};
      return std::nullopt;
    }
    if (kind > static_cast<uint8_t>(PatchOperationKind::assert_bytes) ||
        order > static_cast<uint8_t>(ByteOrder::big)) {
      error = {ErrorCode::invalid_header, reader.position(),
               "patch operation enum is invalid"};
      return std::nullopt;
    }
    operation.kind = static_cast<PatchOperationKind>(kind);
    operation.byte_order = static_cast<ByteOrder>(order);
    if (!reader.read_bytes(byte_count, operation.bytes))
      return std::nullopt;
    plan.operations.push_back(std::move(operation));
  }
  if (reader.remaining()) {
    error = {ErrorCode::invalid_header, reader.position(),
             "patch container contains trailing data"};
    return std::nullopt;
  }
  return plan;
}

} // namespace binforge
