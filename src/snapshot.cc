#include "binforge/binforge.h"

#include <cstring>

namespace binforge {
namespace {

void snapshot_u32(std::vector<uint8_t> &bytes, uint32_t value) {
  for (unsigned shift = 0; shift < 32; shift += 8)
    bytes.push_back(static_cast<uint8_t>(value >> shift));
}
void snapshot_u64(std::vector<uint8_t> &bytes, uint64_t value) {
  for (unsigned shift = 0; shift < 64; shift += 8)
    bytes.push_back(static_cast<uint8_t>(value >> shift));
}

} // namespace

MemorySnapshotCodec::MemorySnapshotCodec(Limits limits) : limits_(limits) {}

MemorySnapshot MemorySnapshotCodec::capture(const AddressSpace &memory,
                                            bool include_bytes,
                                            Error &error) const {
  error.clear();
  MemorySnapshot snapshot;
  snapshot.mapped_bytes = memory.mapped_bytes();
  if (snapshot.mapped_bytes > limits_.max_mapped_bytes ||
      memory.regions().size() > limits_.max_segments) {
    error = {ErrorCode::resource_limit, 0,
             "address space exceeds snapshot limits"};
    return snapshot;
  }
  for (const auto &item : memory.regions()) {
    const MemoryRegion &source = item.second;
    SnapshotRegion region;
    region.base = source.base;
    region.size = source.size;
    region.permissions = source.permissions;
    region.name = source.name;
    region.checksum = crc32(source.bytes.data(), source.bytes.size());
    if (include_bytes)
      region.bytes = source.bytes;
    snapshot.regions.push_back(std::move(region));
  }
  return snapshot;
}

bool MemorySnapshotCodec::restore(const MemorySnapshot &snapshot,
                                  AddressSpace &memory, Error &error) const {
  error.clear();
  if (snapshot.version != 1 ||
      snapshot.mapped_bytes > limits_.max_mapped_bytes ||
      snapshot.regions.size() > limits_.max_segments) {
    error = {ErrorCode::resource_limit, 0,
             "memory snapshot metadata is invalid"};
    return false;
  }
  AddressSpace staged(limits_);
  uint64_t total = 0;
  for (const SnapshotRegion &source : snapshot.regions) {
    if (!source.size || source.size > limits_.max_mapped_bytes ||
        source.name.size() > limits_.max_string_bytes ||
        (!source.bytes.empty() && source.bytes.size() != source.size)) {
      error = {ErrorCode::invalid_segment, source.base,
               "snapshot region is invalid"};
      return false;
    }
    uint64_t next = 0;
    if (!checked_add(total, source.size, next) ||
        next > limits_.max_mapped_bytes) {
      error = {ErrorCode::resource_limit, source.base,
               "snapshot mapped-byte total exceeds limit"};
      return false;
    }
    total = next;
    if (!staged.map(source.base, source.size, source.permissions, source.name,
                    error))
      return false;
    if (!source.bytes.empty()) {
      if (crc32(source.bytes.data(), source.bytes.size()) != source.checksum) {
        error = {ErrorCode::invalid_header, source.base,
                 "snapshot region checksum does not match"};
        return false;
      }
      if (!staged.write(source.base, source.bytes.data(), source.bytes.size(),
                        error, true))
        return false;
    }
  }
  if (snapshot.mapped_bytes != total) {
    error = {ErrorCode::invalid_header, 0,
             "snapshot mapped-byte total does not match regions"};
    return false;
  }
  memory = std::move(staged);
  return true;
}

std::vector<uint8_t> MemorySnapshotCodec::encode(const MemorySnapshot &snapshot,
                                                 Error &error) const {
  error.clear();
  if (snapshot.regions.size() > limits_.max_segments ||
      snapshot.mapped_bytes > limits_.max_mapped_bytes) {
    error = {ErrorCode::resource_limit, 0, "snapshot exceeds encoding limits"};
    return {};
  }
  std::vector<uint8_t> output = {'B', 'F', 'S', 'N'};
  snapshot_u32(output, snapshot.version);
  snapshot_u64(output, snapshot.mapped_bytes);
  snapshot_u32(output, static_cast<uint32_t>(snapshot.regions.size()));
  for (const SnapshotRegion &region : snapshot.regions) {
    if (region.name.size() > limits_.max_string_bytes ||
        region.bytes.size() > limits_.max_mapped_bytes) {
      error = {ErrorCode::resource_limit, region.base,
               "snapshot region exceeds encoding limits"};
      return {};
    }
    snapshot_u64(output, region.base);
    snapshot_u64(output, region.size);
    output.push_back(region.permissions);
    snapshot_u32(output, static_cast<uint32_t>(region.name.size()));
    output.insert(output.end(), region.name.begin(), region.name.end());
    snapshot_u32(output, region.checksum);
    snapshot_u64(output, region.bytes.size());
    output.insert(output.end(), region.bytes.begin(), region.bytes.end());
  }
  snapshot_u32(output, crc32(output.data(), output.size()));
  return output;
}

std::optional<MemorySnapshot> MemorySnapshotCodec::decode(const uint8_t *data,
                                                          size_t size,
                                                          Error &error) const {
  error.clear();
  if (!data || size < 24 || std::memcmp(data, "BFSN", 4) != 0 ||
      size > limits_.max_mapped_bytes + limits_.max_file_size) {
    error = {ErrorCode::bad_magic, 0, "snapshot container is invalid"};
    return std::nullopt;
  }
  uint32_t stored = uint32_t(data[size - 4]) | (uint32_t(data[size - 3]) << 8) |
                    (uint32_t(data[size - 2]) << 16) |
                    (uint32_t(data[size - 1]) << 24);
  if (stored != crc32(data, size - 4)) {
    error = {ErrorCode::invalid_header, size - 4,
             "snapshot container checksum does not match"};
    return std::nullopt;
  }
  ByteReader reader(data + 4, size - 8, ByteOrder::little);
  MemorySnapshot snapshot;
  uint32_t count = 0;
  if (!reader.read_u32(snapshot.version) ||
      !reader.read_u64(snapshot.mapped_bytes) || !reader.read_u32(count) ||
      snapshot.version != 1 || count > limits_.max_segments ||
      snapshot.mapped_bytes > limits_.max_mapped_bytes) {
    error = {ErrorCode::invalid_header, 4,
             "snapshot container header is invalid"};
    return std::nullopt;
  }
  for (uint32_t index = 0; index < count; ++index) {
    SnapshotRegion region;
    uint32_t name_size = 0;
    uint64_t byte_size = 0;
    if (!reader.read_u64(region.base) || !reader.read_u64(region.size) ||
        !reader.read_u8(region.permissions) || !reader.read_u32(name_size) ||
        name_size > limits_.max_string_bytes ||
        name_size > reader.remaining()) {
      error = {ErrorCode::truncated, reader.position(),
               "snapshot region header is truncated"};
      return std::nullopt;
    }
    std::vector<uint8_t> name;
    if (!reader.read_bytes(name_size, name) ||
        !reader.read_u32(region.checksum) || !reader.read_u64(byte_size) ||
        byte_size > limits_.max_mapped_bytes ||
        byte_size > reader.remaining()) {
      error = {ErrorCode::truncated, reader.position(),
               "snapshot region data is truncated"};
      return std::nullopt;
    }
    region.name.assign(name.begin(), name.end());
    if (!reader.read_bytes(static_cast<size_t>(byte_size), region.bytes))
      return std::nullopt;
    snapshot.regions.push_back(std::move(region));
  }
  if (reader.remaining()) {
    error = {ErrorCode::invalid_header, reader.position(),
             "snapshot container contains trailing bytes"};
    return std::nullopt;
  }
  return snapshot;
}

} // namespace binforge
