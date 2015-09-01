#include "binforge/binforge.h"
#include <cstring>

namespace binforge {

ByteReader::ByteReader(const uint8_t *data, size_t size, ByteOrder order)
    : data_(data), size_(size), order_(order) {}

size_t ByteReader::remaining() const {
  return position_ <= size_ ? size_ - position_ : 0;
}

bool ByteReader::seek(uint64_t position) {
  if (position > size_)
    return false;
  position_ = static_cast<size_t>(position);
  return true;
}

bool ByteReader::skip(uint64_t amount) {
  uint64_t next = 0;
  return checked_add(position_, amount, next) && seek(next);
}

bool ByteReader::read_u8(uint8_t &value) {
  if (!remaining())
    return false;
  value = data_[position_++];
  return true;
}

bool ByteReader::read_u16(uint16_t &value) {
  const uint8_t *p = pointer(position_, 2);
  if (!p)
    return false;
  if (order_ == ByteOrder::little)
    value = uint16_t(p[0]) | (uint16_t(p[1]) << 8);
  else
    value = (uint16_t(p[0]) << 8) | uint16_t(p[1]);
  position_ += 2;
  return true;
}

bool ByteReader::read_u32(uint32_t &value) {
  const uint8_t *p = pointer(position_, 4);
  if (!p)
    return false;
  value = 0;
  if (order_ == ByteOrder::little) {
    for (int i = 3; i >= 0; --i)
      value = (value << 8) | p[i];
  } else {
    for (int i = 0; i < 4; ++i)
      value = (value << 8) | p[i];
  }
  position_ += 4;
  return true;
}

bool ByteReader::read_u64(uint64_t &value) {
  const uint8_t *p = pointer(position_, 8);
  if (!p)
    return false;
  value = 0;
  if (order_ == ByteOrder::little) {
    for (int i = 7; i >= 0; --i)
      value = (value << 8) | p[i];
  } else {
    for (int i = 0; i < 8; ++i)
      value = (value << 8) | p[i];
  }
  position_ += 8;
  return true;
}

bool ByteReader::read_i32(int32_t &value) {
  uint32_t raw = 0;
  if (!read_u32(raw))
    return false;
  std::memcpy(&value, &raw, sizeof(value));
  return true;
}

bool ByteReader::read_i64(int64_t &value) {
  uint64_t raw = 0;
  if (!read_u64(raw))
    return false;
  std::memcpy(&value, &raw, sizeof(value));
  return true;
}

bool ByteReader::read_uleb128(uint64_t &value) {
  value = 0;
  for (unsigned shift = 0; shift < 64; shift += 7) {
    uint8_t byte = 0;
    if (!read_u8(byte))
      return false;
    uint64_t payload = byte & 0x7fu;
    if (shift == 63 && payload > 1)
      return false;
    value |= payload << shift;
    if (!(byte & 0x80u))
      return true;
  }
  return false;
}

bool ByteReader::read_sleb128(int64_t &value) {
  uint64_t raw = 0;
  unsigned shift = 0;
  uint8_t byte = 0;
  do {
    if (shift >= 64 || !read_u8(byte))
      return false;
    raw |= uint64_t(byte & 0x7fu) << shift;
    shift += 7;
  } while (byte & 0x80u);
  if (shift < 64 && (byte & 0x40u))
    raw |= (~uint64_t{0}) << shift;
  std::memcpy(&value, &raw, sizeof(value));
  return true;
}

bool ByteReader::read_bytes(size_t count, std::vector<uint8_t> &value) {
  const uint8_t *p = pointer(position_, count);
  if (!p)
    return false;
  value.assign(p, p + count);
  position_ += count;
  return true;
}

bool ByteReader::read_fixed_string(size_t count, std::string &value) {
  const uint8_t *p = pointer(position_, count);
  if (!p)
    return false;
  size_t length = 0;
  while (length < count && p[length])
    ++length;
  value.assign(reinterpret_cast<const char *>(p), length);
  position_ += count;
  return true;
}

bool ByteReader::read_c_string(uint64_t offset, uint64_t limit,
                               std::string &value) const {
  if (offset > size_ || limit > size_ - offset)
    return false;
  const uint8_t *start = data_ + offset;
  const void *terminator = std::memchr(start, 0, static_cast<size_t>(limit));
  if (!terminator)
    return false;
  auto end = static_cast<const uint8_t *>(terminator);
  value.assign(reinterpret_cast<const char *>(start),
               static_cast<size_t>(end - start));
  return true;
}

const uint8_t *ByteReader::pointer(uint64_t offset, uint64_t count) const {
  if (!data_ || !range_inside(offset, count, size_))
    return nullptr;
  return data_ + static_cast<size_t>(offset);
}

} // namespace binforge
