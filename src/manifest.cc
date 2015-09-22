#include "binforge/binforge.h"

#include <cstring>

namespace binforge {
namespace {

class ManifestWriter {
public:
  void u8(uint8_t value) { bytes_.push_back(value); }
  void u32(uint32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8)
      bytes_.push_back(static_cast<uint8_t>(value >> shift));
  }
  void u64(uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
      bytes_.push_back(static_cast<uint8_t>(value >> shift));
  }
  void i64(int64_t value) {
    uint64_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    u64(bits);
  }
  void text(const std::string &value) {
    u32(static_cast<uint32_t>(value.size()));
    bytes_.insert(bytes_.end(), value.begin(), value.end());
  }
  void raw(const uint8_t *data, size_t size) {
    bytes_.insert(bytes_.end(), data, data + size);
  }
  const std::vector<uint8_t> &bytes() const { return bytes_; }
  std::vector<uint8_t> take() { return std::move(bytes_); }

private:
  std::vector<uint8_t> bytes_;
};

class ManifestReader {
public:
  ManifestReader(const uint8_t *data, size_t size) : reader_(data, size) {}
  bool u8(uint8_t &value) { return reader_.read_u8(value); }
  bool u32(uint32_t &value) { return reader_.read_u32(value); }
  bool u64(uint64_t &value) { return reader_.read_u64(value); }
  bool i64(int64_t &value) { return reader_.read_i64(value); }
  bool text(std::string &value, uint64_t maximum) {
    uint32_t size = 0;
    if (!u32(size) || size > maximum || size > reader_.remaining())
      return false;
    std::vector<uint8_t> bytes;
    if (!reader_.read_bytes(size, bytes))
      return false;
    value.assign(bytes.begin(), bytes.end());
    return true;
  }
  bool raw(size_t size, std::vector<uint8_t> &value) {
    return reader_.read_bytes(size, value);
  }
  size_t remaining() const { return reader_.remaining(); }
  size_t position() const { return reader_.position(); }

private:
  ByteReader reader_;
};

void encode_header(ManifestWriter &writer, const FileHeader &header) {
  writer.u8(static_cast<uint8_t>(header.format));
  writer.u8(static_cast<uint8_t>(header.word_size));
  writer.u8(static_cast<uint8_t>(header.byte_order));
  writer.u8(static_cast<uint8_t>(header.kind));
  writer.u8(static_cast<uint8_t>(header.architecture));
  writer.u64(header.entry_point);
  writer.u64(header.image_base);
  writer.u64(header.section_table_offset);
  writer.u64(header.segment_table_offset);
  writer.u32(header.section_count);
  writer.u32(header.segment_count);
  writer.u32(header.flags);
}

bool decode_header(ManifestReader &reader, FileHeader &header) {
  uint8_t format, word, order, kind, architecture;
  if (!reader.u8(format) || !reader.u8(word) || !reader.u8(order) ||
      !reader.u8(kind) || !reader.u8(architecture) ||
      !reader.u64(header.entry_point) || !reader.u64(header.image_base) ||
      !reader.u64(header.section_table_offset) ||
      !reader.u64(header.segment_table_offset) ||
      !reader.u32(header.section_count) || !reader.u32(header.segment_count) ||
      !reader.u32(header.flags))
    return false;
  header.format = static_cast<BinaryFormat>(format);
  header.word_size = static_cast<WordSize>(word);
  header.byte_order = static_cast<ByteOrder>(order);
  header.kind = static_cast<BinaryKind>(kind);
  header.architecture = static_cast<Architecture>(architecture);
  return format <= static_cast<uint8_t>(BinaryFormat::macho_like) &&
         (word == 4 || word == 8) &&
         order <= static_cast<uint8_t>(ByteOrder::big);
}

} // namespace

ImageManifestCodec::ImageManifestCodec(Limits limits) : limits_(limits) {}

std::vector<uint8_t> ImageManifestCodec::encode(const BinaryImage &image,
                                                const ManifestOptions &options,
                                                Error &error) const {
  error.clear();
  if (!image.file_data || image.file_data->size() > limits_.max_file_size ||
      image.sections.size() > limits_.max_sections ||
      image.segments.size() > limits_.max_segments ||
      image.symbols.size() > limits_.max_symbols ||
      image.relocations.size() > limits_.max_relocations) {
    error = {ErrorCode::resource_limit, 0,
             "image exceeds manifest encoding limits"};
    return {};
  }

  ManifestWriter writer;
  writer.raw(reinterpret_cast<const uint8_t *>("BFMF"), 4);
  writer.u32(1);
  uint32_t flags = 0;
  flags |= options.include_symbols ? 1u : 0u;
  flags |= options.include_relocations ? 2u : 0u;
  flags |= options.include_imports ? 4u : 0u;
  flags |= options.include_exports ? 8u : 0u;
  flags |= options.include_debug_summary ? 16u : 0u;
  flags |= options.include_checksums ? 32u : 0u;
  writer.u32(flags);
  encode_header(writer, image.header);
  writer.u64(image.file_data->size());
  writer.raw(image.file_data->data(), image.file_data->size());

  writer.u32(static_cast<uint32_t>(image.sections.size()));
  for (const Section &section : image.sections) {
    writer.u32(section.index);
    writer.text(section.name);
    writer.u8(static_cast<uint8_t>(section.kind));
    writer.u64(section.file_offset);
    writer.u64(section.file_size);
    writer.u64(section.virtual_address);
    writer.u64(section.memory_size);
    writer.u64(section.alignment);
    writer.u64(section.entry_size);
    writer.u32(section.link);
    writer.u32(section.info);
    writer.u8(section.permissions);
    if (options.include_checksums && section.file_size &&
        range_inside(section.file_offset, section.file_size,
                     image.file_data->size()))
      writer.u32(crc32(image.file_data->data() + section.file_offset,
                       static_cast<size_t>(section.file_size)));
    else
      writer.u32(0);
  }

  writer.u32(static_cast<uint32_t>(image.segments.size()));
  for (const Segment &segment : image.segments) {
    writer.u32(segment.index);
    writer.u64(segment.file_offset);
    writer.u64(segment.file_size);
    writer.u64(segment.virtual_address);
    writer.u64(segment.memory_size);
    writer.u64(segment.alignment);
    writer.u8(segment.permissions);
    writer.u32(static_cast<uint32_t>(segment.sections.size()));
    for (uint32_t section : segment.sections)
      writer.u32(section);
  }

  uint32_t symbol_count =
      options.include_symbols ? static_cast<uint32_t>(image.symbols.size()) : 0;
  writer.u32(symbol_count);
  for (uint32_t index = 0; index < symbol_count; ++index) {
    const Symbol &symbol = image.symbols[index];
    writer.u32(symbol.index);
    writer.text(symbol.name);
    writer.u8(static_cast<uint8_t>(symbol.binding));
    writer.u8(static_cast<uint8_t>(symbol.kind));
    writer.u32(symbol.section_index);
    writer.u64(symbol.value);
    writer.u64(symbol.size);
    writer.u8(symbol.visibility);
    writer.text(symbol.library);
  }

  uint32_t relocation_count =
      options.include_relocations
          ? static_cast<uint32_t>(image.relocations.size())
          : 0;
  writer.u32(relocation_count);
  for (uint32_t index = 0; index < relocation_count; ++index) {
    const Relocation &relocation = image.relocations[index];
    writer.u32(relocation.index);
    writer.u8(static_cast<uint8_t>(relocation.kind));
    writer.u32(relocation.target_section);
    writer.u32(relocation.symbol_index);
    writer.u64(relocation.offset);
    writer.i64(relocation.addend);
    writer.u8(relocation.width);
  }

  uint32_t import_count =
      options.include_imports ? static_cast<uint32_t>(image.imports.size()) : 0;
  writer.u32(import_count);
  for (uint32_t index = 0; index < import_count; ++index) {
    const Import &imported = image.imports[index];
    writer.text(imported.library);
    writer.text(imported.name);
    writer.u64(imported.ordinal);
    writer.u64(imported.slot_address);
    writer.u8(imported.weak ? 1 : 0);
  }

  uint32_t export_count =
      options.include_exports ? static_cast<uint32_t>(image.exports.size()) : 0;
  writer.u32(export_count);
  for (uint32_t index = 0; index < export_count; ++index) {
    const Export &exported = image.exports[index];
    writer.text(exported.name);
    writer.u64(exported.address);
    writer.u64(exported.ordinal);
    writer.u8(exported.forwarded ? 1 : 0);
    writer.text(exported.forward_target);
  }

  uint32_t debug_count = options.include_debug_summary
                             ? static_cast<uint32_t>(image.debug_units.size())
                             : 0;
  writer.u32(debug_count);
  for (uint32_t index = 0; index < debug_count; ++index) {
    const DebugUnit &unit = image.debug_units[index];
    writer.u64(unit.offset);
    writer.u64(unit.length);
    writer.u32(unit.version);
    writer.u8(unit.address_size);
    writer.u32(static_cast<uint32_t>(unit.files.size()));
    writer.u32(static_cast<uint32_t>(unit.lines.size()));
    writer.u32(static_cast<uint32_t>(unit.entries.size()));
  }

  std::vector<uint8_t> result = writer.take();
  uint32_t checksum = crc32(result.data(), result.size());
  ManifestWriter trailer;
  trailer.u32(checksum);
  auto trailer_bytes = trailer.take();
  result.insert(result.end(), trailer_bytes.begin(), trailer_bytes.end());
  return result;
}

std::optional<BinaryImage> ImageManifestCodec::decode(const uint8_t *data,
                                                      size_t size,
                                                      Error &error) const {
  error.clear();
  if (!data || size < 16 || size > limits_.max_file_size * 2) {
    error = {ErrorCode::truncated, 0, "manifest input size is invalid"};
    return std::nullopt;
  }
  if (std::memcmp(data, "BFMF", 4) != 0) {
    error = {ErrorCode::bad_magic, 0, "manifest signature is invalid"};
    return std::nullopt;
  }
  uint32_t expected =
      uint32_t(data[size - 4]) | (uint32_t(data[size - 3]) << 8) |
      (uint32_t(data[size - 2]) << 16) | (uint32_t(data[size - 1]) << 24);
  if (crc32(data, size - 4) != expected) {
    error = {ErrorCode::invalid_header, size - 4,
             "manifest checksum does not match"};
    return std::nullopt;
  }

  ManifestReader reader(data + 4, size - 8);
  uint32_t version = 0, flags = 0;
  BinaryImage image;
  if (!reader.u32(version) || version != 1 || !reader.u32(flags) ||
      !decode_header(reader, image.header)) {
    error = {ErrorCode::invalid_header, 4, "manifest header is invalid"};
    return std::nullopt;
  }
  (void)flags;
  uint64_t file_size = 0;
  if (!reader.u64(file_size) || file_size > limits_.max_file_size ||
      file_size > reader.remaining()) {
    error = {ErrorCode::resource_limit, reader.position(),
             "manifest backing-file size is invalid"};
    return std::nullopt;
  }
  std::vector<uint8_t> file_bytes;
  if (!reader.raw(static_cast<size_t>(file_size), file_bytes))
    return std::nullopt;
  image.file_data =
      std::make_shared<const std::vector<uint8_t>>(std::move(file_bytes));

  uint32_t count = 0;
  if (!reader.u32(count) || count > limits_.max_sections)
    return std::nullopt;
  for (uint32_t index = 0; index < count; ++index) {
    Section section;
    uint8_t kind = 0;
    uint32_t stored_checksum = 0;
    if (!reader.u32(section.index) ||
        !reader.text(section.name, limits_.max_string_bytes) ||
        !reader.u8(kind) || !reader.u64(section.file_offset) ||
        !reader.u64(section.file_size) ||
        !reader.u64(section.virtual_address) ||
        !reader.u64(section.memory_size) || !reader.u64(section.alignment) ||
        !reader.u64(section.entry_size) || !reader.u32(section.link) ||
        !reader.u32(section.info) || !reader.u8(section.permissions) ||
        !reader.u32(stored_checksum)) {
      error = {ErrorCode::truncated, reader.position(),
               "manifest section is truncated"};
      return std::nullopt;
    }
    section.kind = static_cast<SectionKind>(kind);
    if (stored_checksum && section.file_size &&
        range_inside(section.file_offset, section.file_size,
                     image.file_data->size()) &&
        crc32(image.file_data->data() + section.file_offset,
              static_cast<size_t>(section.file_size)) != stored_checksum) {
      error = {ErrorCode::invalid_section, section.file_offset,
               "manifest section checksum does not match"};
      return std::nullopt;
    }
    image.sections.push_back(std::move(section));
  }

  if (!reader.u32(count) || count > limits_.max_segments)
    return std::nullopt;
  for (uint32_t index = 0; index < count; ++index) {
    Segment segment;
    uint32_t section_count = 0;
    if (!reader.u32(segment.index) || !reader.u64(segment.file_offset) ||
        !reader.u64(segment.file_size) ||
        !reader.u64(segment.virtual_address) ||
        !reader.u64(segment.memory_size) || !reader.u64(segment.alignment) ||
        !reader.u8(segment.permissions) || !reader.u32(section_count) ||
        section_count > limits_.max_sections)
      return std::nullopt;
    for (uint32_t section = 0; section < section_count; ++section) {
      uint32_t value = 0;
      if (!reader.u32(value) || value >= image.sections.size())
        return std::nullopt;
      segment.sections.push_back(value);
    }
    image.segments.push_back(std::move(segment));
  }

  if (!reader.u32(count) || count > limits_.max_symbols)
    return std::nullopt;
  for (uint32_t index = 0; index < count; ++index) {
    Symbol symbol;
    uint8_t binding = 0, kind = 0;
    if (!reader.u32(symbol.index) ||
        !reader.text(symbol.name, limits_.max_string_bytes) ||
        !reader.u8(binding) || !reader.u8(kind) ||
        !reader.u32(symbol.section_index) || !reader.u64(symbol.value) ||
        !reader.u64(symbol.size) || !reader.u8(symbol.visibility) ||
        !reader.text(symbol.library, limits_.max_string_bytes))
      return std::nullopt;
    symbol.binding = static_cast<SymbolBinding>(binding);
    symbol.kind = static_cast<SymbolKind>(kind);
    image.symbols.push_back(std::move(symbol));
  }

  if (!reader.u32(count) || count > limits_.max_relocations)
    return std::nullopt;
  for (uint32_t index = 0; index < count; ++index) {
    Relocation relocation;
    uint8_t kind = 0;
    if (!reader.u32(relocation.index) || !reader.u8(kind) ||
        !reader.u32(relocation.target_section) ||
        !reader.u32(relocation.symbol_index) ||
        !reader.u64(relocation.offset) || !reader.i64(relocation.addend) ||
        !reader.u8(relocation.width))
      return std::nullopt;
    relocation.kind = static_cast<RelocationKind>(kind);
    image.relocations.push_back(std::move(relocation));
  }

  if (!reader.u32(count) || count > limits_.max_imports)
    return std::nullopt;
  for (uint32_t index = 0; index < count; ++index) {
    Import imported;
    uint8_t weak = 0;
    if (!reader.text(imported.library, limits_.max_string_bytes) ||
        !reader.text(imported.name, limits_.max_string_bytes) ||
        !reader.u64(imported.ordinal) || !reader.u64(imported.slot_address) ||
        !reader.u8(weak))
      return std::nullopt;
    imported.weak = weak != 0;
    image.imports.push_back(std::move(imported));
  }

  if (!reader.u32(count) || count > limits_.max_exports)
    return std::nullopt;
  for (uint32_t index = 0; index < count; ++index) {
    Export exported;
    uint8_t forwarded = 0;
    if (!reader.text(exported.name, limits_.max_string_bytes) ||
        !reader.u64(exported.address) || !reader.u64(exported.ordinal) ||
        !reader.u8(forwarded) ||
        !reader.text(exported.forward_target, limits_.max_string_bytes))
      return std::nullopt;
    exported.forwarded = forwarded != 0;
    image.exports.push_back(std::move(exported));
  }

  if (!reader.u32(count) || count > limits_.max_debug_units)
    return std::nullopt;
  for (uint32_t index = 0; index < count; ++index) {
    DebugUnit unit;
    uint32_t version = 0, files = 0, lines = 0, entries = 0;
    if (!reader.u64(unit.offset) || !reader.u64(unit.length) ||
        !reader.u32(version) || !reader.u8(unit.address_size) ||
        !reader.u32(files) || !reader.u32(lines) || !reader.u32(entries))
      return std::nullopt;
    unit.version = static_cast<uint16_t>(version);
    image.debug_units.push_back(std::move(unit));
  }
  if (reader.remaining() != 0) {
    error = {ErrorCode::invalid_header, reader.position(),
             "manifest contains trailing model data"};
    return std::nullopt;
  }
  auto validation = BinaryValidator(limits_).validate(image);
  if (!validation.valid) {
    error = validation.errors.front();
    return std::nullopt;
  }
  return image;
}

} // namespace binforge
