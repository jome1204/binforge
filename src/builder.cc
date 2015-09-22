#include "binforge/binforge.h"

#include <algorithm>

namespace binforge {

BinaryImageBuilder::BinaryImageBuilder(Limits limits) : limits_(limits) {}

bool BinaryImageBuilder::add_section(BuilderSection section, Error &error) {
  error.clear();
  if (sections_.size() >= limits_.max_sections ||
      section.name.size() > limits_.max_string_bytes ||
      section.data.size() > limits_.max_section_bytes || !section.alignment ||
      (section.alignment & (section.alignment - 1))) {
    error = {ErrorCode::resource_limit, sections_.size(),
             "builder section exceeds limits or has invalid alignment"};
    return false;
  }
  if (std::any_of(sections_.begin(), sections_.end(),
                  [&](const BuilderSection &existing) {
                    return existing.name == section.name;
                  })) {
    error = {ErrorCode::invalid_section, sections_.size(),
             "builder section name is duplicated"};
    return false;
  }
  sections_.push_back(std::move(section));
  return true;
}

bool BinaryImageBuilder::add_symbol(Symbol symbol, Error &error) {
  error.clear();
  if (symbols_.size() >= limits_.max_symbols ||
      symbol.name.size() > limits_.max_string_bytes ||
      symbol.library.size() > limits_.max_string_bytes) {
    error = {ErrorCode::resource_limit, symbols_.size(),
             "builder symbol exceeds limits"};
    return false;
  }
  symbol.index = static_cast<uint32_t>(symbols_.size());
  symbols_.push_back(std::move(symbol));
  return true;
}

bool BinaryImageBuilder::add_import(Import imported, Error &error) {
  error.clear();
  if (imports_.size() >= limits_.max_imports ||
      imported.name.size() > limits_.max_string_bytes ||
      imported.library.size() > limits_.max_string_bytes) {
    error = {ErrorCode::resource_limit, imports_.size(),
             "builder import exceeds limits"};
    return false;
  }
  imports_.push_back(std::move(imported));
  return true;
}

bool BinaryImageBuilder::add_export(Export exported, Error &error) {
  error.clear();
  if (exports_.size() >= limits_.max_exports ||
      exported.name.size() > limits_.max_string_bytes ||
      exported.forward_target.size() > limits_.max_string_bytes) {
    error = {ErrorCode::resource_limit, exports_.size(),
             "builder export exceeds limits"};
    return false;
  }
  exports_.push_back(std::move(exported));
  return true;
}

bool BinaryImageBuilder::add_relocation(Relocation relocation, Error &error) {
  error.clear();
  if (relocations_.size() >= limits_.max_relocations) {
    error = {ErrorCode::resource_limit, relocations_.size(),
             "builder relocation limit exceeded"};
    return false;
  }
  relocation.index = static_cast<uint32_t>(relocations_.size());
  relocations_.push_back(std::move(relocation));
  return true;
}

std::optional<BinaryImage>
BinaryImageBuilder::build(const BuilderOptions &options, Error &error) const {
  error.clear();
  if (!options.file_alignment ||
      (options.file_alignment & (options.file_alignment - 1)) ||
      !options.memory_alignment ||
      (options.memory_alignment & (options.memory_alignment - 1)) ||
      options.file_alignment > limits_.max_section_bytes ||
      options.memory_alignment > limits_.max_mapped_bytes) {
    error = {ErrorCode::invalid_alignment, 0,
             "builder output alignments are invalid"};
    return std::nullopt;
  }

  BinaryImage image;
  image.header.format = options.format;
  image.header.kind = options.kind;
  image.header.architecture = options.architecture;
  image.header.word_size = options.word_size;
  image.header.byte_order = options.byte_order;
  image.header.image_base = options.image_base;
  image.symbols = symbols_;
  image.imports = imports_;
  image.exports = exports_;
  image.relocations = relocations_;

  auto storage = std::make_shared<std::vector<uint8_t>>();
  uint64_t file_cursor = 0;
  uint64_t memory_cursor = options.image_base;
  for (size_t index = 0; index < sections_.size(); ++index) {
    const BuilderSection &source = sections_[index];
    uint64_t file_alignment =
        std::max(options.file_alignment, source.alignment);
    uint64_t memory_alignment =
        std::max(options.memory_alignment, source.alignment);
    uint64_t file_offset = 0, virtual_address = 0;
    if (!checked_align_up(file_cursor, file_alignment, file_offset) ||
        !checked_align_up(memory_cursor, memory_alignment, virtual_address)) {
      error = {ErrorCode::address_overflow, index,
               "builder section placement overflows"};
      return std::nullopt;
    }
    if (file_offset > limits_.max_file_size ||
        source.data.size() > limits_.max_file_size - file_offset) {
      error = {ErrorCode::resource_limit, index,
               "builder file-size limit exceeded"};
      return std::nullopt;
    }
    storage->resize(static_cast<size_t>(file_offset), 0);
    storage->insert(storage->end(), source.data.begin(), source.data.end());

    uint64_t memory_size = 0;
    if (!checked_add(source.data.size(), source.zero_fill, memory_size)) {
      error = {ErrorCode::address_overflow, index,
               "builder section memory size overflows"};
      return std::nullopt;
    }
    Section section;
    section.index = static_cast<uint32_t>(index);
    section.name = source.name;
    section.kind = source.kind;
    section.file_offset = file_offset;
    section.file_size = source.data.size();
    section.virtual_address = virtual_address;
    section.memory_size = memory_size;
    section.alignment = source.alignment;
    section.permissions = source.permissions;
    image.sections.push_back(section);

    bool start_segment = image.segments.empty();
    if (!start_segment && options.separate_permissions)
      start_segment = image.segments.back().permissions != source.permissions;
    if (start_segment) {
      Segment segment;
      segment.index = static_cast<uint32_t>(image.segments.size());
      segment.file_offset = file_offset;
      segment.file_size = source.data.size();
      segment.virtual_address = virtual_address;
      segment.memory_size = memory_size;
      segment.alignment = memory_alignment;
      segment.permissions = source.permissions;
      segment.sections.push_back(section.index);
      image.segments.push_back(std::move(segment));
    } else {
      Segment &segment = image.segments.back();
      uint64_t segment_file_end = 0, segment_memory_end = 0;
      if (!checked_add(file_offset, source.data.size(), segment_file_end) ||
          !checked_add(virtual_address, memory_size, segment_memory_end)) {
        error = {ErrorCode::address_overflow, index,
                 "builder combined segment overflows"};
        return std::nullopt;
      }
      segment.file_size = segment_file_end - segment.file_offset;
      segment.memory_size = segment_memory_end - segment.virtual_address;
      segment.sections.push_back(section.index);
    }
    if (!checked_add(file_offset, source.data.size(), file_cursor) ||
        !checked_add(virtual_address, memory_size, memory_cursor)) {
      error = {ErrorCode::address_overflow, index,
               "builder cursor update overflows"};
      return std::nullopt;
    }
  }

  image.header.section_count = static_cast<uint32_t>(image.sections.size());
  image.header.segment_count = static_cast<uint32_t>(image.segments.size());
  for (const Section &section : image.sections) {
    if (section.permissions & permission_execute) {
      image.header.entry_point = section.virtual_address;
      break;
    }
  }
  image.file_data =
      std::shared_ptr<const std::vector<uint8_t>>(std::move(storage));
  auto validation = BinaryValidator(limits_).validate(image);
  if (!validation.valid) {
    error = validation.errors.front();
    return std::nullopt;
  }
  return image;
}

void BinaryImageBuilder::clear() {
  sections_.clear();
  symbols_.clear();
  imports_.clear();
  exports_.clear();
  relocations_.clear();
}

} // namespace binforge
