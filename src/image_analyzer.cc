#include "binforge/binforge.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <limits>

namespace binforge {

bool AddressRange::contains(uint64_t address) const {
  return address >= begin && address < end;
}

bool AddressRange::overlaps(const AddressRange &other) const {
  return begin < other.end && other.begin < end;
}

ImageAnalyzer::ImageAnalyzer(Limits limits) : limits_(limits) {}

SectionMetrics ImageAnalyzer::analyze_section(const BinaryImage &image,
                                              const Section &section,
                                              Error &error) const {
  SectionMetrics metrics;
  metrics.section_index = section.index;
  metrics.checksum = 0;

  if (!image.file_data) {
    error = {ErrorCode::invalid_header, section.file_offset,
             "section analysis requires backing bytes"};
    return metrics;
  }

  if (section.kind == SectionKind::no_bits || section.file_size == 0) {
    metrics.zero_bytes = section.memory_size;
    return metrics;
  }

  if (section.file_size > limits_.max_section_bytes ||
      !range_inside(section.file_offset, section.file_size,
                    image.file_data->size())) {
    error = {ErrorCode::invalid_section, section.file_offset,
             "section analysis range is invalid"};
    return metrics;
  }

  const uint8_t *bytes = image.file_data->data() + section.file_offset;
  size_t size = static_cast<size_t>(section.file_size);
  std::array<uint64_t, 256> frequencies{};

  for (size_t index = 0; index < size; ++index) {
    uint8_t value = bytes[index];
    ++frequencies[value];
    if (value == 0)
      ++metrics.zero_bytes;
    if ((value >= 0x20 && value <= 0x7e) || value == '\n' || value == '\r' ||
        value == '\t')
      ++metrics.printable_bytes;
  }

  for (uint64_t frequency : frequencies) {
    if (!frequency)
      continue;
    ++metrics.unique_byte_values;
    double probability =
        static_cast<double>(frequency) / static_cast<double>(section.file_size);
    metrics.entropy -= probability * std::log2(probability);
  }

  metrics.checksum = crc32(bytes, size);
  metrics.likely_code = (section.permissions & permission_execute) != 0 &&
                        metrics.zero_bytes * 4 < section.file_size * 3;
  metrics.likely_compressed = metrics.entropy > 7.2 &&
                              metrics.unique_byte_values > 192 &&
                              metrics.printable_bytes * 4 < section.file_size;
  return metrics;
}

std::optional<ImageMetrics> ImageAnalyzer::analyze(const BinaryImage &image,
                                                   Error &error) const {
  error.clear();
  auto validation = BinaryValidator(limits_).validate(image);
  if (!validation.valid) {
    error = validation.errors.front();
    return std::nullopt;
  }

  ImageMetrics metrics;
  metrics.file_size = image.file_data->size();
  metrics.sections.reserve(image.sections.size());
  metrics.address_ranges.reserve(image.segments.size());

  for (const Section &section : image.sections) {
    uint64_t next = 0;
    if (!checked_add(metrics.declared_file_bytes, section.file_size, next)) {
      error = {ErrorCode::address_overflow, section.file_offset,
               "declared file-byte total overflow"};
      return std::nullopt;
    }
    metrics.declared_file_bytes = next;

    if (!checked_add(metrics.declared_memory_bytes, section.memory_size,
                     next)) {
      error = {ErrorCode::address_overflow, section.virtual_address,
               "declared memory-byte total overflow"};
      return std::nullopt;
    }
    metrics.declared_memory_bytes = next;

    if (section.permissions & permission_execute) {
      if (!checked_add(metrics.executable_bytes, section.memory_size, next)) {
        error = {ErrorCode::address_overflow, section.virtual_address,
                 "executable-byte total overflow"};
        return std::nullopt;
      }
      metrics.executable_bytes = next;
    }

    if (section.permissions & permission_write) {
      if (!checked_add(metrics.writable_bytes, section.memory_size, next)) {
        error = {ErrorCode::address_overflow, section.virtual_address,
                 "writable-byte total overflow"};
        return std::nullopt;
      }
      metrics.writable_bytes = next;
    }

    if (section.memory_size > section.file_size) {
      uint64_t difference = section.memory_size - section.file_size;
      if (!checked_add(metrics.zero_fill_bytes, difference, next)) {
        error = {ErrorCode::address_overflow, section.virtual_address,
                 "zero-fill total overflow"};
        return std::nullopt;
      }
      metrics.zero_fill_bytes = next;
    }

    if (!section.name.empty())
      ++metrics.named_sections;

    SectionMetrics section_metrics = analyze_section(image, section, error);
    if (error)
      return std::nullopt;
    metrics.sections.push_back(std::move(section_metrics));
  }

  for (const Segment &segment : image.segments) {
    uint64_t end = 0;
    if (!checked_add(segment.virtual_address, segment.memory_size, end)) {
      error = {ErrorCode::address_overflow, segment.virtual_address,
               "segment range overflows"};
      return std::nullopt;
    }
    metrics.address_ranges.push_back(
        {segment.virtual_address, end, segment.permissions,
         "segment." + std::to_string(segment.index)});
  }

  std::sort(metrics.address_ranges.begin(), metrics.address_ranges.end(),
            [](const AddressRange &left, const AddressRange &right) {
              if (left.begin != right.begin)
                return left.begin < right.begin;
              return left.end < right.end;
            });

  for (size_t index = 1; index < metrics.address_ranges.size(); ++index) {
    const AddressRange &previous = metrics.address_ranges[index - 1];
    const AddressRange &current = metrics.address_ranges[index];
    if (previous.overlaps(current)) {
      metrics.anomalies.push_back(previous.owner + " overlaps " +
                                  current.owner);
    }
  }

  for (const Symbol &symbol : image.symbols) {
    if (symbol.binding == SymbolBinding::import_symbol)
      ++metrics.imported_symbols;
    if (symbol.binding == SymbolBinding::export_symbol ||
        symbol.binding == SymbolBinding::global)
      ++metrics.exported_symbols;
  }

  for (const SectionMetrics &section : metrics.sections) {
    if (section.likely_compressed) {
      const Section *original = image.section(section.section_index);
      metrics.anomalies.push_back(
          "high-entropy section: " +
          (original ? original->name : std::to_string(section.section_index)));
    }
  }

  if (metrics.executable_bytes && metrics.writable_bytes) {
    for (const Section &section : image.sections) {
      if ((section.permissions & permission_execute) &&
          (section.permissions & permission_write)) {
        metrics.anomalies.push_back("writable-executable section: " +
                                    section.name);
      }
    }
  }

  return metrics;
}

DependencyAnalyzer::DependencyAnalyzer(Limits limits) : limits_(limits) {}

DependencyReport
DependencyAnalyzer::analyze(const BinaryImage &image,
                            const SymbolResolver *resolver) const {
  DependencyReport report;
  std::set<std::pair<std::string, std::string>> seen_exports;

  size_t import_limit =
      std::min<size_t>(image.imports.size(), limits_.max_imports);
  for (size_t index = 0; index < import_limit; ++index) {
    const Import &symbol = image.imports[index];
    DependencyNode &node = report.libraries[symbol.library];
    node.library = symbol.library;
    std::string identity = symbol.name.empty()
                               ? "#" + std::to_string(symbol.ordinal)
                               : symbol.name;
    node.imports.insert(identity);

    bool resolved = false;
    if (resolver)
      resolved = resolver->resolve(symbol.library, symbol.name, symbol.ordinal)
                     .has_value();
    if (resolved) {
      ++report.resolved;
    } else {
      ++report.unresolved;
      node.unresolved.insert(identity);
    }
  }

  size_t export_limit =
      std::min<size_t>(image.exports.size(), limits_.max_exports);
  for (size_t index = 0; index < export_limit; ++index) {
    const Export &symbol = image.exports[index];
    std::string library =
        image.header.format == BinaryFormat::pe_like ? "self.dll" : "self";
    DependencyNode &node = report.libraries[library];
    node.library = library;
    std::string identity = symbol.name.empty()
                               ? "#" + std::to_string(symbol.ordinal)
                               : symbol.name;
    auto key = std::make_pair(library, identity);
    if (!seen_exports.insert(key).second)
      report.duplicate_exports.push_back(library + "!" + identity);
    node.exports.insert(identity);
  }

  for (const Symbol &symbol : image.symbols) {
    if (symbol.binding == SymbolBinding::import_symbol) {
      DependencyNode &node = report.libraries[symbol.library];
      node.library = symbol.library;
      node.imports.insert(symbol.name);
    } else if (symbol.binding == SymbolBinding::export_symbol) {
      DependencyNode &node = report.libraries["self"];
      node.library = "self";
      node.exports.insert(symbol.name);
    }
  }

  return report;
}

} // namespace binforge
