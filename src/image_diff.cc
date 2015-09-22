#include "binforge/binforge.h"

#include <algorithm>
#include <sstream>

namespace binforge {
namespace {

std::string section_description(const Section &section) {
  std::ostringstream stream;
  stream << "file=" << section.file_offset << "+" << section.file_size
         << " virtual=" << section.virtual_address << "+" << section.memory_size
         << " permissions=" << unsigned(section.permissions)
         << " kind=" << unsigned(section.kind);
  return stream.str();
}

std::string segment_description(const Segment &segment) {
  std::ostringstream stream;
  stream << "file=" << segment.file_offset << "+" << segment.file_size
         << " virtual=" << segment.virtual_address << "+" << segment.memory_size
         << " permissions=" << unsigned(segment.permissions);
  return stream.str();
}

std::string symbol_description(const Symbol &symbol) {
  std::ostringstream stream;
  stream << "value=" << symbol.value << " size=" << symbol.size
         << " section=" << symbol.section_index
         << " binding=" << unsigned(symbol.binding)
         << " kind=" << unsigned(symbol.kind);
  return stream.str();
}

void add_difference(ImageDiffReport &report, ImageDifference difference,
                    bool addition, bool removal) {
  if (addition)
    ++report.additions;
  else if (removal)
    ++report.removals;
  else
    ++report.modifications;
  report.differences.push_back(std::move(difference));
}

template <typename T, typename Key>
std::map<Key, const T *> index_values(const std::vector<T> &values,
                                      Key (*key)(const T &)) {
  std::map<Key, const T *> result;
  for (const T &value : values)
    result.emplace(key(value), &value);
  return result;
}

std::string section_key(const Section &section) {
  return section.name.empty() ? "#" + std::to_string(section.index)
                              : section.name;
}

uint64_t segment_key(const Segment &segment) { return segment.virtual_address; }

std::string symbol_key(const Symbol &symbol) {
  return symbol.library + "!" + symbol.name + "@" +
         std::to_string(symbol.value);
}

std::string import_key(const Import &imported) {
  return imported.library + "!" +
         (imported.name.empty() ? "#" + std::to_string(imported.ordinal)
                                : imported.name);
}

std::string export_key(const Export &exported) {
  return exported.name.empty() ? "#" + std::to_string(exported.ordinal)
                               : exported.name;
}

} // namespace

ImageDiffer::ImageDiffer(Limits limits) : limits_(limits) {}

ImageDiffReport ImageDiffer::compare(const BinaryImage &before,
                                     const BinaryImage &after,
                                     Error &error) const {
  error.clear();
  ImageDiffReport report;
  uint64_t total_items = before.sections.size() + after.sections.size() +
                         before.segments.size() + after.segments.size() +
                         before.symbols.size() + after.symbols.size() +
                         before.imports.size() + after.imports.size() +
                         before.exports.size() + after.exports.size() +
                         before.relocations.size() + after.relocations.size();
  uint64_t item_limit = uint64_t(limits_.max_sections) * 4 +
                        uint64_t(limits_.max_symbols) * 4 +
                        uint64_t(limits_.max_relocations) * 2;
  if (total_items > item_limit) {
    error = {ErrorCode::resource_limit, 0,
             "image comparison exceeds item limit"};
    return report;
  }

  if (before.header.format != after.header.format ||
      before.header.word_size != after.header.word_size ||
      before.header.byte_order != after.header.byte_order ||
      before.header.kind != after.header.kind ||
      before.header.architecture != after.header.architecture ||
      before.header.entry_point != after.header.entry_point ||
      before.header.image_base != after.header.image_base ||
      before.header.flags != after.header.flags) {
    add_difference(report,
                   {DifferenceKind::header_changed, "header", "before", "after",
                    after.header.entry_point},
                   false, false);
  }

  auto before_sections =
      index_values<Section, std::string>(before.sections, section_key);
  auto after_sections =
      index_values<Section, std::string>(after.sections, section_key);
  for (const auto &item : before_sections) {
    auto found = after_sections.find(item.first);
    if (found == after_sections.end()) {
      add_difference(report,
                     {DifferenceKind::section_removed, item.first,
                      section_description(*item.second), "",
                      item.second->virtual_address},
                     false, true);
    } else {
      std::string left = section_description(*item.second);
      std::string right = section_description(*found->second);
      if (left != right)
        add_difference(report,
                       {DifferenceKind::section_changed, item.first, left,
                        right, found->second->virtual_address},
                       false, false);
    }
  }
  for (const auto &item : after_sections) {
    if (!before_sections.count(item.first))
      add_difference(report,
                     {DifferenceKind::section_added, item.first, "",
                      section_description(*item.second),
                      item.second->virtual_address},
                     true, false);
  }

  auto before_segments =
      index_values<Segment, uint64_t>(before.segments, segment_key);
  auto after_segments =
      index_values<Segment, uint64_t>(after.segments, segment_key);
  for (const auto &item : before_segments) {
    auto found = after_segments.find(item.first);
    if (found == after_segments.end()) {
      add_difference(report,
                     {DifferenceKind::segment_removed,
                      std::to_string(item.first),
                      segment_description(*item.second), "", item.first},
                     false, true);
    } else {
      std::string left = segment_description(*item.second);
      std::string right = segment_description(*found->second);
      if (left != right)
        add_difference(report,
                       {DifferenceKind::segment_changed,
                        std::to_string(item.first), left, right, item.first},
                       false, false);
    }
  }
  for (const auto &item : after_segments) {
    if (!before_segments.count(item.first))
      add_difference(report,
                     {DifferenceKind::segment_added, std::to_string(item.first),
                      "", segment_description(*item.second), item.first},
                     true, false);
  }

  auto before_symbols =
      index_values<Symbol, std::string>(before.symbols, symbol_key);
  auto after_symbols =
      index_values<Symbol, std::string>(after.symbols, symbol_key);
  for (const auto &item : before_symbols) {
    auto found = after_symbols.find(item.first);
    if (found == after_symbols.end()) {
      add_difference(report,
                     {DifferenceKind::symbol_removed, item.first,
                      symbol_description(*item.second), "", item.second->value},
                     false, true);
    } else {
      std::string left = symbol_description(*item.second);
      std::string right = symbol_description(*found->second);
      if (left != right)
        add_difference(report,
                       {DifferenceKind::symbol_changed, item.first, left, right,
                        found->second->value},
                       false, false);
    }
  }
  for (const auto &item : after_symbols) {
    if (!before_symbols.count(item.first))
      add_difference(report,
                     {DifferenceKind::symbol_added, item.first, "",
                      symbol_description(*item.second), item.second->value},
                     true, false);
  }

  auto before_imports =
      index_values<Import, std::string>(before.imports, import_key);
  auto after_imports =
      index_values<Import, std::string>(after.imports, import_key);
  for (const auto &item : before_imports)
    if (!after_imports.count(item.first))
      add_difference(report,
                     {DifferenceKind::import_removed, item.first, "present", "",
                      item.second->slot_address},
                     false, true);
  for (const auto &item : after_imports)
    if (!before_imports.count(item.first))
      add_difference(report,
                     {DifferenceKind::import_added, item.first, "", "present",
                      item.second->slot_address},
                     true, false);

  auto before_exports =
      index_values<Export, std::string>(before.exports, export_key);
  auto after_exports =
      index_values<Export, std::string>(after.exports, export_key);
  for (const auto &item : before_exports)
    if (!after_exports.count(item.first))
      add_difference(report,
                     {DifferenceKind::export_removed, item.first, "present", "",
                      item.second->address},
                     false, true);
  for (const auto &item : after_exports)
    if (!before_exports.count(item.first))
      add_difference(report,
                     {DifferenceKind::export_added, item.first, "", "present",
                      item.second->address},
                     true, false);

  size_t relocation_count =
      std::max(before.relocations.size(), after.relocations.size());
  for (size_t index = 0; index < relocation_count; ++index) {
    if (index >= before.relocations.size() ||
        index >= after.relocations.size() ||
        before.relocations[index].kind != after.relocations[index].kind ||
        before.relocations[index].offset != after.relocations[index].offset ||
        before.relocations[index].symbol_index !=
            after.relocations[index].symbol_index ||
        before.relocations[index].addend != after.relocations[index].addend) {
      uint64_t address = index < after.relocations.size()
                             ? after.relocations[index].offset
                             : before.relocations[index].offset;
      add_difference(report,
                     {DifferenceKind::relocation_changed, std::to_string(index),
                      index < before.relocations.size() ? "present" : "",
                      index < after.relocations.size() ? "present" : "",
                      address},
                     index >= before.relocations.size(),
                     index >= after.relocations.size());
    }
  }
  report.equivalent = report.differences.empty();
  return report;
}

} // namespace binforge
