#include "binforge/binforge.h"

#include <algorithm>
#include <cctype>

namespace binforge {
namespace {

bool ascii_character(uint8_t value) {
  return value == '\t' || value == '\n' || value == '\r' ||
         (value >= 0x20 && value <= 0x7e);
}

bool utf8_sequence(const uint8_t *data, size_t remaining, size_t &length,
                   uint32_t &code_point) {
  uint8_t first = data[0];
  if (first < 0x80) {
    length = 1;
    code_point = first;
    return ascii_character(first);
  }
  if ((first & 0xe0) == 0xc0) {
    length = 2;
    code_point = first & 0x1f;
    if (code_point < 2)
      return false;
  } else if ((first & 0xf0) == 0xe0) {
    length = 3;
    code_point = first & 0x0f;
  } else if ((first & 0xf8) == 0xf0) {
    length = 4;
    code_point = first & 0x07;
  } else {
    return false;
  }
  if (length > remaining)
    return false;
  for (size_t index = 1; index < length; ++index) {
    if ((data[index] & 0xc0) != 0x80)
      return false;
    code_point = (code_point << 6) | (data[index] & 0x3f);
  }
  if ((length == 3 && code_point < 0x800) ||
      (length == 4 && code_point < 0x10000) || code_point > 0x10ffff ||
      (code_point >= 0xd800 && code_point <= 0xdfff))
    return false;
  return true;
}

void append_utf8(std::string &output, uint32_t code_point) {
  if (code_point < 0x80) {
    output.push_back(static_cast<char>(code_point));
  } else if (code_point < 0x800) {
    output.push_back(static_cast<char>(0xc0 | (code_point >> 6)));
    output.push_back(static_cast<char>(0x80 | (code_point & 0x3f)));
  } else if (code_point < 0x10000) {
    output.push_back(static_cast<char>(0xe0 | (code_point >> 12)));
    output.push_back(static_cast<char>(0x80 | ((code_point >> 6) & 0x3f)));
    output.push_back(static_cast<char>(0x80 | (code_point & 0x3f)));
  } else {
    output.push_back(static_cast<char>(0xf0 | (code_point >> 18)));
    output.push_back(static_cast<char>(0x80 | ((code_point >> 12) & 0x3f)));
    output.push_back(static_cast<char>(0x80 | ((code_point >> 6) & 0x3f)));
    output.push_back(static_cast<char>(0x80 | (code_point & 0x3f)));
  }
}

void populate_location(const BinaryImage &image, ExtractedString &result) {
  for (const Section &section : image.sections) {
    if (result.file_offset < section.file_offset)
      continue;
    uint64_t displacement = result.file_offset - section.file_offset;
    if (displacement >= section.file_size)
      continue;
    result.section_index = section.index;
    checked_add(section.virtual_address, displacement, result.virtual_address);
    return;
  }
}

void populate_match_location(const BinaryImage &image, PatternMatch &result) {
  for (const Section &section : image.sections) {
    if (result.file_offset < section.file_offset)
      continue;
    uint64_t displacement = result.file_offset - section.file_offset;
    if (displacement >= section.file_size)
      continue;
    result.section_index = section.index;
    checked_add(section.virtual_address, displacement, result.virtual_address);
    return;
  }
}

} // namespace

StringScanner::StringScanner(Limits limits) : limits_(limits) {}

std::vector<ExtractedString>
StringScanner::scan(const BinaryImage &image, const StringScanOptions &options,
                    Error &error) const {
  error.clear();
  std::vector<ExtractedString> result;
  if (!image.file_data) {
    error = {ErrorCode::invalid_header, 0,
             "string scanning requires backing file data"};
    return result;
  }
  if (!options.minimum_characters ||
      options.minimum_characters > options.maximum_characters ||
      options.maximum_characters > limits_.max_string_bytes ||
      options.maximum_results > limits_.max_symbols) {
    error = {ErrorCode::resource_limit, 0, "string scan options are invalid"};
    return result;
  }
  const std::vector<uint8_t> &bytes = *image.file_data;

  auto append = [&](ExtractedString value) {
    populate_location(image, value);
    result.push_back(std::move(value));
  };

  if (options.ascii) {
    for (size_t begin = 0;
         begin < bytes.size() && result.size() < options.maximum_results;) {
      if (!ascii_character(bytes[begin])) {
        ++begin;
        continue;
      }
      size_t end = begin;
      while (end < bytes.size() && ascii_character(bytes[end]) &&
             end - begin < options.maximum_characters)
        ++end;
      bool terminated = end < bytes.size() && bytes[end] == 0;
      if (end - begin >= options.minimum_characters &&
          (!options.require_terminator || terminated)) {
        ExtractedString value;
        value.file_offset = begin;
        value.encoding = StringEncoding::ascii;
        value.value.assign(reinterpret_cast<const char *>(bytes.data() + begin),
                           end - begin);
        value.byte_length = static_cast<uint32_t>(end - begin);
        append(std::move(value));
      }
      begin = end == begin ? begin + 1 : end + (terminated ? 1 : 0);
    }
  }

  if (options.utf8 && result.size() < options.maximum_results) {
    for (size_t begin = 0;
         begin < bytes.size() && result.size() < options.maximum_results;) {
      if (bytes[begin] < 0x80) {
        ++begin;
        continue;
      }
      size_t cursor = begin;
      uint32_t characters = 0;
      std::string value;
      while (cursor < bytes.size() && characters < options.maximum_characters) {
        size_t length = 0;
        uint32_t code_point = 0;
        if (!utf8_sequence(bytes.data() + cursor, bytes.size() - cursor, length,
                           code_point))
          break;
        append_utf8(value, code_point);
        cursor += length;
        ++characters;
      }
      bool terminated = cursor < bytes.size() && bytes[cursor] == 0;
      if (characters >= options.minimum_characters &&
          (!options.require_terminator || terminated)) {
        ExtractedString found;
        found.file_offset = begin;
        found.encoding = StringEncoding::utf8;
        found.value = std::move(value);
        found.byte_length = static_cast<uint32_t>(cursor - begin);
        append(std::move(found));
      }
      ++begin;
    }
  }

  auto scan_utf16 = [&](bool little) {
    for (size_t begin = 0;
         begin + 1 < bytes.size() && result.size() < options.maximum_results;
         ++begin) {
      size_t cursor = begin;
      uint32_t characters = 0;
      std::string value;
      while (cursor + 1 < bytes.size() &&
             characters < options.maximum_characters) {
        uint16_t unit =
            little
                ? uint16_t(bytes[cursor]) | (uint16_t(bytes[cursor + 1]) << 8)
                : (uint16_t(bytes[cursor]) << 8) | uint16_t(bytes[cursor + 1]);
        if (!unit || unit < 0x20 || (unit >= 0xd800 && unit <= 0xdfff))
          break;
        append_utf8(value, unit);
        cursor += 2;
        ++characters;
      }
      bool terminated = cursor + 1 < bytes.size() && bytes[cursor] == 0 &&
                        bytes[cursor + 1] == 0;
      if (characters >= options.minimum_characters &&
          (!options.require_terminator || terminated)) {
        ExtractedString found;
        found.file_offset = begin;
        found.encoding =
            little ? StringEncoding::utf16_little : StringEncoding::utf16_big;
        found.value = std::move(value);
        found.byte_length = static_cast<uint32_t>(cursor - begin);
        append(std::move(found));
        begin = cursor + (terminated ? 1 : 0);
      }
    }
  };
  if (options.utf16_little)
    scan_utf16(true);
  if (options.utf16_big && result.size() < options.maximum_results)
    scan_utf16(false);
  return result;
}

SignatureScanner::SignatureScanner(Limits limits) : limits_(limits) {}

bool SignatureScanner::add(BytePattern pattern, Error &error) {
  error.clear();
  if (pattern.name.empty() || pattern.name.size() > limits_.max_string_bytes ||
      pattern.bytes.empty() ||
      pattern.bytes.size() > limits_.max_section_bytes ||
      (!pattern.mask.empty() && pattern.mask.size() != pattern.bytes.size()) ||
      !pattern.alignment || (pattern.alignment & (pattern.alignment - 1))) {
    error = {ErrorCode::invalid_header, 0, "byte pattern is invalid"};
    return false;
  }
  if (patterns_.size() >= limits_.max_sections) {
    error = {ErrorCode::resource_limit, 0, "signature pattern limit exceeded"};
    return false;
  }
  if (pattern.mask.empty())
    pattern.mask.assign(pattern.bytes.size(), 0xff);
  patterns_.push_back(std::move(pattern));
  return true;
}

std::vector<PatternMatch> SignatureScanner::scan(const BinaryImage &image,
                                                 Error &error) const {
  error.clear();
  std::vector<PatternMatch> matches;
  if (!image.file_data) {
    error = {ErrorCode::invalid_header, 0,
             "signature scanning requires backing file data"};
    return matches;
  }
  const std::vector<uint8_t> &data = *image.file_data;
  for (const BytePattern &pattern : patterns_) {
    if (pattern.bytes.size() > data.size())
      continue;
    for (size_t offset = 0; offset <= data.size() - pattern.bytes.size();) {
      if (offset % pattern.alignment) {
        offset += pattern.alignment - (offset % pattern.alignment);
        continue;
      }
      bool equal = true;
      for (size_t index = 0; index < pattern.bytes.size(); ++index) {
        if ((data[offset + index] & pattern.mask[index]) !=
            (pattern.bytes[index] & pattern.mask[index])) {
          equal = false;
          break;
        }
      }
      if (equal) {
        PatternMatch match;
        match.pattern = pattern.name;
        match.file_offset = offset;
        populate_match_location(image, match);
        matches.push_back(std::move(match));
        if (matches.size() >= limits_.max_symbols)
          return matches;
      }
      offset += std::max<uint64_t>(1, pattern.alignment);
    }
  }
  return matches;
}

void SignatureScanner::clear() { patterns_.clear(); }

} // namespace binforge
