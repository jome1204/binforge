#include "binforge/binforge.h"

#include <iomanip>
#include <sstream>

namespace binforge {
namespace {

std::string json_escape(std::string_view value) {
  std::string result;
  result.reserve(value.size() + 8);
  for (unsigned char character : value) {
    switch (character) {
    case '\"':
      result += "\\\"";
      break;
    case '\\':
      result += "\\\\";
      break;
    case '\b':
      result += "\\b";
      break;
    case '\f':
      result += "\\f";
      break;
    case '\n':
      result += "\\n";
      break;
    case '\r':
      result += "\\r";
      break;
    case '\t':
      result += "\\t";
      break;
    default:
      if (character < 0x20) {
        static const char *digits = "0123456789abcdef";
        result += "\\u00";
        result.push_back(digits[character >> 4]);
        result.push_back(digits[character & 15]);
      } else {
        result.push_back(static_cast<char>(character));
      }
    }
  }
  return result;
}

std::string format_name(BinaryFormat format) {
  switch (format) {
  case BinaryFormat::elf_like:
    return "elf";
  case BinaryFormat::pe_like:
    return "pe";
  case BinaryFormat::macho_like:
    return "macho";
  case BinaryFormat::unknown:
    return "unknown";
  }
  return "unknown";
}

std::string architecture_name(Architecture architecture) {
  switch (architecture) {
  case Architecture::x86:
    return "x86";
  case Architecture::x86_64:
    return "x86_64";
  case Architecture::arm:
    return "arm";
  case Architecture::arm64:
    return "arm64";
  case Architecture::riscv32:
    return "riscv32";
  case Architecture::riscv64:
    return "riscv64";
  case Architecture::unknown:
    return "unknown";
  }
  return "unknown";
}

std::string permissions(uint8_t value) {
  std::string result;
  result += value & permission_read ? 'r' : '-';
  result += value & permission_write ? 'w' : '-';
  result += value & permission_execute ? 'x' : '-';
  return result;
}

std::string severity_name(FindingSeverity severity) {
  switch (severity) {
  case FindingSeverity::information:
    return "information";
  case FindingSeverity::low:
    return "low";
  case FindingSeverity::medium:
    return "medium";
  case FindingSeverity::high:
    return "high";
  case FindingSeverity::critical:
    return "critical";
  }
  return "unknown";
}

} // namespace

BinaryReportWriter::BinaryReportWriter(Limits limits) : limits_(limits) {}

std::optional<std::string>
BinaryReportWriter::write(const BinaryImage &image,
                          const ReportOptions &options, Error &error) const {
  error.clear();
  if (!options.maximum_items || options.maximum_items > limits_.max_symbols) {
    error = {ErrorCode::resource_limit, 0, "report item limit is invalid"};
    return std::nullopt;
  }
  auto validation = BinaryValidator(limits_).validate(image);
  if (!validation.valid) {
    error = validation.errors.front();
    return std::nullopt;
  }

  std::optional<ImageMetrics> metrics;
  if (options.include_metrics) {
    metrics = ImageAnalyzer(limits_).analyze(image, error);
    if (!metrics)
      return std::nullopt;
  }
  std::optional<HardeningReport> hardening;
  if (options.include_hardening) {
    hardening = HardeningAnalyzer(limits_).analyze(image, error);
    if (!hardening)
      return std::nullopt;
  }

  std::ostringstream output;
  uint32_t emitted = 0;
  auto available = [&]() { return emitted < options.maximum_items; };
  if (options.format == ReportFormat::text) {
    output << "BinForge binary report\n";
    output << "format: " << format_name(image.header.format) << "\n";
    output << "architecture: " << architecture_name(image.header.architecture)
           << "\n";
    output << "word-size: " << unsigned(image.header.word_size) * 8 << "\n";
    output << "entry-point: 0x" << std::hex << image.header.entry_point
           << std::dec << "\n";
    output << "image-base: 0x" << std::hex << image.header.image_base
           << std::dec << "\n";
    output << "sections: " << image.sections.size() << "\n";
    output << "segments: " << image.segments.size() << "\n";
    output << "symbols: " << image.symbols.size() << "\n";
    output << "relocations: " << image.relocations.size() << "\n";
    output << "imports: " << image.imports.size() << "\n";
    output << "exports: " << image.exports.size() << "\n";
    if (metrics) {
      output << "file-bytes: " << metrics->file_size << "\n";
      output << "mapped-bytes: " << metrics->declared_memory_bytes << "\n";
      output << "executable-bytes: " << metrics->executable_bytes << "\n";
    }
    if (hardening)
      output << "hardening-score: " << hardening->score << "\n";
    if (options.include_sections) {
      output << "\n[sections]\n";
      for (const Section &section : image.sections) {
        if (!available())
          break;
        ++emitted;
        output << section.index << " " << section.name << " file=0x" << std::hex
               << section.file_offset << "+0x" << section.file_size
               << " virtual=0x" << section.virtual_address << "+0x"
               << section.memory_size << std::dec << " "
               << permissions(section.permissions) << "\n";
      }
    }
    if (options.include_segments) {
      output << "\n[segments]\n";
      for (const Segment &segment : image.segments) {
        if (!available())
          break;
        ++emitted;
        output << segment.index << " file=0x" << std::hex << segment.file_offset
               << "+0x" << segment.file_size << " virtual=0x"
               << segment.virtual_address << "+0x" << segment.memory_size
               << std::dec << " " << permissions(segment.permissions) << "\n";
      }
    }
    if (options.include_symbols) {
      output << "\n[symbols]\n";
      for (const Symbol &symbol : image.symbols) {
        if (!available())
          break;
        ++emitted;
        output << symbol.index << " 0x" << std::hex << symbol.value << std::dec
               << " " << symbol.name << " size=" << symbol.size << "\n";
      }
    }
    if (options.include_imports) {
      output << "\n[imports]\n";
      for (const Import &imported : image.imports) {
        if (!available())
          break;
        ++emitted;
        output << imported.library << "!"
               << (imported.name.empty()
                       ? "#" + std::to_string(imported.ordinal)
                       : imported.name)
               << " slot=0x" << std::hex << imported.slot_address << std::dec
               << "\n";
      }
    }
    if (options.include_exports) {
      output << "\n[exports]\n";
      for (const Export &exported : image.exports) {
        if (!available())
          break;
        ++emitted;
        output << exported.name << " ordinal=" << exported.ordinal
               << " address=0x" << std::hex << exported.address << std::dec;
        if (exported.forwarded)
          output << " forward=" << exported.forward_target;
        output << "\n";
      }
    }
    if (options.include_relocations) {
      output << "\n[relocations]\n";
      for (const Relocation &relocation : image.relocations) {
        if (!available())
          break;
        ++emitted;
        output << relocation.index << " address=0x" << std::hex
               << relocation.offset << std::dec
               << " kind=" << unsigned(relocation.kind)
               << " symbol=" << relocation.symbol_index
               << " addend=" << relocation.addend << "\n";
      }
    }
    if (hardening) {
      output << "\n[hardening]\n";
      for (const HardeningFinding &finding : hardening->findings) {
        if (!available())
          break;
        ++emitted;
        output << severity_name(finding.severity) << ": " << finding.title
               << " — " << finding.detail << "\n";
      }
    }
    if (!available())
      output << "\n[report truncated at item limit]\n";
    return output.str();
  }

  bool lines = options.format == ReportFormat::json_lines;
  if (!lines) {
    output << "{\"header\":{\"format\":\""
           << json_escape(format_name(image.header.format))
           << "\",\"architecture\":\""
           << json_escape(architecture_name(image.header.architecture))
           << "\",\"entry_point\":" << image.header.entry_point
           << ",\"image_base\":" << image.header.image_base << "}";
    if (metrics)
      output << ",\"metrics\":{\"file_bytes\":" << metrics->file_size
             << ",\"memory_bytes\":" << metrics->declared_memory_bytes
             << ",\"executable_bytes\":" << metrics->executable_bytes << "}";
    if (hardening)
      output << ",\"hardening_score\":" << hardening->score;
    output << ",\"items\":[";
  }
  bool first = true;
  auto emit_json = [&](std::string type, uint32_t index, std::string name,
                       uint64_t address, uint64_t size) {
    if (!available())
      return;
    ++emitted;
    if (lines) {
      output << "{\"type\":\"" << json_escape(type) << "\",\"index\":" << index
             << ",\"name\":\"" << json_escape(name)
             << "\",\"address\":" << address << ",\"size\":" << size << "}\n";
    } else {
      if (!first)
        output << ',';
      first = false;
      output << "{\"type\":\"" << json_escape(type) << "\",\"index\":" << index
             << ",\"name\":\"" << json_escape(name)
             << "\",\"address\":" << address << ",\"size\":" << size << "}";
    }
  };
  if (options.include_sections)
    for (const Section &section : image.sections)
      emit_json("section", section.index, section.name, section.virtual_address,
                section.memory_size);
  if (options.include_segments)
    for (const Segment &segment : image.segments)
      emit_json("segment", segment.index,
                "segment." + std::to_string(segment.index),
                segment.virtual_address, segment.memory_size);
  if (options.include_symbols)
    for (const Symbol &symbol : image.symbols)
      emit_json("symbol", symbol.index, symbol.name, symbol.value, symbol.size);
  if (options.include_imports)
    for (uint32_t index = 0; index < image.imports.size(); ++index)
      emit_json("import", index,
                image.imports[index].library + "!" + image.imports[index].name,
                image.imports[index].slot_address, 0);
  if (options.include_exports)
    for (uint32_t index = 0; index < image.exports.size(); ++index)
      emit_json("export", index, image.exports[index].name,
                image.exports[index].address, 0);
  if (!lines)
    output << "],\"truncated\":" << (!available() ? "true" : "false") << "}";
  return output.str();
}

} // namespace binforge
