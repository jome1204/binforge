#include "binforge/binforge.h"

#include <algorithm>
#include <cctype>

namespace binforge {
namespace {

void add_finding(HardeningReport &report, FindingSeverity severity,
                 FindingCategory category, std::string title,
                 std::string detail, uint64_t address = 0,
                 std::optional<uint32_t> section = std::nullopt) {
  report.findings.push_back({severity, category, std::move(title),
                             std::move(detail), address, section});
  uint32_t penalty = 0;
  switch (severity) {
  case FindingSeverity::information:
    penalty = 0;
    break;
  case FindingSeverity::low:
    penalty = 3;
    break;
  case FindingSeverity::medium:
    penalty = 8;
    break;
  case FindingSeverity::high:
    penalty = 15;
    break;
  case FindingSeverity::critical:
    penalty = 25;
    break;
  }
  report.score = penalty > report.score ? 0 : report.score - penalty;
}

bool symbol_named_like(const BinaryImage &image, std::string_view fragment) {
  return std::any_of(image.symbols.begin(), image.symbols.end(),
                     [&](const Symbol &symbol) {
                       return symbol.name.find(fragment) != std::string::npos;
                     }) ||
         std::any_of(image.imports.begin(), image.imports.end(),
                     [&](const Import &symbol) {
                       return symbol.name.find(fragment) != std::string::npos;
                     });
}

bool suspicious_import(std::string name) {
  std::transform(name.begin(), name.end(), name.begin(), [](char character) {
    return static_cast<char>(
        std::tolower(static_cast<unsigned char>(character)));
  });
  static const char *patterns[] = {"virtualprotect",
                                   "writeprocessmemory",
                                   "createremotethread",
                                   "ptrace",
                                   "mprotect",
                                   "process_vm_writev",
                                   "dlopen",
                                   "loadlibrary",
                                   "getprocaddress",
                                   "winexec",
                                   "system",
                                   "popen"};
  for (const char *pattern : patterns)
    if (name.find(pattern) != std::string::npos)
      return true;
  return false;
}

} // namespace

HardeningAnalyzer::HardeningAnalyzer(Limits limits) : limits_(limits) {}

std::optional<HardeningReport>
HardeningAnalyzer::analyze(const BinaryImage &image, Error &error) const {
  error.clear();
  auto validation = BinaryValidator(limits_).validate(image);
  if (!validation.valid) {
    error = validation.errors.front();
    return std::nullopt;
  }
  HardeningReport report;
  report.position_independent =
      image.header.kind == BinaryKind::shared_library ||
      (image.header.format == BinaryFormat::pe_like &&
       (image.header.flags & 0x40u) != 0);
  report.stripped =
      image.symbols.empty() ||
      std::none_of(image.sections.begin(), image.sections.end(),
                   [](const Section &section) {
                     return section.kind == SectionKind::symbol_table;
                   });
  report.stack_protection = symbol_named_like(image, "stack_chk") ||
                            symbol_named_like(image, "security_cookie");
  report.control_flow_protection =
      symbol_named_like(image, "guard_check") ||
      symbol_named_like(image, "__cfi") ||
      std::any_of(image.sections.begin(), image.sections.end(),
                  [](const Section &section) {
                    return section.name == ".note.gnu.property";
                  });

  for (const Section &section : image.sections) {
    bool writable = (section.permissions & permission_write) != 0;
    bool executable = (section.permissions & permission_execute) != 0;
    if (writable && executable) {
      report.writable_executable = true;
      report.non_executable_data = false;
      add_finding(report, FindingSeverity::critical,
                  FindingCategory::writable_executable,
                  "Writable and executable section",
                  section.name + " permits both writes and execution",
                  section.virtual_address, section.index);
    } else if (executable && section.kind == SectionKind::no_bits) {
      add_finding(report, FindingSeverity::high,
                  FindingCategory::suspicious_layout,
                  "Executable zero-fill section",
                  section.name + " has no file-backed executable bytes",
                  section.virtual_address, section.index);
    }
    if (section.alignment > limits_.page_size * 1024ull) {
      add_finding(report, FindingSeverity::medium,
                  FindingCategory::suspicious_layout,
                  "Unusually large section alignment",
                  section.name + " requests alignment " +
                      std::to_string(section.alignment),
                  section.virtual_address, section.index);
    }
    if (section.file_size &&
        section.memory_size > section.file_size * 1024ull) {
      add_finding(report, FindingSeverity::medium,
                  FindingCategory::suspicious_layout,
                  "Large zero-fill expansion",
                  section.name + " expands significantly when mapped",
                  section.virtual_address, section.index);
    }
  }

  ImageAnalyzer analyzer(limits_);
  auto metrics = analyzer.analyze(image, error);
  if (!metrics)
    return std::nullopt;
  for (const SectionMetrics &section_metrics : metrics->sections) {
    if (!section_metrics.likely_compressed)
      continue;
    const Section *section = image.section(section_metrics.section_index);
    FindingSeverity severity =
        section && (section->permissions & permission_execute)
            ? FindingSeverity::high
            : FindingSeverity::low;
    add_finding(
        report, severity, FindingCategory::high_entropy, "High-entropy section",
        section ? section->name : "unnamed section",
        section ? section->virtual_address : 0, section_metrics.section_index);
  }

  for (const Import &imported : image.imports) {
    if (suspicious_import(imported.name))
      add_finding(report, FindingSeverity::medium,
                  FindingCategory::suspicious_import, "Sensitive imported API",
                  imported.library + "!" + imported.name,
                  imported.slot_address);
  }
  for (const Export &exported : image.exports) {
    if (exported.forwarded && exported.forward_target.empty())
      add_finding(report, FindingSeverity::medium,
                  FindingCategory::suspicious_export,
                  "Invalid forwarded export",
                  exported.name + " lacks a forward target", exported.address);
  }

  bool entry_mapped = false;
  for (const Segment &segment : image.segments) {
    uint64_t end = 0;
    if (!checked_add(segment.virtual_address, segment.memory_size, end))
      continue;
    if (image.header.entry_point >= segment.virtual_address &&
        image.header.entry_point < end) {
      entry_mapped = true;
      if (!(segment.permissions & permission_execute))
        add_finding(report, FindingSeverity::high, FindingCategory::entry_point,
                    "Entry point is not executable",
                    "The declared entry lies in a non-executable segment",
                    image.header.entry_point);
      break;
    }
  }
  if (image.header.entry_point && !entry_mapped)
    add_finding(report, FindingSeverity::high, FindingCategory::entry_point,
                "Entry point is unmapped",
                "The declared entry does not lie in a load segment",
                image.header.entry_point);

  if (!report.position_independent &&
      image.header.kind != BinaryKind::relocatable)
    add_finding(report, FindingSeverity::medium,
                FindingCategory::missing_hardening,
                "Position independence not detected",
                "The image may require a fixed load address");
  if (!report.stack_protection)
    add_finding(report, FindingSeverity::low,
                FindingCategory::missing_hardening,
                "Stack protection not detected",
                "No known stack guard symbols were found");
  if (!report.control_flow_protection)
    add_finding(report, FindingSeverity::low,
                FindingCategory::missing_hardening,
                "Control-flow protection not detected",
                "No known control-flow guard metadata was found");
  if (!image.debug_units.empty())
    add_finding(report, FindingSeverity::information,
                FindingCategory::debug_information, "Debug information present",
                std::to_string(image.debug_units.size()) +
                    " debug units are retained");
  if (image.relocations.empty() && report.position_independent)
    add_finding(report, FindingSeverity::low,
                FindingCategory::relocation_policy,
                "Position-independent image has no relocations",
                "Relocation metadata may have been stripped");
  std::stable_sort(
      report.findings.begin(), report.findings.end(),
      [](const HardeningFinding &left, const HardeningFinding &right) {
        return left.severity > right.severity;
      });
  return report;
}

} // namespace binforge
