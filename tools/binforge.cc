#include "binforge/binforge.h"

#include <fstream>
#include <iostream>
#include <iterator>

namespace {

std::optional<std::vector<uint8_t>> read_file(const char *path) {
  std::ifstream input(path, std::ios::binary);
  if (!input)
    return std::nullopt;
  return std::vector<uint8_t>(std::istreambuf_iterator<char>(input), {});
}

void print_error(const binforge::Error &error) {
  std::cerr << binforge::error_code_name(error.code) << " at " << error.offset
            << ": " << error.message << "\n";
}

int inspect(const binforge::BinaryImage &image, bool json) {
  binforge::ReportOptions options;
  options.format =
      json ? binforge::ReportFormat::json : binforge::ReportFormat::text;
  binforge::Error error;
  auto report = binforge::BinaryReportWriter().write(image, options, error);
  if (!report) {
    print_error(error);
    return 1;
  }
  std::cout << *report << (json ? "\n" : "");
  return 0;
}

int load(const binforge::BinaryImage &image, uint64_t requested_base) {
  binforge::AddressSpace memory;
  binforge::LoadOptions options;
  options.preferred_base = requested_base;
  options.resolve_imports = false;
  binforge::Error error;
  auto loaded =
      binforge::BinaryLoader().load(image, memory, options, nullptr, error);
  if (!loaded) {
    print_error(error);
    return 1;
  }
  std::cout << "load-base=0x" << std::hex << loaded->load_base << " entry=0x"
            << loaded->entry_point << " mapped=0x" << loaded->mapped_bytes
            << std::dec << " relocations=" << loaded->relocations_applied
            << " imports=" << loaded->imports_resolved << "\n";
  for (const auto &item : memory.regions()) {
    const binforge::MemoryRegion &region = item.second;
    std::cout << "region 0x" << std::hex << region.base << "+0x" << region.size
              << std::dec << " permissions=" << unsigned(region.permissions)
              << " name=" << region.name << "\n";
  }
  return 0;
}

int strings(const binforge::BinaryImage &image, uint32_t minimum) {
  binforge::StringScanOptions options;
  options.minimum_characters = minimum;
  options.maximum_results = 10000;
  binforge::Error error;
  auto values = binforge::StringScanner().scan(image, options, error);
  if (error) {
    print_error(error);
    return 1;
  }
  for (const binforge::ExtractedString &value : values) {
    std::cout << "0x" << std::hex << value.file_offset << std::dec << " ["
              << unsigned(value.encoding) << "] " << value.value << "\n";
  }
  return 0;
}

int hardening(const binforge::BinaryImage &image) {
  binforge::Error error;
  auto report = binforge::HardeningAnalyzer().analyze(image, error);
  if (!report) {
    print_error(error);
    return 1;
  }
  std::cout << "score=" << report->score
            << " position-independent=" << report->position_independent
            << " nx-data=" << report->non_executable_data
            << " stack-protection=" << report->stack_protection
            << " control-flow-protection=" << report->control_flow_protection
            << "\n";
  for (const binforge::HardeningFinding &finding : report->findings) {
    std::cout << unsigned(finding.severity) << " " << finding.title << ": "
              << finding.detail;
    if (finding.address)
      std::cout << " at 0x" << std::hex << finding.address << std::dec;
    std::cout << "\n";
  }
  return 0;
}

int manifest(const binforge::BinaryImage &image, const char *output_path) {
  binforge::Error error;
  auto bytes = binforge::ImageManifestCodec().encode(
      image, binforge::ManifestOptions{}, error);
  if (error) {
    print_error(error);
    return 1;
  }
  std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
  if (!output) {
    std::cerr << "cannot create manifest output\n";
    return 2;
  }
  output.write(reinterpret_cast<const char *>(bytes.data()), bytes.size());
  if (!output) {
    std::cerr << "cannot write complete manifest\n";
    return 2;
  }
  std::cout << "wrote " << bytes.size() << " bytes to " << output_path << "\n";
  return 0;
}

void usage() {
  std::cerr << "usage:\n"
            << "  binforge inspect <binary>\n"
            << "  binforge json <binary>\n"
            << "  binforge load <binary> [base]\n"
            << "  binforge strings <binary> [minimum]\n"
            << "  binforge hardening <binary>\n"
            << "  binforge manifest <binary> <output.bfmf>\n";
}

} // namespace

int main(int argc, char **argv) {
  if (argc < 3) {
    usage();
    return 2;
  }
  auto bytes = read_file(argv[2]);
  if (!bytes) {
    std::cerr << "cannot open input file\n";
    return 2;
  }
  binforge::Error error;
  auto image =
      binforge::BinaryParser().parse(bytes->data(), bytes->size(), error);
  if (!image) {
    print_error(error);
    return 1;
  }
  std::string command = argv[1];
  if (command == "inspect")
    return inspect(*image, false);
  if (command == "json")
    return inspect(*image, true);
  if (command == "load") {
    uint64_t base = 0;
    if (argc > 3) {
      try {
        base = std::stoull(argv[3], nullptr, 0);
      } catch (...) {
        std::cerr << "invalid load base\n";
        return 2;
      }
    }
    return load(*image, base);
  }
  if (command == "strings") {
    uint32_t minimum = 4;
    if (argc > 3) {
      try {
        minimum = static_cast<uint32_t>(std::stoul(argv[3]));
      } catch (...) {
        std::cerr << "invalid minimum string length\n";
        return 2;
      }
    }
    return strings(*image, minimum);
  }
  if (command == "hardening")
    return hardening(*image);
  if (command == "manifest" && argc == 4)
    return manifest(*image, argv[3]);
  usage();
  return 2;
}
