#include "binforge/binforge.h"
#include <fstream>
#include <iostream>
#include <iterator>
int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: binforge <binary>\n";
    return 2;
  }
  std::ifstream in(argv[1], std::ios::binary);
  if (!in) {
    std::cerr << "cannot open file\n";
    return 2;
  }
  std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)), {});
  binforge::Error e;
  auto image = binforge::BinaryParser().parse(bytes.data(), bytes.size(), e);
  if (!image) {
    std::cerr << binforge::error_code_name(e.code) << " at " << e.offset << ": "
              << e.message << "\n";
    return 1;
  }
  std::cout << "sections=" << image->sections.size()
            << " segments=" << image->segments.size()
            << " symbols=" << image->symbols.size()
            << " relocations=" << image->relocations.size() << "\n";
  binforge::AddressSpace memory;
  binforge::LoadOptions options;
  options.resolve_imports = false;
  auto loaded =
      binforge::BinaryLoader().load(*image, memory, options, nullptr, e);
  if (!loaded) {
    std::cerr << "load: " << e.message << "\n";
    return 1;
  }
  std::cout << "entry=0x" << std::hex << loaded->entry_point << " mapped=0x"
            << loaded->mapped_bytes << "\n";
}
