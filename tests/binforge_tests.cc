#include "binforge/binforge.h"
#include <cassert>
#include <iostream>
static std::vector<uint8_t> minimal_elf() {
  std::vector<uint8_t> b(64);
  b[0] = 0x7f;
  b[1] = 'E';
  b[2] = 'L';
  b[3] = 'F';
  b[4] = 2;
  b[5] = 1;
  b[6] = 1;
  b[16] = 2;
  b[18] = 0x3e;
  b[20] = 1;
  b[24] = 0x00;
  b[25] = 0x10;
  b[52] = 64;
  b[54] = 56;
  b[58] = 64;
  return b;
}
static void arithmetic() {
  uint64_t v;
  assert(binforge::checked_add(4, 5, v) && v == 9);
  assert(!binforge::checked_add(UINT64_MAX, 1, v));
  assert(binforge::checked_align_up(4097, 4096, v) && v == 8192);
}
static void reader() {
  uint8_t b[] = {1, 2, 3, 4, 0x81, 1, 'o', 'k', 0};
  binforge::ByteReader r(b, sizeof b);
  uint32_t v;
  assert(r.read_u32(v) && v == 0x04030201);
  uint64_t leb;
  assert(r.read_uleb128(leb) && leb == 129);
  std::string s;
  assert(r.read_c_string(6, 3, s) && s == "ok");
}
static void parse() {
  auto bytes = minimal_elf();
  binforge::Error e;
  auto image = binforge::BinaryParser().parse(bytes.data(), bytes.size(), e);
  assert(image && !e);
  assert(image->header.format == binforge::BinaryFormat::elf_like);
  assert(binforge::BinaryValidator().validate(*image).valid);
}
static void memory() {
  binforge::AddressSpace m;
  binforge::Error e;
  assert(m.map(0x1000, 4096, 3, "data", e));
  assert(!m.map(0x1800, 4096, 3, "overlap", e));
  e.clear();
  uint64_t value = 0x11223344;
  assert(m.write_integer(0x1000, 4, binforge::ByteOrder::little, value, e));
  uint64_t read = 0;
  assert(m.read_integer(0x1000, 4, binforge::ByteOrder::little, read, e) &&
         read == value);
  assert(m.unmap(0x1000, e));
}
static void disassemble() {
  uint8_t code[] = {0xe8, 1, 0, 0, 0, 0xc3};
  binforge::Instruction ins;
  binforge::Error e;
  assert(binforge::X86Disassembler().decode(code, sizeof code, 0x1000, ins, e));
  assert(ins.call && ins.target == 0x1006);
}
static void analysis() {
  auto bytes = minimal_elf();
  binforge::Error error;
  auto image =
      binforge::BinaryParser().parse(bytes.data(), bytes.size(), error);
  assert(image);
  auto metrics = binforge::ImageAnalyzer().analyze(*image, error);
  assert(metrics && metrics->file_size == bytes.size());
  uint8_t code[] = {0x90, 0x74, 0x01, 0x90, 0xc3};
  auto report = binforge::DisassemblyAnalyzer().analyze(
      code, sizeof(code), 0x4000, binforge::X86Disassembler(), error);
  assert(report && report->instructions.size() == 4);
  assert(!report->blocks.empty());
}
int main() {
  arithmetic();
  reader();
  parse();
  memory();
  disassemble();
  analysis();
  std::cout << "all binforge tests passed\n";
}
