#include "binforge/binforge.h"
#include <algorithm>
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
static void indexes_and_relocations() {
  auto bytes = minimal_elf();
  binforge::Error error;
  auto image =
      binforge::BinaryParser().parse(bytes.data(), bytes.size(), error);
  assert(image);
  binforge::SymbolIndex index;
  assert(index.build(*image, error));
  auto plan = binforge::LayoutPlanner().plan(*image, 0x400000, true, error);
  assert(plan);
  uint8_t records[] = {0x00, 0x10, 0x00, 0x00, 0x0a, 0x30};
  std::vector<binforge::Relocation> relocations;
  assert(binforge::RelocationTableDecoder().decode_pe_base(
             records, sizeof(records), 0x140000000, relocations, error) ==
         false);
}
static binforge::BinaryImage built_image() {
  binforge::BinaryImageBuilder builder;
  binforge::Error error;
  binforge::BuilderSection text;
  text.name = ".text";
  text.permissions = binforge::permission_read | binforge::permission_execute;
  text.alignment = 16;
  text.data = {0x90, 0xc3, 'h', 'e', 'l', 'l', 'o', 0};
  assert(builder.add_section(std::move(text), error));
  binforge::BuilderSection data;
  data.name = ".data";
  data.permissions = binforge::permission_read | binforge::permission_write;
  data.alignment = 8;
  data.data = {'w', 'o', 'r', 'l', 'd', 0};
  data.zero_fill = 32;
  assert(builder.add_section(std::move(data), error));
  binforge::Symbol symbol;
  symbol.name = "entry";
  symbol.kind = binforge::SymbolKind::function;
  symbol.binding = binforge::SymbolBinding::global;
  symbol.value = 0x400000;
  symbol.size = 2;
  assert(builder.add_symbol(std::move(symbol), error));
  auto image = builder.build(binforge::BuilderOptions{}, error);
  assert(image && !error);
  return *image;
}
static void manifests_and_diff() {
  auto image = built_image();
  binforge::Error error;
  binforge::ImageManifestCodec codec;
  auto bytes = codec.encode(image, binforge::ManifestOptions{}, error);
  assert(!bytes.empty() && !error);
  auto decoded = codec.decode(bytes.data(), bytes.size(), error);
  assert(decoded && decoded->sections.size() == image.sections.size());
  auto difference = binforge::ImageDiffer().compare(image, *decoded, error);
  assert(difference.equivalent);
  auto graph = binforge::SectionGraphAnalyzer().analyze(image, error);
  assert(graph && graph->components.size() == image.sections.size());
}
static void snapshots_and_patches() {
  binforge::AddressSpace memory;
  binforge::Error error;
  assert(memory.map(0x1000, 4096, 3, "data", error));
  uint8_t initial[] = {1, 2, 3, 4};
  assert(memory.write(0x1000, initial, sizeof(initial), error));
  binforge::MemorySnapshotCodec snapshots;
  auto snapshot = snapshots.capture(memory, true, error);
  auto encoded = snapshots.encode(snapshot, error);
  auto decoded = snapshots.decode(encoded.data(), encoded.size(), error);
  assert(decoded);
  binforge::AddressSpace restored;
  assert(snapshots.restore(*decoded, restored, error));
  uint8_t read[4]{};
  assert(restored.read(0x1000, read, sizeof(read), error));
  assert(std::equal(std::begin(initial), std::end(initial), std::begin(read)));
  binforge::PatchPlan plan;
  plan.name = "unit patch";
  binforge::PatchOperation assertion;
  assertion.kind = binforge::PatchOperationKind::assert_bytes;
  assertion.address = 0x1000;
  assertion.bytes = {1, 2};
  plan.operations.push_back(assertion);
  binforge::PatchOperation write;
  write.kind = binforge::PatchOperationKind::write_integer;
  write.address = 0x1002;
  write.width = 2;
  write.integer = 0xbeef;
  plan.operations.push_back(write);
  plan.bytes_written = 2;
  auto result = binforge::PatchEngine().apply(plan, restored, error);
  assert(result && result->operations_applied == 2);
  auto patch_bytes = binforge::PatchEngine().encode(plan, error);
  auto patch = binforge::PatchEngine().decode(patch_bytes.data(),
                                              patch_bytes.size(), error);
  assert(patch && patch->operations.size() == 2);
}
static void scanners_queries_and_reports() {
  auto image = built_image();
  binforge::Error error;
  binforge::StringScanOptions scan_options;
  scan_options.minimum_characters = 5;
  auto strings = binforge::StringScanner().scan(image, scan_options, error);
  assert(strings.size() >= 2);
  binforge::SignatureScanner scanner;
  binforge::BytePattern pattern;
  pattern.name = "return";
  pattern.bytes = {0xc3};
  assert(scanner.add(std::move(pattern), error));
  auto matches = scanner.scan(image, error);
  assert(matches.size() == 1);
  binforge::ImageQuery query;
  query.entity = binforge::QueryEntity::section;
  query.predicates.push_back({binforge::QueryField::permissions,
                              binforge::QueryOperator::bitwise_contains,
                              uint64_t(binforge::permission_execute)});
  auto rows = binforge::ImageQueryEngine().execute(image, query, error);
  assert(rows && rows->rows.size() == 1);
  auto hardening = binforge::HardeningAnalyzer().analyze(image, error);
  assert(hardening && !hardening->writable_executable);
  binforge::ReportOptions report_options;
  report_options.format = binforge::ReportFormat::json;
  auto report =
      binforge::BinaryReportWriter().write(image, report_options, error);
  assert(report && report->find("\"sections\"") == std::string::npos);
}
static void fixed_disassemblers() {
  binforge::Error error;
  binforge::Instruction instruction;
  uint8_t arm_nop[] = {0x1f, 0x20, 0x03, 0xd5};
  assert(binforge::Arm64Disassembler().decode(arm_nop, sizeof(arm_nop), 0x1000,
                                              instruction, error));
  assert(instruction.mnemonic == "nop");
  uint8_t riscv_ret[] = {0x67, 0x80, 0x00, 0x00};
  assert(binforge::RiscVDisassembler().decode(riscv_ret, sizeof(riscv_ret),
                                              0x2000, instruction, error));
  assert(instruction.mnemonic == "ret");
}
int main() {
  arithmetic();
  reader();
  parse();
  memory();
  disassemble();
  analysis();
  indexes_and_relocations();
  manifests_and_diff();
  snapshots_and_patches();
  scanners_queries_and_reports();
  fixed_disassemblers();
  std::cout << "all binforge tests passed\n";
}
