#ifndef BINFORGE_BINFORGE_H
#define BINFORGE_BINFORGE_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace binforge {

enum class ErrorCode {
  none,
  truncated,
  bad_magic,
  unsupported_format,
  unsupported_class,
  unsupported_endian,
  invalid_header,
  invalid_offset,
  invalid_count,
  invalid_alignment,
  invalid_string,
  invalid_section,
  invalid_segment,
  invalid_symbol,
  invalid_relocation,
  invalid_debug_info,
  address_overflow,
  file_range_overflow,
  mapping_overlap,
  mapping_missing,
  permission_denied,
  unresolved_import,
  duplicate_export,
  resource_limit,
  internal_error
};

struct Error {
  ErrorCode code = ErrorCode::none;
  uint64_t offset = 0;
  std::string message;
  explicit operator bool() const { return code != ErrorCode::none; }
  void clear();
};

struct Limits {
  uint64_t max_file_size = 256ull * 1024 * 1024;
  uint64_t max_mapped_bytes = 512ull * 1024 * 1024;
  uint64_t max_section_bytes = 128ull * 1024 * 1024;
  uint64_t max_debug_bytes = 64ull * 1024 * 1024;
  uint64_t max_string_bytes = 1ull * 1024 * 1024;
  uint32_t max_sections = 65536;
  uint32_t max_segments = 65536;
  uint32_t max_symbols = 1'000'000;
  uint32_t max_relocations = 2'000'000;
  uint32_t max_imports = 250000;
  uint32_t max_exports = 250000;
  uint32_t max_debug_units = 65536;
  uint32_t max_debug_depth = 128;
  uint32_t max_line_rows = 2'000'000;
  uint32_t max_disassembly_instructions = 1'000'000;
  uint32_t page_size = 4096;
};

bool checked_add(uint64_t left, uint64_t right, uint64_t &result);
bool checked_multiply(uint64_t left, uint64_t right, uint64_t &result);
bool checked_align_up(uint64_t value, uint64_t alignment, uint64_t &result);
bool range_inside(uint64_t offset, uint64_t length, uint64_t container_size);
uint32_t crc32(const uint8_t *data, size_t size);
std::string error_code_name(ErrorCode code);

enum class ByteOrder { little, big };
enum class BinaryFormat { unknown, elf_like, pe_like, macho_like };
enum class WordSize { bits32 = 4, bits64 = 8 };
enum class BinaryKind {
  unknown,
  relocatable,
  executable,
  shared_library,
  core
};
enum class Architecture { unknown, x86, x86_64, arm, arm64, riscv32, riscv64 };
enum class SectionKind {
  unknown,
  program_bits,
  no_bits,
  string_table,
  symbol_table,
  dynamic_symbols,
  relocations,
  relocation_addends,
  debug,
  imports,
  exports,
  resources,
  unwind,
  notes
};
enum class SymbolBinding { local, global, weak, import_symbol, export_symbol };
enum class SymbolKind {
  unknown,
  object,
  function,
  section,
  file,
  common,
  tls_object
};
enum class RelocationKind {
  none,
  absolute32,
  absolute64,
  relative32,
  relative64,
  pc_relative32,
  got_relative,
  plt_relative,
  high16,
  low16
};

enum Permission : uint8_t {
  permission_none = 0,
  permission_read = 1,
  permission_write = 2,
  permission_execute = 4
};

struct FileHeader {
  BinaryFormat format = BinaryFormat::unknown;
  WordSize word_size = WordSize::bits32;
  ByteOrder byte_order = ByteOrder::little;
  BinaryKind kind = BinaryKind::unknown;
  Architecture architecture = Architecture::unknown;
  uint64_t entry_point = 0;
  uint64_t image_base = 0;
  uint64_t section_table_offset = 0;
  uint64_t segment_table_offset = 0;
  uint32_t section_count = 0;
  uint32_t segment_count = 0;
  uint32_t flags = 0;
};

struct Section {
  uint32_t index = 0;
  std::string name;
  SectionKind kind = SectionKind::unknown;
  uint64_t file_offset = 0;
  uint64_t file_size = 0;
  uint64_t virtual_address = 0;
  uint64_t memory_size = 0;
  uint64_t alignment = 1;
  uint64_t entry_size = 0;
  uint32_t link = 0;
  uint32_t info = 0;
  uint8_t permissions = permission_read;
};

struct Segment {
  uint32_t index = 0;
  uint64_t file_offset = 0;
  uint64_t file_size = 0;
  uint64_t virtual_address = 0;
  uint64_t memory_size = 0;
  uint64_t alignment = 1;
  uint8_t permissions = permission_none;
  std::vector<uint32_t> sections;
};

struct Symbol {
  uint32_t index = 0;
  std::string name;
  SymbolBinding binding = SymbolBinding::local;
  SymbolKind kind = SymbolKind::unknown;
  uint32_t section_index = 0;
  uint64_t value = 0;
  uint64_t size = 0;
  uint8_t visibility = 0;
  std::string library;
};

struct Relocation {
  uint32_t index = 0;
  RelocationKind kind = RelocationKind::none;
  uint32_t target_section = 0;
  uint32_t symbol_index = 0;
  uint64_t offset = 0;
  int64_t addend = 0;
  uint8_t width = 0;
};

struct DebugLineRow {
  uint64_t address = 0;
  uint32_t file = 0;
  uint32_t line = 0;
  uint32_t column = 0;
  bool statement = false;
  bool end_sequence = false;
};

struct DebugAttribute {
  uint32_t name = 0;
  uint32_t form = 0;
  std::variant<uint64_t, int64_t, std::string, std::vector<uint8_t>> value;
};

struct DebugEntry {
  uint64_t offset = 0;
  uint32_t tag = 0;
  bool has_children = false;
  std::vector<DebugAttribute> attributes;
  std::vector<DebugEntry> children;
};

struct DebugUnit {
  uint64_t offset = 0;
  uint64_t length = 0;
  uint16_t version = 0;
  uint8_t address_size = 0;
  std::vector<std::string> files;
  std::vector<DebugLineRow> lines;
  std::vector<DebugEntry> entries;
};

struct Import {
  std::string library;
  std::string name;
  uint64_t ordinal = 0;
  uint64_t slot_address = 0;
  bool weak = false;
};

struct Export {
  std::string name;
  uint64_t address = 0;
  uint64_t ordinal = 0;
  bool forwarded = false;
  std::string forward_target;
};

struct BinaryImage {
  FileHeader header;
  std::vector<Section> sections;
  std::vector<Segment> segments;
  std::vector<Symbol> symbols;
  std::vector<Relocation> relocations;
  std::vector<Import> imports;
  std::vector<Export> exports;
  std::vector<DebugUnit> debug_units;
  std::vector<std::string> warnings;
  std::shared_ptr<const std::vector<uint8_t>> file_data;
  const Section *section(uint32_t index) const;
  const Symbol *symbol(uint32_t index) const;
  const Section *section_named(std::string_view name) const;
};

class ByteReader {
public:
  ByteReader(const uint8_t *data, size_t size,
             ByteOrder order = ByteOrder::little);
  size_t size() const { return size_; }
  size_t position() const { return position_; }
  size_t remaining() const;
  ByteOrder order() const { return order_; }
  void set_order(ByteOrder order) { order_ = order; }
  bool seek(uint64_t position);
  bool skip(uint64_t amount);
  bool read_u8(uint8_t &value);
  bool read_u16(uint16_t &value);
  bool read_u32(uint32_t &value);
  bool read_u64(uint64_t &value);
  bool read_i32(int32_t &value);
  bool read_i64(int64_t &value);
  bool read_uleb128(uint64_t &value);
  bool read_sleb128(int64_t &value);
  bool read_bytes(size_t count, std::vector<uint8_t> &value);
  bool read_fixed_string(size_t count, std::string &value);
  bool read_c_string(uint64_t offset, uint64_t limit, std::string &value) const;
  const uint8_t *pointer(uint64_t offset, uint64_t count) const;

private:
  const uint8_t *data_;
  size_t size_;
  size_t position_ = 0;
  ByteOrder order_;
};

class BinaryParser {
public:
  explicit BinaryParser(Limits limits = {});
  std::optional<BinaryImage> parse(const uint8_t *data, size_t size,
                                   Error &error) const;
  BinaryFormat detect(const uint8_t *data, size_t size) const;

private:
  Limits limits_;
};

class ElfParser {
public:
  explicit ElfParser(Limits limits = {});
  std::optional<BinaryImage>
  parse(std::shared_ptr<const std::vector<uint8_t>> data, Error &error) const;

private:
  Limits limits_;
};

class PeParser {
public:
  explicit PeParser(Limits limits = {});
  std::optional<BinaryImage>
  parse(std::shared_ptr<const std::vector<uint8_t>> data, Error &error) const;

private:
  Limits limits_;
};

class MachOParser {
public:
  explicit MachOParser(Limits limits = {});
  std::optional<BinaryImage>
  parse(std::shared_ptr<const std::vector<uint8_t>> data, Error &error) const;

private:
  Limits limits_;
};

struct MemoryRegion {
  uint64_t base = 0;
  uint64_t size = 0;
  uint8_t permissions = permission_none;
  std::string name;
  std::vector<uint8_t> bytes;
  bool contains(uint64_t address, uint64_t length = 1) const;
};

class AddressSpace {
public:
  explicit AddressSpace(Limits limits = {});
  bool map(uint64_t base, uint64_t size, uint8_t permissions, std::string name,
           Error &error);
  bool unmap(uint64_t base, Error &error);
  bool protect(uint64_t base, uint64_t size, uint8_t permissions, Error &error);
  bool read(uint64_t address, uint8_t *output, size_t size, Error &error) const;
  bool write(uint64_t address, const uint8_t *input, size_t size, Error &error,
             bool ignore_permissions = false);
  bool read_integer(uint64_t address, uint8_t width, ByteOrder order,
                    uint64_t &value, Error &error) const;
  bool write_integer(uint64_t address, uint8_t width, ByteOrder order,
                     uint64_t value, Error &error,
                     bool ignore_permissions = false);
  const MemoryRegion *region_at(uint64_t address) const;
  MemoryRegion *region_at(uint64_t address);
  const std::map<uint64_t, MemoryRegion> &regions() const { return regions_; }
  uint64_t mapped_bytes() const { return mapped_bytes_; }
  void clear();

private:
  Limits limits_;
  std::map<uint64_t, MemoryRegion> regions_;
  uint64_t mapped_bytes_ = 0;
};

class SymbolResolver {
public:
  bool add_export(std::string library, Export symbol, Error &error);
  std::optional<uint64_t> resolve(std::string_view library,
                                  std::string_view name,
                                  uint64_t ordinal) const;
  void clear();

private:
  std::map<std::pair<std::string, std::string>, uint64_t> named_;
  std::map<std::pair<std::string, uint64_t>, uint64_t> ordinal_;
};

struct LoadOptions {
  uint64_t preferred_base = 0;
  bool apply_relocations = true;
  bool resolve_imports = true;
  bool enforce_wx = true;
  bool allow_overlapping_sections = false;
};

struct LoadResult {
  uint64_t load_base = 0;
  uint64_t entry_point = 0;
  uint64_t mapped_bytes = 0;
  uint32_t relocations_applied = 0;
  uint32_t imports_resolved = 0;
  std::vector<std::string> warnings;
};

class RelocationProcessor {
public:
  explicit RelocationProcessor(Limits limits = {});
  bool apply(const BinaryImage &image, AddressSpace &memory, uint64_t load_base,
             const SymbolResolver *resolver, uint32_t &applied,
             Error &error) const;
  bool apply_one(const Relocation &relocation, const BinaryImage &image,
                 AddressSpace &memory, uint64_t load_base,
                 const SymbolResolver *resolver, Error &error) const;

private:
  Limits limits_;
};

class BinaryLoader {
public:
  explicit BinaryLoader(Limits limits = {});
  std::optional<LoadResult> load(const BinaryImage &image, AddressSpace &memory,
                                 const LoadOptions &options,
                                 const SymbolResolver *resolver,
                                 Error &error) const;

private:
  Limits limits_;
};

class DebugInfoParser {
public:
  explicit DebugInfoParser(Limits limits = {});
  bool parse_line_program(const uint8_t *data, size_t size, ByteOrder order,
                          uint8_t address_size, DebugUnit &unit,
                          Error &error) const;
  bool parse_entries(const uint8_t *data, size_t size, ByteOrder order,
                     uint8_t address_size, DebugUnit &unit, Error &error) const;

private:
  Limits limits_;
};

struct Instruction {
  uint64_t address = 0;
  uint8_t size = 0;
  std::array<uint8_t, 16> bytes{};
  std::string mnemonic;
  std::string operands;
  bool branch = false;
  bool call = false;
  bool terminal = false;
  std::optional<uint64_t> target;
};

class Disassembler {
public:
  virtual ~Disassembler() = default;
  virtual bool decode(const uint8_t *data, size_t size, uint64_t address,
                      Instruction &instruction, Error &error) const = 0;
};

class X86Disassembler final : public Disassembler {
public:
  bool decode(const uint8_t *data, size_t size, uint64_t address,
              Instruction &instruction, Error &error) const override;
};

struct ValidationReport {
  bool valid = false;
  uint64_t file_bytes_referenced = 0;
  uint64_t virtual_bytes_referenced = 0;
  std::vector<Error> errors;
  std::vector<std::string> warnings;
};

class BinaryValidator {
public:
  explicit BinaryValidator(Limits limits = {});
  ValidationReport validate(const BinaryImage &image) const;

private:
  Limits limits_;
};

struct AddressRange {
  uint64_t begin = 0;
  uint64_t end = 0;
  uint8_t permissions = permission_none;
  std::string owner;
  bool contains(uint64_t address) const;
  bool overlaps(const AddressRange &other) const;
};

struct SectionMetrics {
  uint32_t section_index = 0;
  uint64_t zero_bytes = 0;
  uint64_t printable_bytes = 0;
  uint64_t unique_byte_values = 0;
  double entropy = 0.0;
  uint32_t checksum = 0;
  bool likely_code = false;
  bool likely_compressed = false;
};

struct ImageMetrics {
  uint64_t file_size = 0;
  uint64_t declared_file_bytes = 0;
  uint64_t declared_memory_bytes = 0;
  uint64_t executable_bytes = 0;
  uint64_t writable_bytes = 0;
  uint64_t zero_fill_bytes = 0;
  uint32_t named_sections = 0;
  uint32_t imported_symbols = 0;
  uint32_t exported_symbols = 0;
  std::vector<SectionMetrics> sections;
  std::vector<AddressRange> address_ranges;
  std::vector<std::string> anomalies;
};

class ImageAnalyzer {
public:
  explicit ImageAnalyzer(Limits limits = {});
  std::optional<ImageMetrics> analyze(const BinaryImage &image,
                                      Error &error) const;
  SectionMetrics analyze_section(const BinaryImage &image,
                                 const Section &section, Error &error) const;

private:
  Limits limits_;
};

struct ControlFlowEdge {
  uint64_t source = 0;
  uint64_t target = 0;
  bool conditional = false;
  bool call = false;
  bool fallthrough = false;
};

struct BasicBlockInfo {
  uint64_t begin = 0;
  uint64_t end = 0;
  uint32_t instruction_count = 0;
  bool complete = false;
  std::vector<ControlFlowEdge> outgoing;
};

struct DisassemblyReport {
  uint64_t start = 0;
  uint64_t end = 0;
  uint64_t bytes_decoded = 0;
  std::vector<Instruction> instructions;
  std::vector<BasicBlockInfo> blocks;
  std::vector<std::string> warnings;
};

class DisassemblyAnalyzer {
public:
  explicit DisassemblyAnalyzer(Limits limits = {});
  std::optional<DisassemblyReport> analyze(const uint8_t *data, size_t size,
                                           uint64_t address,
                                           const Disassembler &decoder,
                                           Error &error) const;

private:
  Limits limits_;
};

struct DependencyNode {
  std::string library;
  std::set<std::string> imports;
  std::set<std::string> exports;
  std::set<std::string> unresolved;
};

struct DependencyReport {
  std::map<std::string, DependencyNode> libraries;
  std::vector<std::string> duplicate_exports;
  uint32_t resolved = 0;
  uint32_t unresolved = 0;
};

class DependencyAnalyzer {
public:
  explicit DependencyAnalyzer(Limits limits = {});
  DependencyReport analyze(const BinaryImage &image,
                           const SymbolResolver *resolver = nullptr) const;

private:
  Limits limits_;
};

} // namespace binforge
#endif
