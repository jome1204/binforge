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

struct FileAddress {
  uint64_t file_offset = 0;
  uint64_t available = 0;
  uint32_t section_index = 0;
};

class AddressTranslator {
public:
  explicit AddressTranslator(const BinaryImage &image);
  std::optional<FileAddress> virtual_to_file(uint64_t address,
                                             uint64_t length = 1) const;
  std::optional<uint64_t> file_to_virtual(uint64_t offset,
                                          uint64_t length = 1) const;
  std::optional<FileAddress> rva_to_file(uint64_t rva,
                                         uint64_t length = 1) const;

private:
  const BinaryImage &image_;
};

struct SymbolLookupResult {
  const Symbol *symbol = nullptr;
  uint64_t displacement = 0;
  bool exact = false;
};

class SymbolIndex {
public:
  explicit SymbolIndex(Limits limits = {});
  bool build(const BinaryImage &image, Error &error);
  const Symbol *by_name(std::string_view name) const;
  const Symbol *by_qualified_name(std::string_view library,
                                  std::string_view name) const;
  SymbolLookupResult nearest(uint64_t address) const;
  std::vector<const Symbol *> prefix(std::string_view prefix,
                                     size_t maximum) const;
  void clear();

private:
  Limits limits_;
  std::map<std::string, const Symbol *> names_;
  std::map<std::pair<std::string, std::string>, const Symbol *> qualified_;
  std::map<uint64_t, const Symbol *> addresses_;
};

struct RelocationDecodeOptions {
  Architecture architecture = Architecture::unknown;
  WordSize word_size = WordSize::bits64;
  ByteOrder byte_order = ByteOrder::little;
  uint32_t target_section = 0;
  uint64_t base_address = 0;
  uint64_t entry_size = 0;
  bool explicit_addends = false;
};

class RelocationTableDecoder {
public:
  explicit RelocationTableDecoder(Limits limits = {});
  bool decode_elf(const uint8_t *data, size_t size,
                  const RelocationDecodeOptions &options,
                  std::vector<Relocation> &output, Error &error) const;
  bool decode_pe_base(const uint8_t *data, size_t size, uint64_t image_base,
                      std::vector<Relocation> &output, Error &error) const;
  bool decode_macho(const uint8_t *data, size_t size,
                    const RelocationDecodeOptions &options,
                    std::vector<Relocation> &output, Error &error) const;

private:
  Limits limits_;
};

struct LayoutRegion {
  uint64_t source_offset = 0;
  uint64_t source_size = 0;
  uint64_t target_address = 0;
  uint64_t target_size = 0;
  uint64_t alignment = 1;
  uint8_t permissions = permission_none;
  std::string name;
};

struct LayoutPlan {
  uint64_t image_begin = 0;
  uint64_t image_end = 0;
  uint64_t mapped_bytes = 0;
  uint64_t file_bytes = 0;
  std::vector<LayoutRegion> regions;
  std::vector<std::string> warnings;
};

class LayoutPlanner {
public:
  explicit LayoutPlanner(Limits limits = {});
  std::optional<LayoutPlan> plan(const BinaryImage &image,
                                 uint64_t requested_base, bool merge_adjacent,
                                 Error &error) const;

private:
  Limits limits_;
};

enum class ResourceKind {
  unknown,
  cursor,
  bitmap,
  icon,
  menu,
  dialog,
  string_table,
  font,
  accelerator,
  raw_data,
  message_table,
  version,
  manifest
};

struct ResourceIdentifier {
  std::optional<uint32_t> integer;
  std::string name;
  bool operator<(const ResourceIdentifier &other) const;
};

struct ResourceEntry {
  ResourceIdentifier type;
  ResourceIdentifier name;
  ResourceIdentifier language;
  ResourceKind kind = ResourceKind::unknown;
  uint64_t file_offset = 0;
  uint64_t size = 0;
  uint32_t code_page = 0;
  uint32_t checksum = 0;
};

struct ResourceReport {
  std::vector<ResourceEntry> entries;
  uint64_t total_bytes = 0;
  uint32_t maximum_depth = 0;
  std::vector<std::string> warnings;
};

class PeResourceParser {
public:
  explicit PeResourceParser(Limits limits = {});
  std::optional<ResourceReport> parse(const BinaryImage &image,
                                      uint64_t directory_rva,
                                      uint64_t directory_size,
                                      Error &error) const;

private:
  Limits limits_;
};

enum class UnwindOperation {
  none,
  push_register,
  allocate_stack,
  save_register,
  set_frame_pointer,
  restore_state,
  finish
};

struct UnwindInstruction {
  UnwindOperation operation = UnwindOperation::none;
  uint32_t register_number = 0;
  uint64_t offset = 0;
  int64_t value = 0;
};

struct UnwindRecord {
  uint64_t start_address = 0;
  uint64_t end_address = 0;
  uint64_t personality = 0;
  uint64_t landing_pad = 0;
  bool signal_frame = false;
  std::vector<UnwindInstruction> instructions;
};

struct UnwindReport {
  std::vector<UnwindRecord> records;
  uint64_t covered_bytes = 0;
  std::vector<std::string> warnings;
};

class UnwindParser {
public:
  explicit UnwindParser(Limits limits = {});
  std::optional<UnwindReport>
  parse_eh_frame(const uint8_t *data, size_t size, uint64_t section_address,
                 WordSize word_size, ByteOrder order, Error &error) const;
  std::optional<UnwindReport> parse_pe_functions(const uint8_t *data,
                                                 size_t size,
                                                 uint64_t image_base,
                                                 Error &error) const;

private:
  Limits limits_;
};

enum class NoteValueKind { bytes, text, integer };
struct BinaryNote {
  std::string owner;
  uint32_t type = 0;
  NoteValueKind value_kind = NoteValueKind::bytes;
  std::variant<std::vector<uint8_t>, std::string, uint64_t> value;
  uint64_t file_offset = 0;
};

class NoteParser {
public:
  explicit NoteParser(Limits limits = {});
  bool parse_elf(const uint8_t *data, size_t size, ByteOrder order,
                 std::vector<BinaryNote> &notes, Error &error) const;
  bool parse_macho_commands(const uint8_t *data, size_t size, ByteOrder order,
                            std::vector<BinaryNote> &notes, Error &error) const;

private:
  Limits limits_;
};

struct ImportTableOptions {
  uint64_t directory_rva = 0;
  uint64_t directory_size = 0;
  uint64_t image_base = 0;
  WordSize word_size = WordSize::bits64;
};

class PeImportExportParser {
public:
  explicit PeImportExportParser(Limits limits = {});
  bool parse_imports(const BinaryImage &image,
                     const ImportTableOptions &options,
                     std::vector<Import> &imports, Error &error) const;
  bool parse_exports(const BinaryImage &image, uint64_t directory_rva,
                     uint64_t directory_size, std::vector<Export> &exports,
                     Error &error) const;

private:
  Limits limits_;
};

struct DynamicEntry {
  int64_t tag = 0;
  uint64_t value = 0;
};

struct DynamicReport {
  std::vector<DynamicEntry> entries;
  std::vector<std::string> needed_libraries;
  std::optional<std::string> soname;
  std::optional<std::string> run_path;
  uint64_t string_table_address = 0;
  uint64_t string_table_size = 0;
  uint64_t symbol_table_address = 0;
  uint64_t relocation_address = 0;
  uint64_t relocation_size = 0;
  bool bind_now = false;
  bool symbolic = false;
};

class ElfDynamicParser {
public:
  explicit ElfDynamicParser(Limits limits = {});
  std::optional<DynamicReport> parse(const BinaryImage &image,
                                     const Section &dynamic_section,
                                     Error &error) const;

private:
  Limits limits_;
};

struct ManifestOptions {
  bool include_symbols = true;
  bool include_relocations = true;
  bool include_imports = true;
  bool include_exports = true;
  bool include_debug_summary = true;
  bool include_checksums = true;
};

class ImageManifestCodec {
public:
  explicit ImageManifestCodec(Limits limits = {});
  std::vector<uint8_t> encode(const BinaryImage &image,
                              const ManifestOptions &options,
                              Error &error) const;
  std::optional<BinaryImage> decode(const uint8_t *data, size_t size,
                                    Error &error) const;

private:
  Limits limits_;
};

enum class DifferenceKind {
  header_changed,
  section_added,
  section_removed,
  section_changed,
  segment_added,
  segment_removed,
  segment_changed,
  symbol_added,
  symbol_removed,
  symbol_changed,
  import_added,
  import_removed,
  export_added,
  export_removed,
  relocation_changed
};

struct ImageDifference {
  DifferenceKind kind = DifferenceKind::header_changed;
  std::string identity;
  std::string before;
  std::string after;
  uint64_t address = 0;
};

struct ImageDiffReport {
  bool equivalent = false;
  uint32_t additions = 0;
  uint32_t removals = 0;
  uint32_t modifications = 0;
  std::vector<ImageDifference> differences;
};

class ImageDiffer {
public:
  explicit ImageDiffer(Limits limits = {});
  ImageDiffReport compare(const BinaryImage &before, const BinaryImage &after,
                          Error &error) const;

private:
  Limits limits_;
};

enum class PatchOperationKind {
  write_bytes,
  fill_bytes,
  write_integer,
  copy_bytes,
  assert_bytes
};

struct PatchOperation {
  PatchOperationKind kind = PatchOperationKind::write_bytes;
  uint64_t address = 0;
  uint64_t source_address = 0;
  uint64_t length = 0;
  uint64_t integer = 0;
  uint8_t width = 0;
  uint8_t fill = 0;
  ByteOrder byte_order = ByteOrder::little;
  std::vector<uint8_t> bytes;
};

struct PatchPlan {
  std::string name;
  uint32_t expected_checksum = 0;
  std::vector<PatchOperation> operations;
  uint64_t bytes_written = 0;
};

struct PatchResult {
  uint32_t operations_applied = 0;
  uint64_t bytes_written = 0;
  uint32_t resulting_checksum = 0;
};

class PatchEngine {
public:
  explicit PatchEngine(Limits limits = {});
  bool validate(const PatchPlan &plan, const AddressSpace &memory,
                Error &error) const;
  std::optional<PatchResult> apply(const PatchPlan &plan, AddressSpace &memory,
                                   Error &error) const;
  std::vector<uint8_t> encode(const PatchPlan &plan, Error &error) const;
  std::optional<PatchPlan> decode(const uint8_t *data, size_t size,
                                  Error &error) const;

private:
  Limits limits_;
};

enum class StringEncoding { ascii, utf8, utf16_little, utf16_big };
struct ExtractedString {
  uint64_t file_offset = 0;
  uint64_t virtual_address = 0;
  StringEncoding encoding = StringEncoding::ascii;
  std::string value;
  uint32_t byte_length = 0;
  uint32_t section_index = UINT32_MAX;
};

struct StringScanOptions {
  uint32_t minimum_characters = 4;
  uint32_t maximum_characters = 4096;
  uint32_t maximum_results = 100000;
  bool ascii = true;
  bool utf8 = true;
  bool utf16_little = true;
  bool utf16_big = false;
  bool require_terminator = false;
};

class StringScanner {
public:
  explicit StringScanner(Limits limits = {});
  std::vector<ExtractedString> scan(const BinaryImage &image,
                                    const StringScanOptions &options,
                                    Error &error) const;

private:
  Limits limits_;
};

struct BytePattern {
  std::string name;
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> mask;
  uint64_t alignment = 1;
};

struct PatternMatch {
  std::string pattern;
  uint64_t file_offset = 0;
  uint64_t virtual_address = 0;
  uint32_t section_index = UINT32_MAX;
};

class SignatureScanner {
public:
  explicit SignatureScanner(Limits limits = {});
  bool add(BytePattern pattern, Error &error);
  std::vector<PatternMatch> scan(const BinaryImage &image, Error &error) const;
  void clear();

private:
  Limits limits_;
  std::vector<BytePattern> patterns_;
};

class Arm64Disassembler final : public Disassembler {
public:
  bool decode(const uint8_t *data, size_t size, uint64_t address,
              Instruction &instruction, Error &error) const override;
};

class RiscVDisassembler final : public Disassembler {
public:
  explicit RiscVDisassembler(bool compressed = true);
  bool decode(const uint8_t *data, size_t size, uint64_t address,
              Instruction &instruction, Error &error) const override;

private:
  bool compressed_;
};

struct BuilderSection {
  std::string name;
  SectionKind kind = SectionKind::program_bits;
  uint8_t permissions = permission_read;
  uint64_t alignment = 1;
  std::vector<uint8_t> data;
  uint64_t zero_fill = 0;
};

struct BuilderOptions {
  BinaryFormat format = BinaryFormat::elf_like;
  BinaryKind kind = BinaryKind::executable;
  Architecture architecture = Architecture::x86_64;
  WordSize word_size = WordSize::bits64;
  ByteOrder byte_order = ByteOrder::little;
  uint64_t image_base = 0x400000;
  uint64_t file_alignment = 16;
  uint64_t memory_alignment = 4096;
  bool separate_permissions = true;
};

class BinaryImageBuilder {
public:
  explicit BinaryImageBuilder(Limits limits = {});
  bool add_section(BuilderSection section, Error &error);
  bool add_symbol(Symbol symbol, Error &error);
  bool add_import(Import imported, Error &error);
  bool add_export(Export exported, Error &error);
  bool add_relocation(Relocation relocation, Error &error);
  std::optional<BinaryImage> build(const BuilderOptions &options,
                                   Error &error) const;
  void clear();

private:
  Limits limits_;
  std::vector<BuilderSection> sections_;
  std::vector<Symbol> symbols_;
  std::vector<Import> imports_;
  std::vector<Export> exports_;
  std::vector<Relocation> relocations_;
};

struct SectionRelation {
  uint32_t source = 0;
  uint32_t target = 0;
  std::string reason;
  uint64_t references = 0;
};

struct SectionGraph {
  std::vector<std::vector<uint32_t>> components;
  std::vector<SectionRelation> relations;
  std::vector<uint32_t> roots;
  std::vector<uint32_t> orphans;
  bool cyclic = false;
};

class SectionGraphAnalyzer {
public:
  explicit SectionGraphAnalyzer(Limits limits = {});
  std::optional<SectionGraph> analyze(const BinaryImage &image,
                                      Error &error) const;

private:
  Limits limits_;
};

struct SnapshotRegion {
  uint64_t base = 0;
  uint64_t size = 0;
  uint8_t permissions = permission_none;
  std::string name;
  uint32_t checksum = 0;
  std::vector<uint8_t> bytes;
};

struct MemorySnapshot {
  uint32_t version = 1;
  uint64_t mapped_bytes = 0;
  std::vector<SnapshotRegion> regions;
};

class MemorySnapshotCodec {
public:
  explicit MemorySnapshotCodec(Limits limits = {});
  MemorySnapshot capture(const AddressSpace &memory, bool include_bytes,
                         Error &error) const;
  bool restore(const MemorySnapshot &snapshot, AddressSpace &memory,
               Error &error) const;
  std::vector<uint8_t> encode(const MemorySnapshot &snapshot,
                              Error &error) const;
  std::optional<MemorySnapshot> decode(const uint8_t *data, size_t size,
                                       Error &error) const;

private:
  Limits limits_;
};

enum class FindingSeverity { information, low, medium, high, critical };
enum class FindingCategory {
  malformed_structure,
  writable_executable,
  missing_hardening,
  suspicious_layout,
  suspicious_import,
  suspicious_export,
  high_entropy,
  entry_point,
  debug_information,
  relocation_policy
};

struct HardeningFinding {
  FindingSeverity severity = FindingSeverity::information;
  FindingCategory category = FindingCategory::malformed_structure;
  std::string title;
  std::string detail;
  uint64_t address = 0;
  std::optional<uint32_t> section_index;
};

struct HardeningReport {
  uint32_t score = 100;
  bool position_independent = false;
  bool non_executable_data = true;
  bool writable_executable = false;
  bool immediate_binding = false;
  bool stack_protection = false;
  bool control_flow_protection = false;
  bool stripped = false;
  std::vector<HardeningFinding> findings;
};

class HardeningAnalyzer {
public:
  explicit HardeningAnalyzer(Limits limits = {});
  std::optional<HardeningReport> analyze(const BinaryImage &image,
                                         Error &error) const;

private:
  Limits limits_;
};

enum class QueryEntity {
  section,
  segment,
  symbol,
  import_symbol,
  export_symbol
};
enum class QueryField {
  name,
  library,
  address,
  size,
  permissions,
  kind,
  binding,
  ordinal
};
enum class QueryOperator {
  equal,
  not_equal,
  less,
  less_equal,
  greater,
  greater_equal,
  contains,
  starts_with,
  bitwise_contains
};

struct QueryPredicate {
  QueryField field = QueryField::name;
  QueryOperator operation = QueryOperator::equal;
  std::variant<uint64_t, std::string> value;
};

struct ImageQuery {
  QueryEntity entity = QueryEntity::section;
  std::vector<QueryPredicate> predicates;
  uint32_t limit = 1000;
  bool require_all = true;
  bool ascending = true;
};

struct QueryRow {
  uint32_t index = 0;
  std::string identity;
  uint64_t address = 0;
  uint64_t size = 0;
  std::map<std::string, std::string> attributes;
};

struct QueryResult {
  uint64_t examined = 0;
  bool truncated = false;
  std::vector<QueryRow> rows;
};

class ImageQueryEngine {
public:
  explicit ImageQueryEngine(Limits limits = {});
  std::optional<QueryResult> execute(const BinaryImage &image,
                                     const ImageQuery &query,
                                     Error &error) const;

private:
  Limits limits_;
};

enum class ReportFormat { text, json, json_lines };
struct ReportOptions {
  ReportFormat format = ReportFormat::text;
  bool include_sections = true;
  bool include_segments = true;
  bool include_symbols = true;
  bool include_imports = true;
  bool include_exports = true;
  bool include_relocations = true;
  bool include_metrics = true;
  bool include_hardening = true;
  uint32_t maximum_items = 100000;
};

class BinaryReportWriter {
public:
  explicit BinaryReportWriter(Limits limits = {});
  std::optional<std::string> write(const BinaryImage &image,
                                   const ReportOptions &options,
                                   Error &error) const;

private:
  Limits limits_;
};

} // namespace binforge
#endif
