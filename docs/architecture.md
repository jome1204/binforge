# Architecture

The parser facade performs size enforcement and signature detection before transferring immutable backing storage to a format backend. Backends decode through `ByteReader`, which provides endian-aware fixed integers, bounded C strings, LEB128 values, and overflow-safe seeking without exposing unchecked cursor arithmetic.

ELF parsing supports both classes and byte orders, section/program headers, string tables and static/dynamic symbols. PE parsing validates DOS indirection, COFF and optional headers, section layout, permissions, and COFF symbols. Mach-O parsing walks size-delimited load commands and segment-contained section records. Unknown commands and section types remain representable without weakening range validation.

`BinaryValidator` independently rechecks the normalized model. `BinaryLoader` computes a load bias, page-aligns mappings with checked arithmetic, copies only file-backed bytes, applies relocations, resolves import slots, and returns a numerical entry point. It does not execute mapped data.

`AddressSpace` owns each region in an ordered map. Map overlap is checked against both neighbors; every read and write must fit within a single region and satisfy permissions unless the loader explicitly performs initialization. Stable addresses and copied byte vectors prevent cache lifetime bugs.

Debug parsing uses separate row and nesting budgets. The disassembler interface decodes one instruction at a time, allowing callers to impose instruction and byte limits without requiring an external decoding dependency.
