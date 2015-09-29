# BinForge

BinForge is an original, dependency-free C++17 library for inspecting and loading untrusted executable images into a simulated address space. It recognizes ELF32/ELF64, PE32/PE32+, and 32/64-bit Mach-O structures, retaining stable section, segment, symbol, relocation, import, export, and debug models.

Every file range, table multiplication, virtual address, alignment, string, allocation, index and debug nesting transition is bounded. Parsed images retain immutable backing bytes, while the loader copies mapped content into separately owned regions. Relocations and imports use stable numeric identifiers rather than cached pointers.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
ctest --test-dir build --output-on-failure
```

No network access or package download is required. `binforge_cli executable` prints the structural summary and attempts a resource-limited simulated load.

## Fuzzing

Seven independent libFuzzer targets live under `fuzz/`: complete parsing, parse-and-load, synthetic relocation processing, debug metadata, stateful address-space operations, normalized manifests, and transactional patch plans. Each harness owns a format-appropriate seed directory. `.clusterfuzzlite/build.sh` uses only the compiler, sanitizer flags, and fuzzing engine supplied by ClusterFuzzLite and writes every executable to `$OUT`.

Beyond loading, the library provides PE resource/import/export processing, ELF dynamic metadata, unwind and note readers, address translation, symbol indexing, section graphs, image construction, checksummed manifests and snapshots, transactional patching, structural comparison, string and signature scanning, hardening analysis, bounded queries, deterministic reports, and x86/ARM64/RISC-V disassembly interfaces.

BinForge is an inspection and simulation library, not an operating-system loader. It never transfers control to input bytes and does not execute binaries.
