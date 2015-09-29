#!/bin/bash
set -euxo pipefail
cd "$SRC/repo"
mkdir -p "$WORK/obj" "$OUT"
sources=(src/base.cc src/reader.cc src/address_space.cc src/parser.cc src/elf_parser.cc src/pe_parser.cc src/macho_parser.cc src/loader.cc src/validator.cc src/disassembler.cc src/disassembly_analyzer.cc src/fixed_disassemblers.cc src/debug_info.cc src/image_analyzer.cc src/image_diff.cc src/symbol_index.cc src/relocation_decoder.cc src/layout.cc src/pe_imports.cc src/pe_resources.cc src/elf_dynamic.cc src/notes.cc src/unwind.cc src/manifest.cc src/patch_engine.cc src/scanners.cc src/builder.cc src/section_graph.cc src/snapshot.cc src/hardening.cc src/query.cc src/report_writer.cc)
objects=()
for source in "${sources[@]}"; do
 object="$WORK/obj/$(basename "${source%.cc}").o"
 "$CXX" $CXXFLAGS -std=c++17 -Iinclude -c "$source" -o "$object"
 objects+=("$object")
done
for harness in fuzz/*_fuzzer.cc; do
 name="$(basename "${harness%.cc}")"
 "$CXX" $CXXFLAGS -std=c++17 -Iinclude "$harness" "${objects[@]}" "$LIB_FUZZING_ENGINE" -o "$OUT/$name"
 if [ -d "fuzz/corpus/$name" ]; then
  (cd "fuzz/corpus/$name" && zip -q -r "$OUT/${name}_seed_corpus.zip" .)
 fi
done
