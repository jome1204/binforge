#!/usr/bin/env python3
"""Generate deterministic, original BinForge fuzz seeds without dependencies."""
from pathlib import Path
import struct
import zlib

ROOT = Path(__file__).resolve().parents[1] / "fuzz" / "corpus"

def put(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def align(value: int, boundary: int) -> int:
    return (value + boundary - 1) & -boundary

def elf64(kind=2, sections=(), machine=62, entry=0x401000, alignment=0x1000):
    names = bytearray(b"\0.shstrtab\0")
    records = [(0, 0, 0, b"", 0, 0)]
    for name, section_type, flags, payload, address, link in sections:
        name_offset = len(names); names += name.encode() + b"\0"
        records.append((name_offset, section_type, flags, payload, address, link))
    shstr_name = 1
    records.append((shstr_name, 3, 0, bytes(names), 0, 0))
    has_program = kind != 1
    image = bytearray(120 if has_program else 64)
    image[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", image, 16, kind, machine, 1, entry,
                     64 if has_program else 0, 0, 0, 64, 56,
                     1 if has_program else 0, 64, len(records), len(records)-1)
    section_rows = []
    for name, typ, flags, payload, address, link in records:
        if payload:
            offset = align(len(image), max(1, min(alignment, 16)))
            image += bytes(offset-len(image)); image += payload
        else: offset = 0
        section_rows.append((name, typ, flags, address, offset, len(payload),
                             link, 0, alignment if flags & 2 else 1, 0))
    shoff = align(len(image), 8); image += bytes(shoff-len(image))
    for row in section_rows: image += struct.pack("<IIQQQQIIQQ", *row)
    struct.pack_into("<Q", image, 40, shoff)
    if has_program:
        struct.pack_into("<IIQQQQQQ", image, 64, 1, 5, 0, 0x400000,
                         0x400000, len(image), len(image), alignment)
    return bytes(image)

def elf_executable():
    return elf64(sections=[(".text",1,6,b"\x90\x90\xc3",0x401000,0),
                           (".rodata",1,2,b"hello binforge\0",0x402000,0)])

def elf_object():
    strings=b"\0unit.c\0entry\0"; symbols=bytes(24)+struct.pack("<IBBHQQ",8,0x12,0,1,0,3)
    return elf64(kind=1,entry=0,sections=[(".text",1,6,b"\x90\xc3",0,0),
        (".strtab",3,0,strings,0,0),(".symtab",2,0,symbols,0,2)])

def elf_shared():
    strings=b"\0libdependency.so\0libseed.so\0"; dynamic=(struct.pack("<qQ",1,1)+
        struct.pack("<qQ",14,18)+struct.pack("<qQ",5,0)+
        struct.pack("<qQ",10,len(strings))+struct.pack("<qQ",0,0))
    return elf64(kind=3,entry=0,sections=[(".text",1,6,b"\xc3",0x1000,0),
        (".dynstr",3,2,strings,0x2000,0),(".dynamic",6,3,dynamic,0x3000,1)])

def elf_relocations():
    rela=b"".join(struct.pack("<QQq",0x5000+i*8,8,i) for i in range(32))
    return elf64(sections=[(".text",1,6,b"\x90"*64,0x401000,0),
                           (".rela.text",4,0,rela,0,0)])

def elf_debug():
    debug=b"\x20\0\0\0\x04\0\x08\0"+b"source.c\0main\0"+bytes(range(32))
    return elf64(sections=[(".text",1,6,b"\x55\x90\xc3",0x401000,0),
                           (".debug_info",1,0,debug,0,0),
                           (".debug_line",1,0,b"\x10\0\0\0\x04\0"+bytes(16),0,0)])

def elf_many_sections():
    entries=[]
    for i in range(48): entries.append((f".seed{i:02d}",1,2,bytes([i])*8,0x500000+i*0x1000,0))
    return elf64(sections=entries)

def pe64():
    data=bytearray(0x400); data[:2]=b"MZ"; struct.pack_into("<I",data,0x3c,0x80)
    data[0x80:0x84]=b"PE\0\0"; struct.pack_into("<HHIIIHH",data,0x84,0x8664,1,0,0,0,0xf0,0x22)
    opt=0x98; struct.pack_into("<H",data,opt,0x20b); struct.pack_into("<I",data,opt+16,0x1000)
    struct.pack_into("<Q",data,opt+24,0x140000000); struct.pack_into("<II",data,opt+32,0x1000,0x200)
    struct.pack_into("<I",data,opt+108,16); sec=0x188; data[sec:sec+8]=b".text\0\0\0"
    struct.pack_into("<IIII",data,sec+8,3,0x1000,0x200,0x200); struct.pack_into("<I",data,sec+36,0x60000020)
    data[0x200:0x203]=b"\x90\x90\xc3"; return bytes(data)

def macho64():
    header=struct.pack("<IIIIIIII",0xfeedfacf,0x01000007,3,2,1,72,0,0)
    command=struct.pack("<II16sQQQQIIII",0x19,72,b"__TEXT\0"+bytes(9),0x100000000,0x1000,0,0x1000,7,5,0,0)
    return (header+command).ljust(0x1000,b"\0")

def manifest_seed():
    body=b"BFMF"+struct.pack("<II",1,0)+bytes(32)
    return body+struct.pack("<I",zlib.crc32(body)&0xffffffff)

def main():
    parser=ROOT/"binary_parser_fuzzer"; loader=ROOT/"binary_loader_fuzzer"
    seeds={"minimal_executable.elf":elf_executable(),"object_file.elf":elf_object(),
           "shared_library.elf":elf_shared(),"relocation_heavy.elf":elf_relocations(),
           "debug_information.elf":elf_debug(),"many_sections.elf":elf_many_sections(),
           "unusual_alignment.elf":elf64(sections=[(".odd",1,2,b"A"*17,0x800000,0)],alignment=0x10000),
           "stripped.elf":elf64(sections=[(".text",1,6,b"\xc3",0x401000,0)]),
           "minimal_pe.exe":pe64(),"minimal_macho.bin":macho64()}
    for name,data in seeds.items(): put(parser/name,data)
    for name in ("minimal_executable.elf","shared_library.elf","minimal_pe.exe","minimal_macho.bin"):
        put(loader/name,seeds[name])
    put(ROOT/"manifest_fuzzer"/"minimal_manifest.bfmf",manifest_seed())

if __name__ == "__main__": main()
