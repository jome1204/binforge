#include "binforge/binforge.h"
#include <algorithm>
#include <cstdio>
namespace binforge {
bool X86Disassembler::decode(const uint8_t *d, size_t size, uint64_t address,
                             Instruction &i, Error &e) const {
  if (!d || !size) {
    e = {ErrorCode::truncated, address, "instruction byte missing"};
    return false;
  }
  i = {};
  i.address = address;
  i.bytes[0] = d[0];
  i.size = 1;
  auto rel8 = [&](const char *name) {
    if (size < 2)
      return false;
    i.size = 2;
    i.bytes[1] = d[1];
    i.mnemonic = name;
    i.branch = true;
    i.target = address + 2 + static_cast<int8_t>(d[1]);
    return true;
  };
  switch (d[0]) {
  case 0x90:
    i.mnemonic = "nop";
    break;
  case 0xc3:
    i.mnemonic = "ret";
    i.terminal = true;
    break;
  case 0xcc:
    i.mnemonic = "int3";
    i.terminal = true;
    break;
  case 0xeb:
    if (!rel8("jmp"))
      goto truncated;
    i.terminal = true;
    break;
  case 0x74:
    if (!rel8("je"))
      goto truncated;
    break;
  case 0x75:
    if (!rel8("jne"))
      goto truncated;
    break;
  case 0xe8:
  case 0xe9: {
    if (size < 5)
      goto truncated;
    int32_t relative = 0;
    relative = int32_t(uint32_t(d[1]) | (uint32_t(d[2]) << 8) |
                       (uint32_t(d[3]) << 16) | (uint32_t(d[4]) << 24));
    i.size = 5;
    std::copy(d, d + 5, i.bytes.begin());
    i.mnemonic = d[0] == 0xe8 ? "call" : "jmp";
    i.branch = true;
    i.call = d[0] == 0xe8;
    i.terminal = d[0] == 0xe9;
    i.target = address + 5 + relative;
    break;
  }
  case 0x55:
    i.mnemonic = "push";
    i.operands = "rbp";
    break;
  case 0x5d:
    i.mnemonic = "pop";
    i.operands = "rbp";
    break;
  default: {
    char buffer[16];
    std::snprintf(buffer, sizeof(buffer), "0x%02x", d[0]);
    i.mnemonic = "db";
    i.operands = buffer;
    break;
  }
  }
  return true;
truncated:
  e = {ErrorCode::truncated, address, "x86 instruction operand truncated"};
  return false;
}
} // namespace binforge
