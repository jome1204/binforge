#include "binforge/binforge.h"

#include <algorithm>
#include <cstdio>

namespace binforge {
namespace {

uint32_t little32(const uint8_t *data) {
  return uint32_t(data[0]) | (uint32_t(data[1]) << 8) |
         (uint32_t(data[2]) << 16) | (uint32_t(data[3]) << 24);
}

int64_t sign_extend(uint64_t value, unsigned bits) {
  uint64_t sign = uint64_t{1} << (bits - 1);
  return static_cast<int64_t>((value ^ sign) - sign);
}

std::string arm_register(uint32_t value) {
  if (value == 31)
    return "sp";
  return "x" + std::to_string(value);
}

std::string riscv_register(uint32_t value) {
  static const char *names[] = {
      "zero", "ra", "sp", "gp", "tp",  "t0",  "t1", "t2", "s0", "s1", "a0",
      "a1",   "a2", "a3", "a4", "a5",  "a6",  "a7", "s2", "s3", "s4", "s5",
      "s6",   "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"};
  return names[value & 31];
}

} // namespace

bool Arm64Disassembler::decode(const uint8_t *data, size_t size,
                               uint64_t address, Instruction &instruction,
                               Error &error) const {
  if (!data || size < 4) {
    error = {ErrorCode::truncated, address, "ARM64 instruction is truncated"};
    return false;
  }
  uint32_t word = little32(data);
  instruction = {};
  instruction.address = address;
  instruction.size = 4;
  std::copy(data, data + 4, instruction.bytes.begin());
  uint32_t destination = word & 31;
  uint32_t source = (word >> 5) & 31;

  if (word == 0xd503201f) {
    instruction.mnemonic = "nop";
  } else if (word == 0xd65f03c0) {
    instruction.mnemonic = "ret";
    instruction.terminal = true;
  } else if ((word & 0xfffffc1f) == 0xd61f0000) {
    instruction.mnemonic = "br";
    instruction.operands = arm_register(source);
    instruction.branch = true;
    instruction.terminal = true;
  } else if ((word & 0xfffffc1f) == 0xd63f0000) {
    instruction.mnemonic = "blr";
    instruction.operands = arm_register(source);
    instruction.branch = true;
    instruction.call = true;
  } else if ((word & 0x7c000000) == 0x14000000) {
    int64_t displacement = sign_extend(word & 0x03ffffff, 26) << 2;
    instruction.mnemonic = (word & 0x80000000u) ? "bl" : "b";
    instruction.branch = true;
    instruction.call = (word & 0x80000000u) != 0;
    instruction.terminal = !instruction.call;
    instruction.target = static_cast<uint64_t>(address + displacement);
    instruction.operands = "0x" + std::to_string(*instruction.target);
  } else if ((word & 0xff000010) == 0x54000000) {
    int64_t displacement = sign_extend((word >> 5) & 0x7ffff, 19) << 2;
    instruction.mnemonic = "b.cond";
    instruction.branch = true;
    instruction.target = static_cast<uint64_t>(address + displacement);
    instruction.operands = "0x" + std::to_string(*instruction.target);
  } else if ((word & 0x7f000000) == 0x34000000) {
    int64_t displacement = sign_extend((word >> 5) & 0x7ffff, 19) << 2;
    instruction.mnemonic = (word & 0x01000000) ? "cbnz" : "cbz";
    instruction.branch = true;
    instruction.target = static_cast<uint64_t>(address + displacement);
    instruction.operands = arm_register(destination) + ", 0x" +
                           std::to_string(*instruction.target);
  } else if ((word & 0x7f800000) == 0x52800000) {
    uint32_t immediate = (word >> 5) & 0xffff;
    instruction.mnemonic = "mov";
    instruction.operands =
        arm_register(destination) + ", #" + std::to_string(immediate);
  } else if ((word & 0x7f000000) == 0x11000000) {
    uint32_t immediate = (word >> 10) & 0xfff;
    instruction.mnemonic = (word & 0x40000000) ? "sub" : "add";
    instruction.operands = arm_register(destination) + ", " +
                           arm_register(source) + ", #" +
                           std::to_string(immediate);
  } else if ((word & 0xffc00000) == 0xf9400000) {
    uint32_t offset = ((word >> 10) & 0xfff) * 8;
    instruction.mnemonic = "ldr";
    instruction.operands = arm_register(destination) + ", [" +
                           arm_register(source) + ", #" +
                           std::to_string(offset) + "]";
  } else if ((word & 0xffc00000) == 0xf9000000) {
    uint32_t offset = ((word >> 10) & 0xfff) * 8;
    instruction.mnemonic = "str";
    instruction.operands = arm_register(destination) + ", [" +
                           arm_register(source) + ", #" +
                           std::to_string(offset) + "]";
  } else {
    char buffer[24];
    std::snprintf(buffer, sizeof(buffer), "0x%08x", word);
    instruction.mnemonic = ".word";
    instruction.operands = buffer;
  }
  return true;
}

RiscVDisassembler::RiscVDisassembler(bool compressed)
    : compressed_(compressed) {}

bool RiscVDisassembler::decode(const uint8_t *data, size_t size,
                               uint64_t address, Instruction &instruction,
                               Error &error) const {
  if (!data || size < 2) {
    error = {ErrorCode::truncated, address, "RISC-V instruction is truncated"};
    return false;
  }
  uint16_t half = uint16_t(data[0]) | (uint16_t(data[1]) << 8);
  instruction = {};
  instruction.address = address;
  if ((half & 3) != 3) {
    if (!compressed_) {
      error = {ErrorCode::invalid_header, address,
               "compressed RISC-V instruction is disabled"};
      return false;
    }
    instruction.size = 2;
    instruction.bytes[0] = data[0];
    instruction.bytes[1] = data[1];
    uint8_t quadrant = half & 3;
    uint8_t function = half >> 13;
    if (half == 1) {
      instruction.mnemonic = "c.nop";
    } else if (quadrant == 1 && function == 5) {
      uint32_t immediate = ((half >> 2) & 0x7ff);
      int64_t displacement = sign_extend(immediate, 11) << 1;
      instruction.mnemonic = "c.j";
      instruction.branch = true;
      instruction.terminal = true;
      instruction.target = static_cast<uint64_t>(address + displacement);
    } else if (quadrant == 2 && function == 4 && ((half >> 12) & 1)) {
      uint32_t source = (half >> 2) & 31;
      instruction.mnemonic = source ? "c.jalr" : "c.ebreak";
      instruction.call = source != 0;
      instruction.branch = source != 0;
      instruction.terminal = source == 0;
      instruction.operands = source ? riscv_register(source) : "";
    } else {
      char buffer[16];
      std::snprintf(buffer, sizeof(buffer), "0x%04x", half);
      instruction.mnemonic = ".half";
      instruction.operands = buffer;
    }
    return true;
  }
  if (size < 4) {
    error = {ErrorCode::truncated, address,
             "RISC-V 32-bit instruction is truncated"};
    return false;
  }
  uint32_t word = little32(data);
  instruction.size = 4;
  std::copy(data, data + 4, instruction.bytes.begin());
  uint32_t opcode = word & 0x7f;
  uint32_t destination = (word >> 7) & 31;
  uint32_t function3 = (word >> 12) & 7;
  uint32_t source1 = (word >> 15) & 31;
  uint32_t source2 = (word >> 20) & 31;
  uint32_t function7 = word >> 25;
  if (word == 0x00008067) {
    instruction.mnemonic = "ret";
    instruction.terminal = true;
  } else if (opcode == 0x6f) {
    uint32_t encoded = ((word >> 31) << 20) | (((word >> 12) & 0xff) << 12) |
                       (((word >> 20) & 1) << 11) |
                       (((word >> 21) & 0x3ff) << 1);
    int64_t displacement = sign_extend(encoded, 21);
    instruction.mnemonic = "jal";
    instruction.operands = riscv_register(destination);
    instruction.branch = true;
    instruction.call = destination == 1;
    instruction.terminal = !instruction.call;
    instruction.target = static_cast<uint64_t>(address + displacement);
  } else if (opcode == 0x67) {
    int64_t immediate = sign_extend(word >> 20, 12);
    instruction.mnemonic = "jalr";
    instruction.operands = riscv_register(destination) + ", " +
                           std::to_string(immediate) + "(" +
                           riscv_register(source1) + ")";
    instruction.branch = true;
    instruction.call = destination == 1;
  } else if (opcode == 0x63) {
    uint32_t encoded = ((word >> 31) << 12) | (((word >> 7) & 1) << 11) |
                       (((word >> 25) & 0x3f) << 5) |
                       (((word >> 8) & 0xf) << 1);
    int64_t displacement = sign_extend(encoded, 13);
    static const char *names[] = {"beq", "bne", "?",    "?",
                                  "blt", "bge", "bltu", "bgeu"};
    instruction.mnemonic = names[function3];
    instruction.operands =
        riscv_register(source1) + ", " + riscv_register(source2);
    instruction.branch = true;
    instruction.target = static_cast<uint64_t>(address + displacement);
  } else if (opcode == 0x13) {
    int64_t immediate = sign_extend(word >> 20, 12);
    instruction.mnemonic = function3 == 0 ? "addi" : "op-imm";
    instruction.operands = riscv_register(destination) + ", " +
                           riscv_register(source1) + ", " +
                           std::to_string(immediate);
  } else if (opcode == 0x33) {
    if (function3 == 0)
      instruction.mnemonic = function7 == 0x20 ? "sub" : "add";
    else
      instruction.mnemonic = "op";
    instruction.operands = riscv_register(destination) + ", " +
                           riscv_register(source1) + ", " +
                           riscv_register(source2);
  } else if (opcode == 0x03) {
    instruction.mnemonic = function3 == 3 ? "ld" : "lw";
    instruction.operands =
        riscv_register(destination) + ", (" + riscv_register(source1) + ")";
  } else if (opcode == 0x23) {
    instruction.mnemonic = function3 == 3 ? "sd" : "sw";
    instruction.operands =
        riscv_register(source2) + ", (" + riscv_register(source1) + ")";
  } else {
    char buffer[24];
    std::snprintf(buffer, sizeof(buffer), "0x%08x", word);
    instruction.mnemonic = ".word";
    instruction.operands = buffer;
  }
  return true;
}

} // namespace binforge
