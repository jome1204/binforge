#include "binforge/binforge.h"

#include <algorithm>
#include <map>
#include <set>

namespace binforge {

DisassemblyAnalyzer::DisassemblyAnalyzer(Limits limits) : limits_(limits) {}

std::optional<DisassemblyReport>
DisassemblyAnalyzer::analyze(const uint8_t *data, size_t size, uint64_t address,
                             const Disassembler &decoder, Error &error) const {
  error.clear();
  if (!data && size) {
    error = {ErrorCode::invalid_offset, address,
             "disassembly input pointer is null"};
    return std::nullopt;
  }

  DisassemblyReport report;
  report.start = address;
  report.instructions.reserve(
      std::min<size_t>(size, limits_.max_disassembly_instructions));

  size_t offset = 0;
  while (offset < size &&
         report.instructions.size() < limits_.max_disassembly_instructions) {
    uint64_t instruction_address = 0;
    if (!checked_add(address, offset, instruction_address)) {
      error = {ErrorCode::address_overflow, address,
               "instruction address overflows"};
      return std::nullopt;
    }

    Instruction instruction;
    Error decode_error;
    if (!decoder.decode(data + offset, size - offset, instruction_address,
                        instruction, decode_error)) {
      report.warnings.push_back("decode stopped at " +
                                std::to_string(instruction_address) + ": " +
                                decode_error.message);
      break;
    }
    if (!instruction.size || instruction.size > size - offset ||
        instruction.size > instruction.bytes.size()) {
      error = {ErrorCode::invalid_offset, instruction_address,
               "decoder returned an invalid instruction length"};
      return std::nullopt;
    }
    offset += instruction.size;
    report.instructions.push_back(std::move(instruction));
  }

  if (report.instructions.size() >= limits_.max_disassembly_instructions &&
      offset < size) {
    report.warnings.push_back("instruction limit reached");
  }

  report.bytes_decoded = offset;
  if (!checked_add(address, offset, report.end)) {
    error = {ErrorCode::address_overflow, address,
             "disassembly end address overflows"};
    return std::nullopt;
  }

  std::set<uint64_t> leaders;
  leaders.insert(address);
  std::map<uint64_t, size_t> instruction_at;
  for (size_t index = 0; index < report.instructions.size(); ++index) {
    const Instruction &instruction = report.instructions[index];
    instruction_at[instruction.address] = index;
    uint64_t fallthrough = 0;
    if (!checked_add(instruction.address, instruction.size, fallthrough))
      continue;
    if (instruction.target && instruction_at.count(*instruction.target))
      leaders.insert(*instruction.target);
    if (instruction.branch && !instruction.terminal)
      leaders.insert(fallthrough);
  }

  for (const Instruction &instruction : report.instructions) {
    if (instruction.target && *instruction.target >= report.start &&
        *instruction.target < report.end)
      leaders.insert(*instruction.target);
  }

  std::vector<uint64_t> ordered_leaders(leaders.begin(), leaders.end());
  for (size_t leader_index = 0; leader_index < ordered_leaders.size();
       ++leader_index) {
    uint64_t leader = ordered_leaders[leader_index];
    auto found = instruction_at.find(leader);
    if (found == instruction_at.end())
      continue;

    BasicBlockInfo block;
    block.begin = leader;
    size_t instruction_index = found->second;
    uint64_t next_leader = leader_index + 1 < ordered_leaders.size()
                               ? ordered_leaders[leader_index + 1]
                               : report.end;

    while (instruction_index < report.instructions.size()) {
      const Instruction &instruction = report.instructions[instruction_index];
      if (instruction.address >= next_leader && block.instruction_count)
        break;

      ++block.instruction_count;
      if (!checked_add(instruction.address, instruction.size, block.end)) {
        error = {ErrorCode::address_overflow, instruction.address,
                 "basic-block end overflows"};
        return std::nullopt;
      }

      if (instruction.target) {
        block.outgoing.push_back(
            {instruction.address, *instruction.target,
             instruction.branch && !instruction.terminal && !instruction.call,
             instruction.call, false});
      }

      if (instruction.branch || instruction.terminal) {
        if (!instruction.terminal && !instruction.call) {
          block.outgoing.push_back(
              {instruction.address, block.end, false, false, true});
        } else if (instruction.call) {
          block.outgoing.push_back(
              {instruction.address, block.end, false, false, true});
        }
        block.complete = true;
        break;
      }

      ++instruction_index;
    }

    if (!block.complete && block.end == next_leader)
      block.outgoing.push_back({block.end, next_leader, false, false, true});
    report.blocks.push_back(std::move(block));
  }

  return report;
}

} // namespace binforge
