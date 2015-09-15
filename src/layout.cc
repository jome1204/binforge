#include "binforge/binforge.h"

#include <algorithm>
#include <limits>

namespace binforge {

LayoutPlanner::LayoutPlanner(Limits limits) : limits_(limits) {}

std::optional<LayoutPlan> LayoutPlanner::plan(const BinaryImage &image,
                                              uint64_t requested_base,
                                              bool merge_adjacent,
                                              Error &error) const {
  error.clear();
  auto validation = BinaryValidator(limits_).validate(image);
  if (!validation.valid) {
    error = validation.errors.front();
    return std::nullopt;
  }

  LayoutPlan plan;
  if (image.segments.empty()) {
    plan.image_begin = requested_base;
    plan.image_end = requested_base;
    return plan;
  }

  uint64_t original_base = std::numeric_limits<uint64_t>::max();
  for (const Segment &segment : image.segments)
    original_base = std::min(original_base, segment.virtual_address);
  uint64_t load_base = requested_base ? requested_base : original_base;

  for (const Segment &segment : image.segments) {
    if (!segment.memory_size)
      continue;
    uint64_t displacement = segment.virtual_address - original_base;
    uint64_t address = 0;
    if (!checked_add(load_base, displacement, address)) {
      error = {ErrorCode::address_overflow, segment.virtual_address,
               "planned segment address overflows"};
      return std::nullopt;
    }

    uint64_t alignment = std::max<uint64_t>(
        limits_.page_size, segment.alignment ? segment.alignment : 1);
    if ((alignment & (alignment - 1)) != 0) {
      error = {ErrorCode::invalid_alignment, segment.virtual_address,
               "planned segment alignment is not a power of two"};
      return std::nullopt;
    }

    uint64_t target_end = 0;
    if (!checked_add(address, segment.memory_size, target_end)) {
      error = {ErrorCode::address_overflow, address,
               "planned segment range overflows"};
      return std::nullopt;
    }

    LayoutRegion region;
    region.source_offset = segment.file_offset;
    region.source_size = segment.file_size;
    region.target_address = address;
    region.target_size = segment.memory_size;
    region.alignment = alignment;
    region.permissions = segment.permissions;
    region.name = "segment." + std::to_string(segment.index);
    plan.regions.push_back(std::move(region));
  }

  std::sort(plan.regions.begin(), plan.regions.end(),
            [](const LayoutRegion &left, const LayoutRegion &right) {
              if (left.target_address != right.target_address)
                return left.target_address < right.target_address;
              return left.target_size < right.target_size;
            });

  for (size_t index = 1; index < plan.regions.size(); ++index) {
    const LayoutRegion &previous = plan.regions[index - 1];
    const LayoutRegion &current = plan.regions[index];
    uint64_t previous_end = 0;
    if (!checked_add(previous.target_address, previous.target_size,
                     previous_end)) {
      error = {ErrorCode::address_overflow, previous.target_address,
               "planned region end overflows"};
      return std::nullopt;
    }
    if (previous_end > current.target_address) {
      error = {ErrorCode::mapping_overlap, current.target_address,
               previous.name + " overlaps " + current.name};
      return std::nullopt;
    }
  }

  if (merge_adjacent && plan.regions.size() > 1) {
    std::vector<LayoutRegion> merged;
    merged.reserve(plan.regions.size());
    for (LayoutRegion &region : plan.regions) {
      if (!merged.empty()) {
        LayoutRegion &previous = merged.back();
        uint64_t previous_target_end = 0;
        uint64_t previous_source_end = 0;
        bool target_contiguous =
            checked_add(previous.target_address, previous.target_size,
                        previous_target_end) &&
            previous_target_end == region.target_address;
        bool source_contiguous =
            checked_add(previous.source_offset, previous.source_size,
                        previous_source_end) &&
            previous_source_end == region.source_offset;
        if (target_contiguous && source_contiguous &&
            previous.permissions == region.permissions) {
          uint64_t combined_target = 0;
          uint64_t combined_source = 0;
          if (!checked_add(previous.target_size, region.target_size,
                           combined_target) ||
              !checked_add(previous.source_size, region.source_size,
                           combined_source)) {
            error = {ErrorCode::address_overflow, region.target_address,
                     "merged layout size overflows"};
            return std::nullopt;
          }
          previous.target_size = combined_target;
          previous.source_size = combined_source;
          previous.name += "+" + region.name;
          continue;
        }
      }
      merged.push_back(std::move(region));
    }
    plan.regions = std::move(merged);
  }

  if (!plan.regions.empty()) {
    plan.image_begin = plan.regions.front().target_address;
    const LayoutRegion &last = plan.regions.back();
    if (!checked_add(last.target_address, last.target_size, plan.image_end)) {
      error = {ErrorCode::address_overflow, last.target_address,
               "layout image end overflows"};
      return std::nullopt;
    }
  }

  for (const LayoutRegion &region : plan.regions) {
    uint64_t next = 0;
    if (!checked_add(plan.mapped_bytes, region.target_size, next)) {
      error = {ErrorCode::address_overflow, region.target_address,
               "layout mapped-byte total overflows"};
      return std::nullopt;
    }
    plan.mapped_bytes = next;
    if (!checked_add(plan.file_bytes, region.source_size, next)) {
      error = {ErrorCode::address_overflow, region.source_offset,
               "layout file-byte total overflows"};
      return std::nullopt;
    }
    plan.file_bytes = next;
    if ((region.permissions & permission_write) &&
        (region.permissions & permission_execute))
      plan.warnings.push_back(region.name + " is writable and executable");
  }

  if (plan.mapped_bytes > limits_.max_mapped_bytes) {
    error = {ErrorCode::resource_limit, plan.image_begin,
             "planned image exceeds mapped-byte limit"};
    return std::nullopt;
  }
  return plan;
}

} // namespace binforge
