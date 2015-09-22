#include "binforge/binforge.h"

#include <algorithm>
#include <functional>

namespace binforge {

SectionGraphAnalyzer::SectionGraphAnalyzer(Limits limits) : limits_(limits) {}

std::optional<SectionGraph>
SectionGraphAnalyzer::analyze(const BinaryImage &image, Error &error) const {
  error.clear();
  if (image.sections.size() > limits_.max_sections) {
    error = {ErrorCode::resource_limit, 0,
             "section graph exceeds section limit"};
    return std::nullopt;
  }
  SectionGraph graph;
  std::map<std::pair<uint32_t, uint32_t>, size_t> relation_at;
  auto add_relation = [&](uint32_t source, uint32_t target,
                          std::string reason) -> bool {
    if (source >= image.sections.size() || target >= image.sections.size())
      return false;
    auto key = std::make_pair(source, target);
    auto found = relation_at.find(key);
    if (found != relation_at.end()) {
      ++graph.relations[found->second].references;
      if (graph.relations[found->second].reason.find(reason) ==
          std::string::npos)
        graph.relations[found->second].reason += "," + reason;
      return true;
    }
    relation_at[key] = graph.relations.size();
    graph.relations.push_back({source, target, std::move(reason), 1});
    return true;
  };

  for (const Section &section : image.sections) {
    if (section.link && section.link < image.sections.size())
      add_relation(section.index, section.link, "link");
    if ((section.kind == SectionKind::relocations ||
         section.kind == SectionKind::relocation_addends) &&
        section.info < image.sections.size())
      add_relation(section.index, section.info, "relocation-target");
  }
  for (const Segment &segment : image.segments) {
    for (size_t index = 1; index < segment.sections.size(); ++index)
      add_relation(segment.sections[index - 1], segment.sections[index],
                   "segment-order");
  }
  for (const Relocation &relocation : image.relocations) {
    if (relocation.target_section >= image.sections.size())
      continue;
    const Symbol *symbol = image.symbol(relocation.symbol_index);
    if (symbol && symbol->section_index < image.sections.size())
      add_relation(relocation.target_section, symbol->section_index,
                   "symbol-reference");
  }

  std::vector<std::vector<uint32_t>> adjacency(image.sections.size());
  std::vector<uint32_t> indegree(image.sections.size());
  for (const SectionRelation &relation : graph.relations) {
    adjacency[relation.source].push_back(relation.target);
    ++indegree[relation.target];
  }
  for (uint32_t index = 0; index < image.sections.size(); ++index) {
    if (!indegree[index])
      graph.roots.push_back(index);
    if (adjacency[index].empty() && !indegree[index])
      graph.orphans.push_back(index);
  }

  std::vector<int32_t> index_of(image.sections.size(), -1);
  std::vector<int32_t> low_link(image.sections.size(), -1);
  std::vector<uint32_t> stack;
  std::vector<bool> on_stack(image.sections.size());
  int32_t next_index = 0;
  std::function<void(uint32_t)> strong_connect = [&](uint32_t node) {
    index_of[node] = next_index;
    low_link[node] = next_index++;
    stack.push_back(node);
    on_stack[node] = true;
    for (uint32_t target : adjacency[node]) {
      if (index_of[target] < 0) {
        strong_connect(target);
        low_link[node] = std::min(low_link[node], low_link[target]);
      } else if (on_stack[target]) {
        low_link[node] = std::min(low_link[node], index_of[target]);
      }
    }
    if (low_link[node] != index_of[node])
      return;
    std::vector<uint32_t> component;
    for (;;) {
      uint32_t member = stack.back();
      stack.pop_back();
      on_stack[member] = false;
      component.push_back(member);
      if (member == node)
        break;
    }
    std::sort(component.begin(), component.end());
    if (component.size() > 1)
      graph.cyclic = true;
    else if (std::find(adjacency[node].begin(), adjacency[node].end(), node) !=
             adjacency[node].end())
      graph.cyclic = true;
    graph.components.push_back(std::move(component));
  };
  for (uint32_t node = 0; node < image.sections.size(); ++node)
    if (index_of[node] < 0)
      strong_connect(node);
  std::sort(graph.components.begin(), graph.components.end(),
            [](const auto &left, const auto &right) {
              return left.front() < right.front();
            });
  return graph;
}

} // namespace binforge
