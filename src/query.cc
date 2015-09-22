#include "binforge/binforge.h"

#include <algorithm>

namespace binforge {
namespace {

bool numeric_compare(uint64_t actual, const QueryPredicate &predicate) {
  if (!std::holds_alternative<uint64_t>(predicate.value))
    return false;
  uint64_t expected = std::get<uint64_t>(predicate.value);
  switch (predicate.operation) {
  case QueryOperator::equal:
    return actual == expected;
  case QueryOperator::not_equal:
    return actual != expected;
  case QueryOperator::less:
    return actual < expected;
  case QueryOperator::less_equal:
    return actual <= expected;
  case QueryOperator::greater:
    return actual > expected;
  case QueryOperator::greater_equal:
    return actual >= expected;
  case QueryOperator::bitwise_contains:
    return (actual & expected) == expected;
  case QueryOperator::contains:
  case QueryOperator::starts_with:
    return false;
  }
  return false;
}

bool text_compare(std::string_view actual, const QueryPredicate &predicate) {
  if (!std::holds_alternative<std::string>(predicate.value))
    return false;
  const std::string &expected = std::get<std::string>(predicate.value);
  switch (predicate.operation) {
  case QueryOperator::equal:
    return actual == expected;
  case QueryOperator::not_equal:
    return actual != expected;
  case QueryOperator::contains:
    return actual.find(expected) != std::string_view::npos;
  case QueryOperator::starts_with:
    return actual.size() >= expected.size() &&
           actual.substr(0, expected.size()) == expected;
  case QueryOperator::less:
    return actual < expected;
  case QueryOperator::less_equal:
    return actual <= expected;
  case QueryOperator::greater:
    return actual > expected;
  case QueryOperator::greater_equal:
    return actual >= expected;
  case QueryOperator::bitwise_contains:
    return false;
  }
  return false;
}

bool combine(const std::vector<bool> &values, bool require_all) {
  if (values.empty())
    return true;
  return require_all ? std::all_of(values.begin(), values.end(),
                                   [](bool value) { return value; })
                     : std::any_of(values.begin(), values.end(),
                                   [](bool value) { return value; });
}

std::string permission_string(uint8_t permissions) {
  std::string result;
  result.push_back(permissions & permission_read ? 'r' : '-');
  result.push_back(permissions & permission_write ? 'w' : '-');
  result.push_back(permissions & permission_execute ? 'x' : '-');
  return result;
}

} // namespace

ImageQueryEngine::ImageQueryEngine(Limits limits) : limits_(limits) {}

std::optional<QueryResult> ImageQueryEngine::execute(const BinaryImage &image,
                                                     const ImageQuery &query,
                                                     Error &error) const {
  error.clear();
  if (!query.limit || query.limit > limits_.max_symbols ||
      query.predicates.size() > limits_.max_sections) {
    error = {ErrorCode::resource_limit, 0, "query limits are invalid"};
    return std::nullopt;
  }
  for (const QueryPredicate &predicate : query.predicates) {
    bool numeric_field = predicate.field != QueryField::name &&
                         predicate.field != QueryField::library;
    if (numeric_field != std::holds_alternative<uint64_t>(predicate.value)) {
      error = {ErrorCode::invalid_header, 0,
               "query predicate type does not match field"};
      return std::nullopt;
    }
  }

  QueryResult result;
  auto accept = [&](QueryRow row, std::vector<bool> matches) {
    ++result.examined;
    if (!combine(matches, query.require_all))
      return;
    if (result.rows.size() >= query.limit) {
      result.truncated = true;
      return;
    }
    result.rows.push_back(std::move(row));
  };

  if (query.entity == QueryEntity::section) {
    for (const Section &section : image.sections) {
      QueryRow row;
      row.index = section.index;
      row.identity = section.name;
      row.address = section.virtual_address;
      row.size = section.memory_size;
      row.attributes["permissions"] = permission_string(section.permissions);
      row.attributes["file_offset"] = std::to_string(section.file_offset);
      row.attributes["kind"] =
          std::to_string(static_cast<uint8_t>(section.kind));
      std::vector<bool> matches;
      for (const QueryPredicate &predicate : query.predicates) {
        switch (predicate.field) {
        case QueryField::name:
          matches.push_back(text_compare(section.name, predicate));
          break;
        case QueryField::address:
          matches.push_back(
              numeric_compare(section.virtual_address, predicate));
          break;
        case QueryField::size:
          matches.push_back(numeric_compare(section.memory_size, predicate));
          break;
        case QueryField::permissions:
          matches.push_back(numeric_compare(section.permissions, predicate));
          break;
        case QueryField::kind:
          matches.push_back(
              numeric_compare(static_cast<uint8_t>(section.kind), predicate));
          break;
        default:
          matches.push_back(false);
          break;
        }
      }
      accept(std::move(row), std::move(matches));
    }
  } else if (query.entity == QueryEntity::segment) {
    for (const Segment &segment : image.segments) {
      QueryRow row;
      row.index = segment.index;
      row.identity = "segment." + std::to_string(segment.index);
      row.address = segment.virtual_address;
      row.size = segment.memory_size;
      row.attributes["permissions"] = permission_string(segment.permissions);
      row.attributes["file_offset"] = std::to_string(segment.file_offset);
      std::vector<bool> matches;
      for (const QueryPredicate &predicate : query.predicates) {
        switch (predicate.field) {
        case QueryField::name:
          matches.push_back(text_compare(row.identity, predicate));
          break;
        case QueryField::address:
          matches.push_back(
              numeric_compare(segment.virtual_address, predicate));
          break;
        case QueryField::size:
          matches.push_back(numeric_compare(segment.memory_size, predicate));
          break;
        case QueryField::permissions:
          matches.push_back(numeric_compare(segment.permissions, predicate));
          break;
        default:
          matches.push_back(false);
          break;
        }
      }
      accept(std::move(row), std::move(matches));
    }
  } else if (query.entity == QueryEntity::symbol) {
    for (const Symbol &symbol : image.symbols) {
      QueryRow row;
      row.index = symbol.index;
      row.identity = symbol.name;
      row.address = symbol.value;
      row.size = symbol.size;
      row.attributes["library"] = symbol.library;
      row.attributes["binding"] =
          std::to_string(static_cast<uint8_t>(symbol.binding));
      row.attributes["kind"] =
          std::to_string(static_cast<uint8_t>(symbol.kind));
      std::vector<bool> matches;
      for (const QueryPredicate &predicate : query.predicates) {
        switch (predicate.field) {
        case QueryField::name:
          matches.push_back(text_compare(symbol.name, predicate));
          break;
        case QueryField::library:
          matches.push_back(text_compare(symbol.library, predicate));
          break;
        case QueryField::address:
          matches.push_back(numeric_compare(symbol.value, predicate));
          break;
        case QueryField::size:
          matches.push_back(numeric_compare(symbol.size, predicate));
          break;
        case QueryField::binding:
          matches.push_back(
              numeric_compare(static_cast<uint8_t>(symbol.binding), predicate));
          break;
        case QueryField::kind:
          matches.push_back(
              numeric_compare(static_cast<uint8_t>(symbol.kind), predicate));
          break;
        default:
          matches.push_back(false);
          break;
        }
      }
      accept(std::move(row), std::move(matches));
    }
  } else if (query.entity == QueryEntity::import_symbol) {
    for (uint32_t index = 0; index < image.imports.size(); ++index) {
      const Import &imported = image.imports[index];
      QueryRow row;
      row.index = index;
      row.identity = imported.name;
      row.address = imported.slot_address;
      row.attributes["library"] = imported.library;
      row.attributes["ordinal"] = std::to_string(imported.ordinal);
      std::vector<bool> matches;
      for (const QueryPredicate &predicate : query.predicates) {
        switch (predicate.field) {
        case QueryField::name:
          matches.push_back(text_compare(imported.name, predicate));
          break;
        case QueryField::library:
          matches.push_back(text_compare(imported.library, predicate));
          break;
        case QueryField::address:
          matches.push_back(numeric_compare(imported.slot_address, predicate));
          break;
        case QueryField::ordinal:
          matches.push_back(numeric_compare(imported.ordinal, predicate));
          break;
        default:
          matches.push_back(false);
          break;
        }
      }
      accept(std::move(row), std::move(matches));
    }
  } else {
    for (uint32_t index = 0; index < image.exports.size(); ++index) {
      const Export &exported = image.exports[index];
      QueryRow row;
      row.index = index;
      row.identity = exported.name;
      row.address = exported.address;
      row.attributes["ordinal"] = std::to_string(exported.ordinal);
      row.attributes["forward"] = exported.forward_target;
      std::vector<bool> matches;
      for (const QueryPredicate &predicate : query.predicates) {
        switch (predicate.field) {
        case QueryField::name:
          matches.push_back(text_compare(exported.name, predicate));
          break;
        case QueryField::address:
          matches.push_back(numeric_compare(exported.address, predicate));
          break;
        case QueryField::ordinal:
          matches.push_back(numeric_compare(exported.ordinal, predicate));
          break;
        default:
          matches.push_back(false);
          break;
        }
      }
      accept(std::move(row), std::move(matches));
    }
  }
  std::sort(result.rows.begin(), result.rows.end(),
            [&](const QueryRow &left, const QueryRow &right) {
              if (left.address != right.address)
                return query.ascending ? left.address < right.address
                                       : left.address > right.address;
              return query.ascending ? left.identity < right.identity
                                     : left.identity > right.identity;
            });
  return result;
}

} // namespace binforge
