# forge_variant

`forge_variant` provides the FORGE dynamic value model: scalar values, arrays,
objects, blobs, described-type conversion, `static_variant` and dynamic bitsets.
It is the bridge between typed C++ values and generic codec/config/log shapes.

## When To Use

- A layer needs JSON-like value trees without depending on a concrete parser.
- You need `to_variant/from_variant` for described structs, enums or containers.
- You need FC-like `static_variant` behavior for retained wire compatibility.

## When Not To Use

- Do not use `variant` as an internal data model when a typed struct is known.
- Do not put validation or required-field policy here; use `forge_schema`.
- Do not put binary serialization here; use `forge_raw`.

## Public Modules

- `forge.variant.value` — `variant`, `variant_object`, `mutable_variant_object`.
- `forge.variant.conversion` — scalar/string/blob conversions.
- `forge.variant.containers` — STL container conversions.
- `forge.variant.described` — Boost.Describe object/enum mapping.
- `forge.variant.chrono` — std chrono ISO conversion.
- `forge.variant.multiprecision` — Boost multiprecision conversions.
- `forge.variant.format` — display helpers.
- `forge.variant.schema` — recursive schema-aware conversion for format codecs.
- `forge.variant.static_variant` — FC-style static variant.
- `forge.variant.dynamic_bitset`, `forge.variant.variant_dynamic_bitset`.

Target: `forge_variant`.

Dependencies: `forge_chrono`, `forge_core`, `forge_reflect`, `forge_schema`, Boost headers, Boost.MultiIndex and
Boost.Multiprecision.

## Examples

### Build A Value Object

```cpp
import forge.variant.exceptions;
import forge.variant.value;
import forge.variant.conversion;
import forge.variant.containers;
import forge.variant.chrono;
import forge.variant.multiprecision;
import forge.variant.format;
import forge.variant.described;

auto object = forge::mutable_variant_object{};
object("name", "node-a")("enabled", true)("retries", 3);

forge::variant value{object};
auto enabled = value.get_object()["enabled"].as_bool();
```

### Convert A Described Type

```cpp
#include <boost/describe.hpp>

#include <string>

struct profile {
   std::string name;
   bool enabled = false;
};

BOOST_DESCRIBE_STRUCT(profile, (), (name, enabled))

import forge.variant.described;

auto source = profile{.name = "dev", .enabled = true};
auto value = forge::variant{source};
auto restored = value.as<profile>();
```

### Chrono Values Use ISO Text

```cpp
import forge.variant.chrono;

auto now = std::chrono::sys_time<std::chrono::microseconds>{std::chrono::microseconds{1}};
auto value = forge::variant{now};
auto restored = value.as<std::chrono::sys_time<std::chrono::microseconds>>();
```

## Security Notes

`variant` does not know what is secret. Redaction belongs to config/schema/log/UI
layers before rendering or serialization.

## Risks And Anti-Patterns

- Do not use `variant` as the primary model for application config when a typed
  Boost.Describe struct exists.
- Do not rely on dynamic field lookup for protocol compatibility. Raw contracts
  need typed DTOs and stable field order.
- Do not render arbitrary variants to logs before redaction. The value layer has
  no schema metadata.

## Typical Mistakes

- Do not move `variant` into `core`; many upper layers depend on it, but `core`
  must stay lower than dynamic value conversion.
- Do not assume unknown object fields are validation errors here. Schema/config
  decide that policy.
- `dynamic_bitset` is intentionally a `boost::dynamic_bitset<std::uint8_t>`
  alias because the C++ standard library has no equivalent runtime-size bitset
  with the needed block behavior.

## Tests

`tests/variant` and the JSON/YAML codec suites cover described roundtrip,
schema-aware mapping, missing/unknown field behavior, bad enum values, chrono ISO
conversion, `static_variant`, blob compatibility and dynamic bitsets.

## Schema-Aware Values

Import `forge.variant.schema` when a format codec must preserve canonical
`forge_schema` field names inside an otherwise schema-less described value.
`forge::variant_schema::encode` recursively applies schema field mappings, and
`forge::variant_schema::materialize` converts those nested mappings back before
ordinary `from_variant` decoding. JSON and YAML share this mechanism so their
typed write/read paths cannot drift.
