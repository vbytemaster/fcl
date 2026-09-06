# forge_chrono

`forge_chrono` owns pure formatting and parsing helpers for `std::chrono`
timestamps. It owns no clock, scheduler, thread, FC wire conversion or P2P
lifecycle.

## Public Modules

- `forge.chrono.iso8601` provides the legacy Forge ISO forms and strict RFC3339
  nanosecond parsing and formatting.
- `forge.chrono.relative` provides human-readable relative-time formatting.

Target: `forge_chrono`. Package component: `chrono`.

## Boundaries

- Callers acquire wall-clock values themselves and pass explicit timestamps.
- `forge_raw` owns FC-compatible binary time serialization.
- `forge_variant` owns conversion to and from dynamic values.
- The leaf has no async runtime, scheduler, network or P2P dependency.
- IPNS retains its own seconds-plus-subsecond timestamp and RFC3339Nano codec:
  libp2p-compatible EOL values may reach year 9999, while an `int64`
  `sys_time<nanoseconds>` cannot represent dates beyond 2262.

## ISO And RFC3339

The `format` and `parse_*` functions retain existing millisecond text while
round-tripping full microsecond values. Generic text parsing does not inherit
the FC `uint32` wire range; that validation belongs to `forge_raw`.
Legacy ISO formatting accepts only the Boost Gregorian range from
`1400-01-01T00:00:00` through `9999-12-31T23:59:59` and throws
`std::out_of_range` before invoking Boost outside that range.
`format_rfc3339` emits canonical UTC text with `Z` and trims only insignificant
fractional zeroes. `parse_rfc3339` accepts `Z` or numeric timezone offsets and
rejects invalid dates, trailing data and values outside the exact `int64`
nanosecond range from `1677-09-21T00:12:43.145224192Z` through
`2262-04-11T23:47:16.854775807Z`.
