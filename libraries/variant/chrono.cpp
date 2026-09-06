module;
#include <chrono>

module forge.variant.chrono;

import forge.chrono.iso8601;
import forge.variant.value;

namespace forge {
void to_variant(const std::chrono::sys_time<std::chrono::microseconds>& t, variant& v) {
   v = forge::chrono::iso8601::format(t);
}

void from_variant(const variant& v, std::chrono::sys_time<std::chrono::microseconds>& t) {
   t = forge::chrono::iso8601::parse_microseconds(v.as_string());
}

void to_variant(const std::chrono::sys_seconds& t, variant& v) {
   v = forge::chrono::iso8601::format(t);
}

void from_variant(const variant& v, std::chrono::sys_seconds& t) {
   t = forge::chrono::iso8601::parse_seconds(v.as_string());
}

void to_variant(const std::chrono::microseconds& input_microseconds, variant& output_variant) {
   output_variant = input_microseconds.count();
}

void from_variant(const variant& input_variant, std::chrono::microseconds& output_microseconds) {
   output_microseconds = std::chrono::microseconds{input_variant.as_int64()};
}
} // namespace forge
