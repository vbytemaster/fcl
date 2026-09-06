#include <chrono>

import forge.chrono.iso8601;

int main() {
   const auto instant = std::chrono::sys_seconds{std::chrono::seconds{1}};
   return forge::chrono::iso8601::format(instant) == "1970-01-01T00:00:01" ? 0 : 1;
}
