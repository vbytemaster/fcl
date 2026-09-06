#include <cstdint>

import forge.core.string;

int main()
{
   return forge::to_uint64("1") == std::uint64_t{1} ? 0 : 1;
}
