module;
#include <chrono>
#include <string>
#include <string_view>

export module forge.chrono.relative;

export namespace forge::chrono::relative {

[[nodiscard]] std::string format(std::chrono::sys_seconds event_time, std::chrono::sys_seconds relative_to_time,
                                 std::string_view suffix = " ago");
[[nodiscard]] std::string format(std::chrono::sys_time<std::chrono::microseconds> event_time,
                                 std::chrono::sys_time<std::chrono::microseconds> relative_to_time,
                                 std::string_view suffix = " ago");

} // namespace forge::chrono::relative
