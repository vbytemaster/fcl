module;
#include <chrono>
#include <cstdint>
#include <sstream>
#include <string>
#include <string_view>

module forge.chrono.relative;

namespace forge::chrono::relative {
namespace {

[[nodiscard]] constexpr std::uint64_t distance(std::int64_t later, std::int64_t earlier) noexcept {
   return static_cast<std::uint64_t>(later) - static_cast<std::uint64_t>(earlier);
}

[[nodiscard]] constexpr std::uint64_t rounded_divide(std::uint64_t value, std::uint64_t divisor) noexcept {
   return (value / divisor) + ((value % divisor) >= ((divisor + 1) / 2) ? 1 : 0);
}

} // namespace

std::string format(std::chrono::sys_seconds event_time, std::chrono::sys_seconds relative_to_time,
                   std::string_view suffix) {
   auto result_suffix = std::string{suffix};
   const auto event_seconds = event_time.time_since_epoch().count();
   const auto relative_seconds = relative_to_time.time_since_epoch().count();
   const auto future = event_seconds > relative_seconds;
   const auto seconds_ago =
       future ? distance(event_seconds, relative_seconds) : distance(relative_seconds, event_seconds);
   if (future) {
      result_suffix = " in the future";
   }

   auto result = std::ostringstream{};
   if (seconds_ago < 90) {
      result << seconds_ago << " second" << (seconds_ago > 1 ? "s" : "") << result_suffix;
      return result.str();
   }

   const auto minutes_ago = rounded_divide(seconds_ago, 60);
   if (minutes_ago < 90) {
      result << minutes_ago << " minute" << (minutes_ago > 1 ? "s" : "") << result_suffix;
      return result.str();
   }

   const auto hours_ago = rounded_divide(minutes_ago, 60);
   if (hours_ago < 90) {
      result << hours_ago << " hour" << (hours_ago > 1 ? "s" : "") << result_suffix;
      return result.str();
   }

   const auto days_ago = rounded_divide(hours_ago, 24);
   if (days_ago < 90) {
      result << days_ago << " day" << (days_ago > 1 ? "s" : "") << result_suffix;
      return result.str();
   }

   const auto weeks_ago = rounded_divide(days_ago, 7);
   if (weeks_ago < 70) {
      result << weeks_ago << " week" << (weeks_ago > 1 ? "s" : "") << result_suffix;
      return result.str();
   }

   const auto months_ago = rounded_divide(days_ago, 30);
   if (months_ago < 12) {
      result << months_ago << " month" << (months_ago > 1 ? "s" : "") << result_suffix;
      return result.str();
   }

   const auto years_ago = days_ago / 365;
   result << years_ago << " year" << (years_ago > 1 ? "s" : "");
   if (months_ago < 12 * 5) {
      const auto leftover_days = days_ago - (years_ago * 365);
      const auto leftover_months = rounded_divide(leftover_days, 30);
      if (leftover_months) {
         result << " " << leftover_months << " month" << (leftover_months > 1 ? "s" : "");
      }
   }
   result << result_suffix;
   return result.str();
}

std::string format(std::chrono::sys_time<std::chrono::microseconds> event_time,
                   std::chrono::sys_time<std::chrono::microseconds> relative_to_time, std::string_view suffix) {
   return format(std::chrono::time_point_cast<std::chrono::seconds>(event_time),
                 std::chrono::time_point_cast<std::chrono::seconds>(relative_to_time), suffix);
}

} // namespace forge::chrono::relative
