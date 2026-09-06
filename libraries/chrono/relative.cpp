module;
#include <chrono>
#include <cstdint>
#include <sstream>
#include <string>
#include <string_view>

module forge.chrono.relative;

namespace forge::chrono::relative {

std::string format(std::chrono::sys_seconds event_time, std::chrono::sys_seconds relative_to_time,
                   std::string_view suffix) {
   auto result_suffix = std::string{suffix};
   auto seconds_ago = static_cast<std::int64_t>((relative_to_time - event_time).count());
   if (seconds_ago < 0) {
      result_suffix = " in the future";
      seconds_ago = -seconds_ago;
   }

   auto result = std::ostringstream{};
   if (seconds_ago < 90) {
      result << seconds_ago << " second" << (seconds_ago > 1 ? "s" : "") << result_suffix;
      return result.str();
   }

   const auto minutes_ago = static_cast<std::uint32_t>((seconds_ago + 30) / 60);
   if (minutes_ago < 90) {
      result << minutes_ago << " minute" << (minutes_ago > 1 ? "s" : "") << result_suffix;
      return result.str();
   }

   const auto hours_ago = (minutes_ago + 30) / 60;
   if (hours_ago < 90) {
      result << hours_ago << " hour" << (hours_ago > 1 ? "s" : "") << result_suffix;
      return result.str();
   }

   const auto days_ago = (hours_ago + 12) / 24;
   if (days_ago < 90) {
      result << days_ago << " day" << (days_ago > 1 ? "s" : "") << result_suffix;
      return result.str();
   }

   const auto weeks_ago = (days_ago + 3) / 7;
   if (weeks_ago < 70) {
      result << weeks_ago << " week" << (weeks_ago > 1 ? "s" : "") << result_suffix;
      return result.str();
   }

   const auto months_ago = (days_ago + 15) / 30;
   if (months_ago < 12) {
      result << months_ago << " month" << (months_ago > 1 ? "s" : "") << result_suffix;
      return result.str();
   }

   const auto years_ago = days_ago / 365;
   result << years_ago << " year" << (months_ago > 1 ? "s" : "");
   if (months_ago < 12 * 5) {
      const auto leftover_days = days_ago - (years_ago * 365);
      const auto leftover_months = (leftover_days + 15) / 30;
      if (leftover_months) {
         result << leftover_months << " month" << (months_ago > 1 ? "s" : "");
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
