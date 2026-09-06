#include <boost/test/unit_test.hpp>

#include <chrono>
#include <stdexcept>

import forge.chrono.iso8601;
import forge.chrono.relative;

BOOST_AUTO_TEST_SUITE(chrono_test_suite)

BOOST_AUTO_TEST_CASE(legacy_iso_roundtrip) {
   const auto one_second = std::chrono::sys_seconds{std::chrono::seconds{1}};
   BOOST_CHECK_EQUAL(forge::chrono::iso8601::format(one_second), "1970-01-01T00:00:01");
   BOOST_CHECK_EQUAL(forge::chrono::iso8601::format_compact(one_second), "19700101T000001");
   BOOST_CHECK(forge::chrono::iso8601::parse_seconds("1970-01-01T00:00:01") == one_second);
   BOOST_CHECK(forge::chrono::iso8601::parse_seconds("19700101T000001") == one_second);

   const auto one_second_us = std::chrono::sys_time<std::chrono::microseconds>{std::chrono::seconds{1}};
   BOOST_CHECK_EQUAL(forge::chrono::iso8601::format(one_second_us), "1970-01-01T00:00:01.000");
   BOOST_CHECK(forge::chrono::iso8601::parse_microseconds("1970-01-01T00:00:01.000") == one_second_us);

   const auto precise = one_second_us + std::chrono::microseconds{123'456};
   BOOST_CHECK_EQUAL(forge::chrono::iso8601::format(precise), "1970-01-01T00:00:01.123456");
   BOOST_CHECK(forge::chrono::iso8601::parse_microseconds("1970-01-01T00:00:01.123456") == precise);
}

BOOST_AUTO_TEST_CASE(legacy_iso_rejects_invalid_input) {
   BOOST_CHECK_THROW(static_cast<void>(forge::chrono::iso8601::parse_seconds("not-a-time")), std::invalid_argument);
   BOOST_CHECK_THROW(static_cast<void>(forge::chrono::iso8601::parse_microseconds("not-a-time")),
                     std::invalid_argument);
   BOOST_CHECK_THROW(static_cast<void>(forge::chrono::iso8601::parse_microseconds("1970-01-01T00:00:01.1234567")),
                     std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(iso_seconds_do_not_inherit_fc_wire_bounds) {
   const auto before_epoch = std::chrono::sys_seconds{std::chrono::seconds{-1}};
   BOOST_CHECK_EQUAL(forge::chrono::iso8601::format(before_epoch), "1969-12-31T23:59:59");
   BOOST_CHECK(forge::chrono::iso8601::parse_seconds("1969-12-31T23:59:59") == before_epoch);

   const auto before_epoch_us = std::chrono::sys_time<std::chrono::microseconds>{std::chrono::microseconds{-500'000}};
   BOOST_CHECK_EQUAL(forge::chrono::iso8601::format(before_epoch_us), "1969-12-31T23:59:59.500");
   BOOST_CHECK(forge::chrono::iso8601::parse_microseconds("1969-12-31T23:59:59.500") == before_epoch_us);

   const auto after_fc_range = std::chrono::sys_seconds{std::chrono::seconds{4'294'967'296LL}};
   BOOST_CHECK(forge::chrono::iso8601::parse_seconds("2106-02-07T06:28:16") == after_fc_range);
}

BOOST_AUTO_TEST_CASE(rfc3339_preserves_nanoseconds_and_normalizes_offsets) {
   const auto instant =
       std::chrono::sys_time<std::chrono::nanoseconds>{std::chrono::seconds{1} + std::chrono::nanoseconds{120'340'500}};
   BOOST_CHECK_EQUAL(forge::chrono::iso8601::format_rfc3339(instant), "1970-01-01T00:00:01.1203405Z");
   BOOST_CHECK(forge::chrono::iso8601::parse_rfc3339("1970-01-01T01:30:01.120340500+01:30") == instant);
}

BOOST_AUTO_TEST_CASE(rfc3339_rejects_invalid_or_lossy_input) {
   BOOST_CHECK_THROW(static_cast<void>(forge::chrono::iso8601::parse_rfc3339("1970-02-30T00:00:00Z")),
                     std::invalid_argument);
   BOOST_CHECK_THROW(static_cast<void>(forge::chrono::iso8601::parse_rfc3339("1970-01-01T00:00:00.1234567890Z")),
                     std::invalid_argument);
   BOOST_CHECK_THROW(static_cast<void>(forge::chrono::iso8601::parse_rfc3339("1970-01-01T00:00:00Ztrailing")),
                     std::invalid_argument);
   BOOST_CHECK_THROW(static_cast<void>(forge::chrono::iso8601::parse_rfc3339("1970-01-01T00:00:00+24:00")),
                     std::invalid_argument);
   BOOST_CHECK_THROW(static_cast<void>(forge::chrono::iso8601::parse_rfc3339("9999-01-01T00:00:00Z")),
                     std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(relative_format_retains_suffix_and_future_behavior) {
   const auto epoch = std::chrono::sys_seconds{};
   BOOST_CHECK_EQUAL(forge::chrono::relative::format(epoch, epoch + std::chrono::seconds{1}), "1 second ago");
   BOOST_CHECK_EQUAL(forge::chrono::relative::format(epoch, epoch + std::chrono::seconds{2}, " since start"),
                     "2 seconds since start");
   BOOST_CHECK_EQUAL(forge::chrono::relative::format(epoch + std::chrono::seconds{2}, epoch, " ignored"),
                     "2 seconds in the future");

   const auto epoch_us = std::chrono::sys_time<std::chrono::microseconds>{};
   BOOST_CHECK_EQUAL(forge::chrono::relative::format(epoch_us, epoch_us + std::chrono::seconds{1}), "1 second ago");
}

BOOST_AUTO_TEST_SUITE_END()
