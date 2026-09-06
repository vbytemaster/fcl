module;

#if FORGE_HAS_STD_STACKTRACE
#include <stacktrace>
#elif FORGE_HAS_BOOST_STACKTRACE
#include <boost/stacktrace.hpp>
#endif

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>

module forge.log.record;

import forge.chrono.iso8601;
import forge.core.string;
import forge.log.exceptions;
import forge.log.log_message;

namespace {

std::string sanitize_value(std::string value, bool redacted) {
   if (redacted) {
      return "<redacted>";
   }
   return value;
}

void write_json_string(std::ostream& out, std::string_view value) {
   auto escaped = std::string{value};
   forge::escape_str(escaped, forge::escape_control_chars::on);
   out << '"' << escaped << '"';
}

class locked_file {
 public:
   locked_file(std::filesystem::path path, bool append) {
      auto mode = std::ios::out;
      if (append) {
         mode |= std::ios::app;
      } else {
         mode |= std::ios::trunc;
      }
      stream.open(path, mode);
      if (!stream) {
         throw forge::log::exceptions::io_error{"failed to open log file: " + path.generic_string()};
      }
   }

   std::mutex mutex;
   std::ofstream stream;
};

} // namespace

namespace forge {

log_field log_ctx(std::string_view key, std::string value) {
   return log_field{std::string(key), std::move(value), false};
}
log_field log_ctx(std::string_view key, std::string_view value) {
   return log_ctx(key, std::string(value));
}
log_field log_ctx(std::string_view key, const char* value) {
   return log_ctx(key, value ? std::string(value) : std::string{"<null>"});
}
log_field log_ctx(std::string_view key, bool value) {
   return log_ctx(key, value ? "true" : "false");
}
log_field log_ctx(std::string_view key, char value) {
   return log_ctx(key, std::string(1, value));
}
log_field log_ctx(std::string_view key, signed char value) {
   return log_ctx(key, static_cast<long long>(value));
}
log_field log_ctx(std::string_view key, unsigned char value) {
   return log_ctx(key, static_cast<unsigned long long>(value));
}
log_field log_ctx(std::string_view key, short value) {
   return log_ctx(key, static_cast<long long>(value));
}
log_field log_ctx(std::string_view key, unsigned short value) {
   return log_ctx(key, static_cast<unsigned long long>(value));
}
log_field log_ctx(std::string_view key, int value) {
   return log_ctx(key, static_cast<long long>(value));
}
log_field log_ctx(std::string_view key, unsigned value) {
   return log_ctx(key, static_cast<unsigned long long>(value));
}
log_field log_ctx(std::string_view key, long value) {
   return log_ctx(key, static_cast<long long>(value));
}
log_field log_ctx(std::string_view key, unsigned long value) {
   return log_ctx(key, static_cast<unsigned long long>(value));
}
log_field log_ctx(std::string_view key, long long value) {
   return log_ctx(key, std::to_string(value));
}
log_field log_ctx(std::string_view key, unsigned long long value) {
   return log_ctx(key, std::to_string(value));
}
log_field log_ctx(std::string_view key, float value) {
   return log_ctx(key, std::to_string(value));
}
log_field log_ctx(std::string_view key, double value) {
   return log_ctx(key, std::to_string(value));
}
log_field log_ctx(std::string_view key, long double value) {
   return log_ctx(key, std::to_string(static_cast<double>(value)));
}

log_field log_secret(std::string_view key, std::string value) {
   static_cast<void>(value);
   return log_field{std::string(key), "<redacted>", true};
}
log_field log_secret(std::string_view key, std::string_view value) {
   return log_secret(key, std::string(value));
}
log_field log_secret(std::string_view key, const char* value) {
   return log_secret(key, value ? std::string(value) : std::string{});
}

void append_log_field(log_fields& fields, log_field field) {
   if (!field.key.empty()) {
      field.value = sanitize_value(std::move(field.value), field.redacted);
      fields.push_back(std::move(field));
   }
}

void append_log_field(log_fields& fields, const log_field_provider& provider) {
   if (provider.provider) {
      append_log_field(fields, provider.provider());
   }
}

stacktrace_snapshot capture_stacktrace(std::size_t skip, std::size_t max_frames) {
   auto result = stacktrace_snapshot{};
#if FORGE_HAS_STD_STACKTRACE
   result.backend = "std::stacktrace";
   const auto trace = std::stacktrace::current(skip + 1, max_frames);
   result.frames.reserve(trace.size());
   for (std::size_t index = 0; index < trace.size(); ++index) {
      const auto& frame = trace[index];
      result.frames.push_back(stacktrace_frame{
          .index = index,
          .address = reinterpret_cast<std::uintptr_t>(frame.native_handle()),
          .name = frame.description(),
          .source_file = frame.source_file(),
          .source_line = frame.source_line(),
      });
   }
#elif FORGE_HAS_BOOST_STACKTRACE
   result.backend = "boost::stacktrace";
   const auto trace = boost::stacktrace::stacktrace(skip + 1, max_frames);
   result.frames.reserve(trace.size());
   for (std::size_t index = 0; index < trace.size(); ++index) {
      const auto& frame = trace[index];
      result.frames.push_back(stacktrace_frame{
          .index = index,
          .address = reinterpret_cast<std::uintptr_t>(frame.address()),
          .name = frame.name(),
          .source_file = frame.source_file(),
          .source_line = static_cast<std::uint64_t>(frame.source_line()),
      });
   }
#else
   static_cast<void>(skip);
   static_cast<void>(max_frames);
   result.backend = "none";
   result.unavailable_reason = "stacktrace_unavailable";
#endif
   if (result.frames.empty() && result.unavailable_reason.empty()) {
      result.unavailable_reason = "stacktrace_unavailable";
   }
   return result;
}

std::string format_stacktrace(const stacktrace_snapshot& stacktrace) {
   if (!stacktrace.available()) {
      return stacktrace.unavailable_reason.empty() ? "stacktrace_unavailable" : stacktrace.unavailable_reason;
   }

   auto out = std::ostringstream{};
   out << stacktrace.backend;
   for (const auto& frame : stacktrace.frames) {
      out << "\n#" << frame.index << ' ';
      if (!frame.name.empty()) {
         out << frame.name;
      } else {
         out << "0x" << std::hex << frame.address << std::dec;
      }
      if (!frame.source_file.empty()) {
         out << " at " << frame.source_file << ':' << frame.source_line;
      }
   }
   return out.str();
}

std::string format_text_log_record(const log_record& record) {
   auto out = std::ostringstream{};
   out << '[' << forge::chrono::iso8601::format(record.timestamp) << "] ";
   out << record.level.to_string() << ' ';
   if (!record.logger.empty()) {
      out << record.logger << ' ';
   }
   if (!record.component.empty()) {
      out << record.component << ' ';
   }
   out << record.message;
   for (const auto& field : record.fields) {
      out << ' ' << field.key << '=' << sanitize_value(field.value, field.redacted);
   }
   if (!record.exception_chain.empty()) {
      out << " exception=" << record.exception_chain;
   }
   if (record.stacktrace) {
      out << "\n" << format_stacktrace(*record.stacktrace);
   }
   return out.str();
}

std::string format_json_log_record(const log_record& record) {
   auto out = std::ostringstream{};
   out << '{';
   out << "\"timestamp\":";
   write_json_string(out, forge::chrono::iso8601::format(record.timestamp));
   out << ",\"level\":";
   write_json_string(out, record.level.to_string());
   out << ",\"logger\":";
   write_json_string(out, record.logger);
   out << ",\"component\":";
   write_json_string(out, record.component);
   out << ",\"message\":";
   write_json_string(out, record.message);
   out << ",\"thread_id\":";
   write_json_string(out, record.thread_id);
   out << ",\"thread\":";
   write_json_string(out, record.thread_name);
   out << ",\"file\":";
   write_json_string(out, record.location.file_name());
   out << ",\"line\":" << record.location.line();
   out << ",\"fields\":{";
   for (std::size_t index = 0; index < record.fields.size(); ++index) {
      if (index != 0) {
         out << ',';
      }
      write_json_string(out, record.fields[index].key);
      out << ':';
      write_json_string(out, sanitize_value(record.fields[index].value, record.fields[index].redacted));
   }
   out << '}';
   if (!record.exception_chain.empty()) {
      out << ",\"exception\":";
      write_json_string(out, record.exception_chain);
   }
   if (record.stacktrace) {
      out << ",\"stacktrace\":{\"backend\":";
      write_json_string(out, record.stacktrace->backend);
      out << ",\"available\":" << (record.stacktrace->available() ? "true" : "false");
      if (!record.stacktrace->unavailable_reason.empty()) {
         out << ",\"reason\":";
         write_json_string(out, record.stacktrace->unavailable_reason);
      }
      out << ",\"frames\":[";
      for (std::size_t index = 0; index < record.stacktrace->frames.size(); ++index) {
         const auto& frame = record.stacktrace->frames[index];
         if (index != 0) {
            out << ',';
         }
         out << "{\"index\":" << frame.index << ",\"name\":";
         write_json_string(out, frame.name);
         out << ",\"file\":";
         write_json_string(out, frame.source_file);
         out << ",\"line\":" << frame.source_line << '}';
      }
      out << "]}";
   }
   out << '}';
   return out.str();
}

console_sink::console_sink(bool stderr_for_warnings) : stderr_for_warnings_(stderr_for_warnings) {}
console_sink::~console_sink() = default;

void console_sink::log(const log_record& record) {
   auto& out = stderr_for_warnings_ && static_cast<int>(record.level) >= static_cast<int>(log_level::warn) ? std::cerr
                                                                                                           : std::cout;
   out << format_text_log_record(record) << '\n';
}

class file_sink::impl : public locked_file {
 public:
   impl(std::filesystem::path path, bool append) : locked_file(std::move(path), append) {}
};

file_sink::file_sink(std::filesystem::path path, bool append)
    : impl_(std::make_unique<impl>(std::move(path), append)) {}
file_sink::~file_sink() = default;

void file_sink::log(const log_record& record) {
   const auto lock = std::scoped_lock{impl_->mutex};
   impl_->stream << format_text_log_record(record) << '\n';
   impl_->stream.flush();
}

class jsonl_sink::impl : public locked_file {
 public:
   impl(std::filesystem::path path, bool append) : locked_file(std::move(path), append) {}
};

jsonl_sink::jsonl_sink(std::filesystem::path path, bool append)
    : impl_(std::make_unique<impl>(std::move(path), append)) {}
jsonl_sink::~jsonl_sink() = default;

void jsonl_sink::log(const log_record& record) {
   const auto lock = std::scoped_lock{impl_->mutex};
   impl_->stream << format_json_log_record(record) << '\n';
   impl_->stream.flush();
}

} // namespace forge
