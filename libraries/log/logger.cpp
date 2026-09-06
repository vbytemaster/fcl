module;
#include <memory>
#include <iostream>
#include <algorithm>
#include <chrono>
#include <mutex>
#include <source_location>
#include <string>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <vector>

module forge.log.logger;

import forge.log.log_message;
import forge.log.appender;
import forge.log.record;
import forge.log.logger_config;
import forge.core.utility;

namespace forge {

namespace {

std::string current_thread_id() {
   auto out = std::ostringstream{};
   out << std::this_thread::get_id();
   return out.str();
}

log_record make_record_from_message(const log_message& message, const std::string& logger_name) {
   auto context = message.get_context();
   auto fields = log_fields{};
   auto data = message.get_data();
   fields.reserve(data.size());
   for (const auto& entry : data) {
      try {
         fields.push_back(log_ctx(entry.key(), entry.value().as_string()));
      } catch (...) {
         fields.push_back(log_ctx(entry.key(), std::string{"<unprintable>"}));
      }
   }

   auto record = log_record{
       .level = context.get_log_level(),
       .logger = logger_name,
       .message = message.get_limited_message(),
       .fields = std::move(fields),
       .timestamp = context.get_timestamp(),
       .thread_id = current_thread_id(),
       .thread_name = context.get_thread_name(),
   };
   if (static_cast<int>(record.level) >= static_cast<int>(log_level::error)) {
      record.stacktrace = capture_stacktrace(1);
   }
   return record;
}

} // namespace

static void ensure_default_logging_configured() {
   static const bool configured = configure_logging(logging_config::default_config());
   (void)configured;
}

class logger::impl {
 public:
   impl() : _parent(nullptr), _enabled(true), _level(log_level::warn) {}
   std::string _name;
   logger _parent;
   bool _enabled;
   log_level _level;

   std::vector<appender::ptr> _appenders;
   std::vector<std::shared_ptr<sink>> _sinks;
};

logger::logger() : my(new impl()) {}

logger::logger(nullptr_t) {}

logger::logger(const std::string& name, const logger& parent) : my(new impl()) {
   my->_name = name;
   my->_parent = parent;
}

logger::logger(const logger& l) : my(l.my) {}

logger::logger(logger&& l) noexcept : my(std::move(l.my)) {}

logger::~logger() {}

logger& logger::operator=(const logger& l) {
   my = l.my;
   return *this;
}
logger& logger::operator=(logger&& l) noexcept {
   forge_swap(my, l.my);
   return *this;
}
bool operator==(const logger& l, std::nullptr_t) {
   return !l.my;
}
bool operator!=(const logger& l, std::nullptr_t) {
   return !!l.my;
}

void logger::set_enabled(bool e) {
   my->_enabled = e;
}
bool logger::is_enabled() const {
   return my->_enabled;
}
bool logger::is_enabled(log_level e) const {
   return my->_enabled && e >= my->_level;
}

void logger::log(log_message m) {
   std::unique_lock g(log_config::get().log_mutex);
   m.get_context().append_context(my->_name);
   const auto has_local_appenders = !my->_appenders.empty();
   const auto has_local_sinks = !my->_sinks.empty();

   if (has_local_appenders) {
      for (auto itr = my->_appenders.begin(); itr != my->_appenders.end(); ++itr) {
         try {
            (*itr)->log(m);
         } catch (const std::exception& e) {
            std::cerr << "ERROR: logger::log std::exception: " << e.what() << std::endl;
         } catch (...) {
            std::cerr << "ERROR: logger::log unknown exception: " << std::endl;
         }
      }
   }

   if (has_local_sinks) {
      auto record = make_record_from_message(m, my->_name);
      const auto sinks = my->_sinks;
      g.unlock();
      for (const auto& current_sink : sinks) {
         try {
            current_sink->log(record);
         } catch (const std::exception& e) {
            std::cerr << "ERROR: logger::log sink std::exception: " << e.what() << std::endl;
         } catch (...) {
            std::cerr << "ERROR: logger::log sink unknown exception" << std::endl;
         }
      }
   } else if (!has_local_appenders && my->_parent != nullptr) {
      logger parent = my->_parent;
      g.unlock();
      parent.log(m);
   }
}

void logger::log(log_record record) {
   std::unique_lock g(log_config::get().log_mutex);
   record.logger = my->_name;

   if (!my->_sinks.empty()) {
      const auto sinks = my->_sinks;
      g.unlock();
      for (const auto& current_sink : sinks) {
         try {
            current_sink->log(record);
         } catch (const std::exception& e) {
            std::cerr << "ERROR: logger::log sink std::exception: " << e.what() << std::endl;
         } catch (...) {
            std::cerr << "ERROR: logger::log sink unknown exception" << std::endl;
         }
      }
   } else if (my->_parent != nullptr) {
      logger parent = my->_parent;
      g.unlock();
      parent.log(std::move(record));
   }
}

void logger::log(log_level level, std::string message, log_fields fields, std::source_location location) {
   if (!is_enabled(level)) {
      return;
   }

   auto record = log_record{
       .level = level,
       .message = std::move(message),
       .fields = std::move(fields),
       .timestamp = std::chrono::time_point_cast<std::chrono::microseconds>(std::chrono::system_clock::now()),
       .thread_id = current_thread_id(),
       .thread_name = forge::get_thread_name(),
       .location = location,
   };
   if (static_cast<int>(level) >= static_cast<int>(log_level::error)) {
      record.stacktrace = capture_stacktrace(1);
   }
   log(std::move(record));
}

void logger::debug(std::string message, log_fields fields, std::source_location location) {
   log(log_level::debug, std::move(message), std::move(fields), location);
}

void logger::info(std::string message, log_fields fields, std::source_location location) {
   log(log_level::info, std::move(message), std::move(fields), location);
}

void logger::warn(std::string message, log_fields fields, std::source_location location) {
   log(log_level::warn, std::move(message), std::move(fields), location);
}

void logger::error(std::string message, log_fields fields, std::source_location location) {
   log(log_level::error, std::move(message), std::move(fields), location);
}

void logger::set_name(const std::string& n) {
   my->_name = n;
}
std::string logger::get_name() const {
   return my->_name;
}

logger logger::get(const std::string& s) {
   ensure_default_logging_configured();
   return log_config::get_logger(s);
}

logger& logger::default_logger() {
   static logger* the_default_logger = new logger;
   return *the_default_logger;
}

void logger::update(const std::string& name, logger& log) {
   log_config::update_logger(name, log);
}

logger logger::get_parent() const {
   return my->_parent;
}
logger& logger::set_parent(const logger& p) {
   my->_parent = p;
   return *this;
}

log_level logger::get_log_level() const {
   return my->_level;
}
logger& logger::set_log_level(log_level ll) {
   my->_level = ll;
   return *this;
}

void logger::add_appender(const std::shared_ptr<appender>& a) {
   my->_appenders.push_back(a);
}

void logger::add_sink(std::shared_ptr<sink> sink) {
   if (!sink) {
      throw std::invalid_argument{"cannot add null log sink"};
   }
   std::lock_guard g(log_config::get().log_mutex);
   my->_sinks.push_back(std::move(sink));
}

void logger::remove_sink(const std::shared_ptr<sink>& sink) {
   if (!sink) {
      return;
   }
   std::lock_guard g(log_config::get().log_mutex);
   my->_sinks.erase(std::remove(my->_sinks.begin(), my->_sinks.end(), sink), my->_sinks.end());
}

} // namespace forge
