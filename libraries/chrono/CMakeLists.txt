add_library(
   forge_chrono STATIC
   iso8601.cpp
   relative.cpp
)
forge_target_modules(forge_chrono chrono)

target_include_directories(forge_chrono PUBLIC ${FORGE_PUBLIC_INCLUDE_DIRS})
target_link_libraries(forge_chrono PRIVATE Boost::date_time)
