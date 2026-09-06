file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/generated")
configure_file(
   "${CMAKE_CURRENT_SOURCE_DIR}/git_revision.cpp.in"
   "${CMAKE_CURRENT_BINARY_DIR}/generated/git_revision.cpp"
   @ONLY
)

add_library(
   forge_core STATIC
   string.cpp
   uint128.cpp
   utf8.cpp
   "${CMAKE_CURRENT_BINARY_DIR}/generated/git_revision.cpp"
)
forge_target_modules(forge_core core)

target_include_directories(
   forge_core
   PUBLIC ${FORGE_PUBLIC_INCLUDE_DIRS}
   PRIVATE "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/vendor/utf8cpp>"
)
target_link_libraries(
   forge_core PRIVATE
      Boost::headers
      Boost::multiprecision
)
target_compile_definitions(
   forge_core
   PUBLIC OPENSSL_API_COMPAT=0x30000000L
          OPENSSL_NO_DEPRECATED
)
