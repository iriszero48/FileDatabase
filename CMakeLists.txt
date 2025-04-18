cmake_minimum_required(VERSION 3.5)
project(file_database VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)

find_package(efsw CONFIG REQUIRED)
find_package(libpqxx CONFIG)

find_package(PkgConfig REQUIRED)

set(FD_LIBS Threads::Threads efsw::efsw)
set(FD_DEFS )

if (libpqxx_FOUND)
    list(APPEND FD_LIBS libpqxx::pqxx)
else()
    pkg_check_modules(libpqxx REQUIRED IMPORTED_TARGET libpqxx)
    list(APPEND FD_LIBS PkgConfig::libpqxx)
endif()

if(MSVC)
    list(APPEND FD_DEFS UNICODE _UNICODE)
else()
    list(APPEND FD_DEFS CU_UTILITY_USE_BOOST_STACKTRACE)
endif()

file(GLOB_RECURSE CU_FILES "CppUtility/*.h" "CppUtility/*.hpp")

add_executable(file_database main.cpp)

target_include_directories(file_database PRIVATE "CppUtility")
target_link_libraries(file_database PRIVATE ${FD_LIBS})
target_compile_definitions(file_database PRIVATE ${FD_DEFS})