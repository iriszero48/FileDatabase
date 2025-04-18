cmake_minimum_required(VERSION 3.5)
project(file_database VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(efsw CONFIG REQUIRED)
find_package(libpqxx CONFIG REQUIRED)

if(MSVC)
    list(APPEND IvDefinitions UNICODE _UNICODE)
endif()

file(GLOB_RECURSE CU_FILES "CppUtility/*.h" "CppUtility/*.hpp")

add_executable(file_database main.cpp)

target_include_directories(file_database PRIVATE "CppUtility")
target_link_libraries(file_database PRIVATE efsw::efsw libpqxx::pqxx)
