# (C) Copyright IBM Deutschland GmbH 2021, 2024
# (C) Copyright IBM Corp. 2021, 2024
#
# non-exclusively licensed to gematik GmbH

########################################################################################################################

# prerequisite: specify a recent CMake version
#
cmake_minimum_required(VERSION "3.18")

########################################################################################################################

# define the project name and languages
#
set(PROJECT_NAME "hsm-client")

project(${PROJECT_NAME} LANGUAGES C CXX)

option(BUILD_TESTING "Build testing" ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
########################################################################################################################

# prerequisite: make sure the platform is either Linux or Windows
#
if (NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
    message(FATAL_ERROR "`${PROJECT_NAME}` builds only on Linux and Windows.")
endif()

########################################################################################################################

# set several variables with the paths of various locations needed by the build system
#
set(SOURCE_DIRECTORY src)
set(TEST_RESOURCES_DIRECTORY ${CMAKE_SOURCE_DIR}/test/resources)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

########################################################################################################################

# include the relevant helper CMake scripts
#
include(cmake/BuildOptions.cmake)
include(cmake/ClangTidy.cmake)
include(cmake/Dependencies.cmake)
include(cmake/Asn.cmake)
include(cmake/Installation.cmake)
include(cmake/TargetConfiguration.cmake)

########################################################################################################################

# continue processing other CMakeLists files
#

add_subdirectory(src)

if (BUILD_TESTING)
  enable_testing()
  add_subdirectory(test)
endif()

########################################################################################################################
