# prerequisite: specify a recent CMake version
#
cmake_minimum_required(VERSION "3.16")

########################################################################################################################

# define the project name and languages
#
set(PROJECT_NAME "hsm-client")

project(${PROJECT_NAME} LANGUAGES C CXX)

########################################################################################################################

# prerequisite: make sure the platform is either Linux or Windows
#
if (NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
    message(FATAL_ERROR "`${PROJECT_NAME}` builds only on Linux and Windows.")
endif()

########################################################################################################################

# set several variables with the paths of various locations needed by the build system
#
set(ROOT_DIRECTORY ${CMAKE_SOURCE_DIR})
set(CMAKE_DIRECTORY ${ROOT_DIRECTORY}/cmake)
set(SOURCE_DIRECTORY ${ROOT_DIRECTORY}/src)
set(TEST_DIRECTORY ${ROOT_DIRECTORY}/test)
set(TEST_RESOURCES_DIRECTORY ${TEST_DIRECTORY}/resources)
set(BUILD_DIRECTORY ${CMAKE_BINARY_DIR})
set(BUILD_BIN_DIRECTORY ${BUILD_DIRECTORY}/bin)
set(BUILD_LIB_DIRECTORY ${BUILD_DIRECTORY}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${BUILD_LIB_DIRECTORY})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${BUILD_LIB_DIRECTORY})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BUILD_BIN_DIRECTORY})

########################################################################################################################

# include the relevant helper CMake scripts
#
include(${CMAKE_DIRECTORY}/Asn.cmake)
include(${CMAKE_DIRECTORY}/BuildOptions.cmake)
include(${CMAKE_DIRECTORY}/ClangTidy.cmake)
include(${CMAKE_DIRECTORY}/Conan.cmake)
include(${CMAKE_DIRECTORY}/Dependencies.cmake)
include(${CMAKE_DIRECTORY}/Installation.cmake)
include(${CMAKE_DIRECTORY}/TargetConfiguration.cmake)

########################################################################################################################

# continue processing other CMakeLists files
#
add_subdirectory(${SOURCE_DIRECTORY})
add_subdirectory(${TEST_DIRECTORY})

########################################################################################################################
