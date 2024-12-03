# (C) Copyright IBM Deutschland GmbH 2021, 2024
# (C) Copyright IBM Corp. 2021, 2024
#
# non-exclusively licensed to gematik GmbH

########################################################################################################################

# enable testing only if the build was configured with tests
#
if (BUILD_TESTS)
    enable_testing()
endif()

########################################################################################################################

# set the general supported/required compiler features (like C & C++ standard versions, etc)
#
set_general_compile_features()

# fetch the dependencies' build infos via Conan
#
setup_conan()

# enable static code analysis via clang-tidy
#
setup_clang_tidy()

########################################################################################################################

# private function that checks that a target actually exists (has previously been configured)
#
function (_private_check_target_exists TARGET_NAME)
    if (NOT TARGET ${TARGET_NAME})
        message(FATAL_ERROR "Unable to find target `${TARGET_NAME}`. Has it been configured?")
    endif()
endfunction()

########################################################################################################################

# private function that checks that a list of source files is well formed
#
function (_private_check_target_source_files TARGET_NAME SOURCE_FILES)
    if (NOT SOURCE_FILES)
        message(FATAL_ERROR "Target '${TARGET_NAME}' cannot be configured without any source files.'")
    endif()

    list(LENGTH SOURCE_FILES SOURCE_FILES_COUNT)
    if (SOURCE_FILES_COUNT LESS 1)
        message(FATAL_ERROR "Target '${TARGET_NAME}' cannot be configured without any source files.'")
    endif()
endfunction()

########################################################################################################################

# private function that given a target name applies the corresponding compilation and linking flags in order to build it
#
function (_private_apply_build_options_to_target TARGET_NAME)
    get_compile_definitions(COMPILE_DEFINITIONS_RESULT)
    target_compile_definitions(${TARGET_NAME} PRIVATE ${COMPILE_DEFINITIONS_RESULT})

    get_compile_options(COMPILE_OPTIONS_RESULT)
    target_compile_options(${TARGET_NAME} PRIVATE ${COMPILE_OPTIONS_RESULT})

    get_include_directories(INCLUDE_DIRECTORIES_RESULT)
    target_include_directories(${TARGET_NAME} PRIVATE ${INCLUDE_DIRECTORIES_RESULT})

    get_link_options(LINK_OPTIONS_RESULT)
    target_link_options(${TARGET_NAME} PRIVATE ${LINK_OPTIONS_RESULT})

    get_libraries_to_link_against(LIBRARIES_RESULT)
    target_link_libraries(${TARGET_NAME} PRIVATE ${LIBRARIES_RESULT})
endfunction()

########################################################################################################################

# function that defines a new test target (given its name,
# a list of other targets that it tests and therefore depends on and the
# list of its own source files) and configures it with all the necessary flags for building
#
function (configure_test_target TARGET_NAME TARGETS_UNDER_TEST SOURCE_FILES)
    if (NOT BUILD_TESTS)
        return()
    endif()

    _private_check_target_source_files(${TARGET_NAME} "${SOURCE_FILES}")

    add_executable(${TARGET_NAME} ${SOURCE_FILES})

    add_test(NAME ${TARGET_NAME} COMMAND ${TARGET_NAME} WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

    _private_apply_build_options_to_target(${TARGET_NAME})

    get_test_libraries_to_link_against(TEST_LIBRARIES_RESULT)

    target_link_libraries(${TARGET_NAME} PRIVATE ${TEST_LIBRARIES_RESULT} ${TARGETS_UNDER_TEST})
endfunction()

########################################################################################################################

# function that defines a new target (given its name,
# type [EXECUTABLE, STATIC_LIBRARY, SHARED_LIBRARY, OBJECT_LIBRARY] and list of
# source files) and configures it with all the necessary flags for building
#
function (configure_target TARGET_NAME TARGET_TYPE SOURCE_FILES)
    _private_check_target_source_files(${TARGET_NAME} "${SOURCE_FILES}")

    if (TARGET_TYPE STREQUAL "EXECUTABLE")
        message(FATAL_ERROR "Executable targets not yet supported.")
    endif()

    if (TARGET_TYPE STREQUAL "SHARED_LIBRARY")
        set(LIBRARY_TARGET_TYPE SHARED)
    elseif (TARGET_TYPE STREQUAL "STATIC_LIBRARY")
        set(LIBRARY_TARGET_TYPE STATIC)
    elseif (TARGET_TYPE STREQUAL "OBJECT_LIBRARY")
        set(LIBRARY_TARGET_TYPE OBJECT)
    else()
        message(FATAL_ERROR "Target '${TARGET_NAME}' does not have a known "
                            "type (EXECUTABLE, SHARED_LIBRARY, STATIC_LIBRARY, OBJECT_LIBRARY)")
    endif()

    add_library(${TARGET_NAME} ${LIBRARY_TARGET_TYPE} ${SOURCE_FILES})

    _private_apply_build_options_to_target(${TARGET_NAME})

    if (TARGET_TYPE STREQUAL "SHARED_LIBRARY" AND CMAKE_SYSTEM_NAME STREQUAL "Windows")
        set_target_properties(${TARGET_NAME} PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS TRUE)
    endif()
endfunction()

########################################################################################################################
