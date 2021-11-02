# (C) Copyright IBM Deutschland GmbH 2021
# (C) Copyright IBM Corp. 2021
# SPDX-License-Identifier: CC BY-NC-ND 3.0 DE

########################################################################################################################

# private function that returns
# the compilation options specific for Linux
#
function (_private_get_linux_compile_options RESULT)
    set(${RESULT} -fPIC
                  -Werror
                  -Wall
                  -Wextra
                  -Wpedantic
                  -Wundef
                  -Wfloat-equal
                  -Winit-self
                  -Wshadow
                  -Wswitch-default
                  $<$<CONFIG:Debug>:-g>
                  $<$<CONFIG:Debug>:-ggdb>
                  $<$<CONFIG:Debug>:-O0>
                  $<$<CONFIG:Release>:-O2>
        PARENT_SCOPE)
endfunction()

########################################################################################################################

# private function that returns
# the compilation options specific for Windows
#
function (_private_get_windows_compile_options RESULT)
    set(${RESULT} /nologo
                  /W4
                  /WX
                  $<$<CONFIG:Debug>:/MDd>
                  $<$<CONFIG:Debug>:/RTC1>
                  $<$<CONFIG:Debug>:/Zi>
                  $<$<CONFIG:Debug>:/Od>
                  $<$<CONFIG:Debug>:/FS>
                  $<$<CONFIG:Release>:/MD>
                  $<$<CONFIG:Release>:/O2>
        PARENT_SCOPE)
endfunction()

########################################################################################################################

# function that sets the default CMake
# variables with general compilation features
#
function (set_general_compile_features)
    set(CMAKE_C_STANDARD 11 PARENT_SCOPE)
    set(CMAKE_C_STANDARD_REQUIRED ON PARENT_SCOPE)
    set(CMAKE_C_EXTENSIONS OFF PARENT_SCOPE)
    set(CMAKE_CXX_STANDARD 17 PARENT_SCOPE)
    set(CMAKE_CXX_STANDARD_REQUIRED ON PARENT_SCOPE)
    set(CMAKE_CXX_EXTENSIONS OFF PARENT_SCOPE)
endfunction()

########################################################################################################################

# function that returns the list
# of defines to be injected at compile time
#
function (get_compile_definitions RESULT)
    if (VERBOSE)
        set(${RESULT} ASN_EMIT_DEBUG=1
                      TRACE_HSM_API
            PARENT_SCOPE)
    else()
        set(${RESULT} ASN_EMIT_DEBUG=0 PARENT_SCOPE)
    endif()
endfunction()

########################################################################################################################

# function that returns the list of specific
# compilation options to be used when configuring a target
#
function (get_compile_options RESULT)
    if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
        _private_get_linux_compile_options(COMPILE_OPTIONS)
    elseif (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
        _private_get_windows_compile_options(COMPILE_OPTIONS)
    endif()

    set(${RESULT} ${COMPILE_OPTIONS} PARENT_SCOPE)
endfunction()

########################################################################################################################

# function that returns the list of additional
# include directories to be provided when configuring a target
#
function (get_include_directories RESULT)
    set(${RESULT} ${SOURCE_DIRECTORY}
                  ${CONAN_INCLUDE_DIRS_ASN1C}
                  ${CONAN_INCLUDE_DIRS_ASN1C}/asn1c
        PARENT_SCOPE)
endfunction()

########################################################################################################################

# function that returns the list of linking
# options to be used when configuring a target
#
function (get_link_options RESULT)
    if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
        set(${RESULT} -fPIC PARENT_SCOPE)
    endif()
endfunction()

########################################################################################################################
