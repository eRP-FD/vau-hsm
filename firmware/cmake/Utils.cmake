# (C) Copyright IBM Deutschland GmbH 2021, 2023
# (C) Copyright IBM Corp. 2021, 2023
#
# non-exclusively licensed to gematik GmbH

########################################################################################################################

# function that verifies (and aborts unless) a given parameter is defined as a CMake variable
#
function (utils_require_parameter_definition PARAMETER_NAME)
    if (NOT ${PARAMETER_NAME})
        message(FATAL_ERROR "Parameter `${PARAMETER_NAME}` is missing.")
    endif()
endfunction()

########################################################################################################################

# function that verifies (and aborts unless) a given parameter exists as a path on the filesystem
#
function (utils_require_file_existence PARAMETER_NAME)
    set(FILE ${${PARAMETER_NAME}})
    if (NOT EXISTS FILE)
        if (CMAKE_SYSTEM_NAME STREQUAL "Linux" OR (CMAKE_SYSTEM_NAME STREQUAL "Windows" AND NOT EXISTS "${FILE}.exe"))
            message(FATAL_ERROR "Parameter `${PARAMETER_NAME}` (`${FILE}`) does not exist on the filesystem.")
        endif()
    endif()
endfunction()

########################################################################################################################

# function that verifies (and aborts unless) a given parameter is
# defined as a CMake variable and points to an existent path on the filesystem
#
function (utils_require_file_parameter FILE_PARAMETER_NAME)
    utils_require_parameter_definition(${FILE_PARAMETER_NAME})
    utils_require_file_existence(${FILE_PARAMETER_NAME})
endfunction()

########################################################################################################################
