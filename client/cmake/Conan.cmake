# (C) Copyright IBM Deutschland GmbH 2021, 2024
# (C) Copyright IBM Corp. 2021, 2024
#
# non-exclusively licensed to gematik GmbH

########################################################################################################################

# function that calls the Conan setup routines
# initializing all third party dependencies variables
#
macro (setup_conan)
    find_program(CONAN conan)
    if (NOT CONAN)
        message(FATAL_ERROR "Cannot find conan. Is it installed?")
    endif()

    set(CONAN_IMPORTS_MANIFEST_NAME "conan_imports_manifest.txt")
    set(CONAN_BUILD_INFO_SCRIPT ${BUILD_DIRECTORY}/conanbuildinfo.cmake)
    set(CONAN_ARGS "install" "." "--build=missing" "--install-folder=${BUILD_DIRECTORY}")
    if (BUILD_TESTS)
        list(APPEND CONAN_ARGS "-o" "hsmclient:with_tests=True")
    endif()
    if (DEFINED CMAKE_BUILD_TYPE)
        list(APPEND CONAN_ARGS "-s" "build_type=${CMAKE_BUILD_TYPE}")
    endif()

    if (NOT CONAN_EXPORTED AND
           (NOT EXISTS ${CONAN_BUILD_INFO_SCRIPT} OR NOT ("${PREVIOUS_CONAN_ARGS}" STREQUAL "${CONAN_ARGS}")))
        set(PREVIOUS_CONAN_ARGS "${CONAN_ARGS}" CACHE INTERNAL "Conan arguments of last conan run")
        file(REMOVE ${CONAN_BUILD_INFO_SCRIPT})
        execute_process(COMMAND ${CONAN} ${CONAN_ARGS}
                        WORKING_DIRECTORY ${ROOT_DIRECTORY}
                        RESULT_VARIABLE RESULT)
        if (NOT RESULT STREQUAL "0")
            message(FATAL_ERROR "Unable to fetch dependencies: `conan install` failed. See errors above.")
        endif()
    endif()

    include(${CONAN_BUILD_INFO_SCRIPT})

    conan_basic_setup(TARGETS)
endmacro()

########################################################################################################################
