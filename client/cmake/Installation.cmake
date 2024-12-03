# (C) Copyright IBM Deutschland GmbH 2021, 2024
# (C) Copyright IBM Corp. 2021, 2024
#
# non-exclusively licensed to gematik GmbH

########################################################################################################################

# private function that sets the install runpath of a target
# to $ORIGIN so that its dependencies can be found at runtime
#
function (_private_set_runpath TARGET_NAME)
    _private_check_target_exists(${TARGET_NAME})

    get_target_property(TARGET_TYPE ${TARGET_NAME} TYPE)
    if (${TARGET_TYPE} STREQUAL "SHARED_LIBRARY")
        set(RUNPATH "$ORIGIN")
    elseif (${TARGET_TYPE} STREQUAL "EXECUTABLE")
        set(RUNPATH "$ORIGIN/../lib")
    endif()

    if (RUNPATH)
        set_target_properties(${TARGET_NAME} PROPERTIES INSTALL_RPATH ${RUNPATH})
    endif()
endfunction()

########################################################################################################################

# function that given a target name (and optionally a list of its public API headers),
# it instructs the generated build system to install its artefacts (in system wide locations)
#
function (install_target TARGET_NAME PUBLIC_HEADERS)
    set_target_properties(${TARGET_NAME} PROPERTIES PUBLIC_HEADER "${PUBLIC_HEADERS}")
    install(TARGETS ${TARGET_NAME} PUBLIC_HEADER DESTINATION include/${TARGET_NAME})

    _private_set_runpath(${TARGET_NAME})
endfunction()

########################################################################################################################

# function that copies the resources of a test target (which must already exist and
# be configured as a test target, see TargetConfiguration::configure_test_target) into the
# build folder of the test executable such that the executable can access the resources it needs
#
function (copy_test_resources TARGET_NAME)
    if (NOT BUILD_TESTS)
        return()
    endif()

    if (NOT TARGET ${TARGET_NAME})
        message(FATAL_ERROR "Test target ${TARGET_NAME} does not exist. Define and "
                            "configure it with `configure_test_target` before copying its resources.")
    endif()

    get_filename_component(RESOURCES_DIRECTORY ${TEST_RESOURCES_DIRECTORY} NAME)
    if (NOT RESOURCES_DIRECTORY)
        message(FATAL_ERROR "Cannot get resources directory from path `${TEST_RESOURCES_DIRECTORY}`.")
    endif()

    set(BUILD_BIN_DIRECTORY_RESOURCES "${BUILD_BIN_DIRECTORY}/${RESOURCES_DIRECTORY}")

    add_custom_command(TARGET ${TARGET_NAME}
                       POST_BUILD
                       COMMAND ${CMAKE_COMMAND}
                       ARGS -E
                            copy_directory
                            ${TEST_RESOURCES_DIRECTORY}
                            ${BUILD_BIN_DIRECTORY_RESOURCES}
                       VERBATIM)
endfunction()

########################################################################################################################
