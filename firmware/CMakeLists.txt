# (C) Copyright IBM Deutschland GmbH 2021, 2024
# (C) Copyright IBM Corp. 2021, 2024
#
# non-exclusively licensed to gematik GmbH

########################################################################################################################

#################
# prerequisites #
#################

cmake_minimum_required(VERSION 3.16)

set(PROJECT_NAME hsm-firmware)

project(${PROJECT_NAME} LANGUAGES C)

if (NOT ${CMAKE_SYSTEM_NAME} STREQUAL "Linux" AND NOT ${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    message(FATAL_ERROR "`${PROJECT_NAME}` builds only on Linux and Windows.")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

####################
# custom variables #
####################

set(ROOT_DIRECTORY ${CMAKE_SOURCE_DIR})

set(CMAKE_DIRECTORY ${ROOT_DIRECTORY}/cmake)

set(HSM_DIRECTORY ${ROOT_DIRECTORY}/hsm)

set(HSM_BACKUP_MBK_DIRECTORY ${HSM_DIRECTORY}/backup/mbk)

set(HSM_BACKUP_DATABASES_DIRECTORY ${HSM_DIRECTORY}/backup/databases)

set(SOURCE_DIRECTORY ${ROOT_DIRECTORY}/src)

set(BUILD_DIRECTORY ${CMAKE_BINARY_DIR})

set(SIMULATOR_DIRECTORY ${BUILD_DIRECTORY}/simulator)

set(SIMULATOR_EXECUTABLE ${SIMULATOR_DIRECTORY}/bin/bl_sim5)

set(CONAN_BUILD_INFO_SCRIPT ${BUILD_DIRECTORY}/conanbuildinfo.cmake)

set(DEPLOYMENT_SCRIPT ${CMAKE_DIRECTORY}/Deployment.cmake)

set(DEPLOYMENT_OPTIONS_SCRIPT ${CMAKE_DIRECTORY}/DeploymentOptions.cmake)

set(DEPLOYMENT_TARGET_NAME deploy)

if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    set(COMPILE_OPTIONS /nologo
                        /W4
                        /WX
                        /wd4057
                        /wd4100
                        /TC
                        /FS
                        $<$<CONFIG:Release>:/MD>
                        $<$<CONFIG:Release>:/O2>
                        $<$<CONFIG:Debug>:/MDd>
                        $<$<CONFIG:Debug>:/RTC1>
                        $<$<CONFIG:Debug>:/Zi>
                        $<$<CONFIG:Debug>:/DDISABLE_BLOB_EXPIRY>
                        $<$<CONFIG:Debug>:/Od>)

    set(LINK_OPTIONS /MACHINE:X86)
elseif (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    set(COMPILE_OPTIONS -m32
                        -Werror
                        -Wall
                        -Wextra
                        -Wpedantic
                        -Wfloat-equal
                        -Winit-self
                        -Wshadow
                        -Wswitch-default
                        -Wundef
                        -Wno-unused-parameter
                        -Wno-pointer-sign
                        $<$<CONFIG:Debug>:-DDISABLE_BLOB_EXPIRY>
                        $<$<CONFIG:Release>:-O2>
                        $<$<CONFIG:Debug>:-g>
                        $<$<CONFIG:Debug>:-ggdb>
                        $<$<CONFIG:Debug>:-O0>)

    set(LINK_OPTIONS -m32)
endif()

####################
# custom functions #
####################

# function that configures a target for building with the required compilation and linking flags
#
function (configure_target TARGET_NAME)
    find_package(cryptoserversdk REQUIRED)
    set_target_properties(${TARGET_NAME} PROPERTIES PREFIX "")

    if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
        set_target_properties(${TARGET_NAME} PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS TRUE)
    endif()

    target_compile_options(${TARGET_NAME} PRIVATE ${COMPILE_OPTIONS})

    target_link_options(${TARGET_NAME} PRIVATE ${LINK_OPTIONS})

    target_link_libraries(${TARGET_NAME} PRIVATE cryptoserversdk::cryptoserversdk)

    target_include_directories(${TARGET_NAME} PRIVATE ${SOURCE_DIRECTORY})
endfunction()

##########################
# dependencies retrieval #
##########################


include(${DEPLOYMENT_OPTIONS_SCRIPT})

########################################################################################################################

# function that attempts to deploy a target on an HSM
#
function (deploy_target_as_firmware TARGET_NAME)
    deployment_options_get_scripts_arguments(DEPLOYMENT_SCRIPT_ARGUMENTS)

    add_custom_target(${DEPLOYMENT_TARGET_NAME}
                      ALL
                      COMMAND ${CMAKE_COMMAND} -DFIRMWARE=$<TARGET_FILE:${TARGET_NAME}>
                                               ${DEPLOYMENT_SCRIPT_ARGUMENTS}
                                               -P ${DEPLOYMENT_SCRIPT}
                      DEPENDS ${TARGET_NAME}
                      WORKING_DIRECTORY ${CMAKE_DIRECTORY}
                      VERBATIM)
endfunction()

########################################################################################################################

###########################
# subdirectories includes #
###########################

add_subdirectory(src)

########################################################################################################################
