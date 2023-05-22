# (C) Copyright IBM Deutschland GmbH 2021, 2023
# (C) Copyright IBM Corp. 2021, 2023
#
# non-exclusively licensed to gematik GmbH

########################################################################################################################

# CMake script in charge of deploying a firmware file on an HSM target.
#
# The script expects the following parameters to be available.
# All paths can be absolute or relative to this script's directory.
#
# - FIRMWARE -- path to a firmware file to be deployed (most likely a shared library)
# - HSM_SIMULATOR -- if not empty, it should be a path to an HSM simulator to be used as HSM target
# - HSM_IP -- IP address of the HSM target
# - HSM_PORT -- port that the HSM target is listening on
# - HSM_ADMIN_TOOL -- path to the cryptoserversdk admin tool (csadm)
# - HSM_ADMIN_LOGON_KEY -- path to the key file used for logging in into the HSM as the admin user
# - HSM_FIRMWARE_SIGN_KEY -- path to the key file that should be used for signing firmware
# - HSM_MBK_FINGERPRINT -- fingerprint of the default MBK
# - HSM_MBK_COMPONENT_COUNT -- how many components the default MBK has
# - HSM_MBK_KEYS -- list of paths to the MBK keys used to compose the default MBK
# - HSM_MBK_PASSWORDS -- list of passwords corresponding to the MBK keys
# - HSM_DATABASES -- list of path to the databases to be restored on the HSM

########################################################################################################################

include("Hsm.cmake")
include("Utils.cmake")

########################################################################################################################

# function that checks if communication can be established
#
function (_private_deployment_check_communication RESULT_OUT SIMULATOR_LAUNCHED_OUT)
    message(STATUS "Trying to communicate with HSM at IP address `${HSM_IP}` and port number `${HSM_PORT}`.")

    hsm_is_reachable(${HSM_ADMIN_TOOL} ${HSM_IP} ${HSM_PORT} IS_REACHABLE_RESULT IS_REACHABLE_ERROR)
    if (NOT IS_REACHABLE_RESULT)
        message(STATUS "Cannot reach HSM. Description: `${IS_REACHABLE_ERROR}`.")

        if (HSM_SIMULATOR)
            message(STATUS "Trying to launch HSM simulator `${HSM_SIMULATOR}`.")

            hsm_launch_simulator(${HSM_SIMULATOR} LAUNCH_SIMULATOR_RESULT LAUNCH_SIMULATOR_ERROR)
            if (NOT LAUNCH_SIMULATOR_RESULT)
                message(FATAL_ERROR "Cannot launch HSM simulator. Failed deployment. "
                                    "Description: `${LAUNCH_SIMULATOR_ERROR}`.")
            endif()

            set(${SIMULATOR_LAUNCHED_OUT} 1 PARENT_SCOPE)

            message(STATUS "HSM simulator running. Trying to reach it.")

            hsm_is_reachable(${HSM_ADMIN_TOOL} ${HSM_IP} ${HSM_PORT} IS_REACHABLE_RESULT IS_REACHABLE_ERROR)
            if (NOT IS_REACHABLE_RESULT)
                message(FATAL_ERROR "Cannot reach HSM simulator. Description: `${IS_REACHABLE_ERROR}`.")
            endif()

            set(${RESULT_OUT} 1 PARENT_SCOPE)
        else()
            message(STATUS "Skipping deployment.")
            set(${RESULT_OUT} 0 PARENT_SCOPE)
        endif()
    else()
        set(${RESULT_OUT} 1 PARENT_SCOPE)
    endif()
endfunction()

########################################################################################################################

# function that imports master backup keys from files
#
function (_private_deployment_import_mbk)
    message(STATUS "Importing MBKs:")
    foreach (MBK IN LISTS HSM_MBK_KEYS)
        message(STATUS "-> `${MBK}`")
    endforeach()

    message(STATUS "Using passwords:")
    foreach (PASSWORD IN LISTS HSM_MBK_PASSWORDS)
        message(STATUS "-> `${PASSWORD}`")
    endforeach()

    hsm_import_mbk(${HSM_ADMIN_TOOL}
                   ${HSM_IP}
                   ${HSM_PORT}
                   ${HSM_ADMIN_LOGON_KEY}
                   "${HSM_MBK_KEYS}"
                   "${HSM_MBK_PASSWORDS}"
                   "${HSM_MBK_COMPONENT_COUNT}"
                   IMPORT_MBK_RESULT
                   IMPORT_MBK_ERROR)

    if (NOT IMPORT_MBK_RESULT)
        message(FATAL_ERROR "Cannot import MBKs. Description: `${IMPORT_MBK_ERROR}`.")
    endif()
endfunction()

########################################################################################################################

# function that restores the databases from backup files; it expects that the necessary MBK has been imported
#
function (_private_deployment_restore_databases)
    message(STATUS "Restoring databases:")
    foreach (DATABASE IN LISTS HSM_DATABASES)
        message(STATUS "-> `${DATABASE}`")

        utils_require_file_existence(DATABASE)

        hsm_restore_database(${HSM_ADMIN_TOOL}
                             ${HSM_IP}
                             ${HSM_PORT}
                             ${HSM_ADMIN_LOGON_KEY}
                             ${DATABASE}
                             RESTORE_DATABASE_RESULT
                             RESTORE_DATABASE_ERROR)

        if (NOT RESTORE_DATABASE_RESULT)
            message(FATAL_ERROR "Cannot restore database `${DATABASE}`. Description: `${RESTORE_DATABASE_ERROR}`.")
        endif()
    endforeach()
endfunction()

########################################################################################################################

# function that sets up an HSM so that the firmware deployed on it can work correctly
#
function (_private_deployment_initialise_before_deployment RESULT_OUT SIMULATOR_STARTED)
    _private_deployment_check_communication(CHECK_COMMUNICATION_RESULT CHECK_COMMUNICATION_SIMULATOR_STARTED)
    if (CHECK_COMMUNICATION_RESULT)
        set(${SIMULATOR_STARTED} ${CHECK_COMMUNICATION_SIMULATOR_STARTED} PARENT_SCOPE)

        message(STATUS "HSM can be reached; continuing initialisation.")
        message(STATUS "Checking if HSM is already initialised.")

        hsm_is_mbk_loaded(${HSM_ADMIN_TOOL}
                          ${HSM_IP}
                          ${HSM_PORT}
                          ${HSM_MBK_FINGERPRINT}
                          IS_MBK_LOADED_RESULT
                          IS_MBK_LOADED_ERROR)

        if (NOT IS_MBK_LOADED_RESULT)
            message(STATUS "HSM not initialised; performing initialisation.")

            _private_deployment_import_mbk()
            _private_deployment_restore_databases()
        else()
            message(STATUS "HSM already initialised; skipping initialisation.")
        endif()

        set(${RESULT_OUT} 1 PARENT_SCOPE)
    else()
        set(${RESULT_OUT} 0 PARENT_SCOPE)
    endif()
endfunction()

########################################################################################################################

# function that performs the deployment steps; it expects that the HSM has been initialised
#
function (_private_deployment_perform_deployment)
    message(STATUS "Deploying firmware `${FIRMWARE}`.")

    hsm_sign_firmware(${HSM_ADMIN_TOOL}
                      ${HSM_IP}
                      ${HSM_PORT}
                      ${HSM_FIRMWARE_SIGN_KEY}
                      ${FIRMWARE}
                      SIGN_FIRMWARE_RESULT
                      SIGN_FIRMWARE_ERROR)

    if (NOT SIGN_FIRMWARE_RESULT)
        message(FATAL_ERROR "Cannot sign firmware `${FIRMWARE}`. Description: `${SIGN_FIRMWARE_ERROR}`.")
    endif()

    hsm_load_signed_firmware(${HSM_ADMIN_TOOL}
                             ${HSM_IP}
                             ${HSM_PORT}
                             ${HSM_ADMIN_LOGON_KEY}
                             ${SIGN_FIRMWARE_RESULT}
                             LOAD_SIGNED_FIRMWARE_RESULT
                             LOAD_SIGNED_FIRMWARE_ERROR)

    if (NOT LOAD_SIGNED_FIRMWARE_RESULT)
        message(FATAL_ERROR "Cannot load firmware `${SIGN_FIRMWARE_RESULT}` "
                            "into HSM. Description: `${LOAD_SIGNED_FIRMWARE_ERROR}`.")
    endif()

    hsm_restart(${HSM_ADMIN_TOOL} ${HSM_IP} ${HSM_PORT} RESTART_RESULT RESTART_ERROR)
    if (NOT RESTART_RESULT)
        message(STATUS "Cannot restart HSM. Firmware may or may not have been "
                       "deployed successfully. Description: `${RESTART_ERROR}`.")
    else()
        message(STATUS "Deployment completed successfully.")
    endif()
endfunction()

########################################################################################################################

# function that acts as the "main" function of this script
#
function (deployment_main)
    _private_deployment_initialise_before_deployment(INITIALISE_RESULT INITIALISE_SIMULATOR_STARTED)

    if (INITIALISE_RESULT)
        _private_deployment_perform_deployment()
    else()
        message("Initialisation did not finish successfully; will not continue with deployment.")
    endif()

    if (INITIALISE_SIMULATOR_STARTED AND CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
        message(STATUS "Killing HSM simulator instance.")
        hsm_kill_simulator(${HSM_SIMULATOR} KILL_SIMULATOR_RESULT KILL_SIMULATOR_ERROR)
        if (NOT KILL_SIMULATOR_RESULT)
            message(FATAL_ERROR "Cannot kill HSM simulator. Description: `${KILL_SIMULATOR_ERROR}`.")
        endif()
    endif()
endfunction()

########################################################################################################################

# call the main function of the script
#
if (CMAKE_SCRIPT_MODE_FILE)
    deployment_main()
endif()

########################################################################################################################
