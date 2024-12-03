# (C) Copyright IBM Deutschland GmbH 2021, 2024
# (C) Copyright IBM Corp. 2021, 2024
#
# non-exclusively licensed to gematik GmbH

########################################################################################################################

# CMake script that offers an API for interacting with an HSM.
#
# Most API functions require the following parameters:
# - ADMIN_TOOL -- path to the cryptoserversdk admin tool (csadm)
# - IP -- IP address where the target HSM can be reached
# - PORT -- TCP port on which the target HSM is listening
# - ADMIN_LOGON_KEY -- key file used for logging in into the HSM as the admin user (not needed by all API functions)

########################################################################################################################

# private function that computes the import MBK command from the list of keys and passwords
#
function (_private_hsm_compute_import_mbk_command MBK_KEYS MBK_PASSWORDS MBK_COMPONENT_COUNT RESULT_OUT)
    set(MBK_KEYS_LOCAL ${MBK_KEYS})
    set(MBK_PASSWORDS_LOCAL ${MBK_PASSWORDS})

    list(LENGTH MBK_KEYS_LOCAL MBK_KEYS_COUNT)
    math(EXPR MBK_KEYS_COUNT_END "${MBK_KEYS_COUNT} - 1")

    foreach (INDEX RANGE ${MBK_KEYS_COUNT_END})
        list(GET MBK_KEYS_LOCAL ${INDEX} KEY)
        list(GET MBK_PASSWORDS_LOCAL ${INDEX} PASSWORD)

        string(APPEND KEYS "${KEY}#${PASSWORD}")
        if (NOT INDEX EQUAL ${MBK_KEYS_COUNT_END})
            string(APPEND KEYS ",")
        endif()
    endforeach()

    set(${RESULT_OUT} "Key=${KEYS};MBKImportKey=${MBK_COMPONENT_COUNT}" PARENT_SCOPE)
endfunction()

########################################################################################################################

# private function that executes a given command against an HSM and returns the results
#
function (_private_hsm_execute_command TOOL IP PORT LOGON_KEY COMMAND RESULT_OUT OUTPUT_OUT ERROR_OUT)
    set(LOGON_SUBCOMMAND "")
    if (NOT ${LOGON_KEY} STREQUAL "")
        set(LOGON_SUBCOMMAND "LogonSign=ADMIN,${LOGON_KEY}")
    endif()

    execute_process(COMMAND ${TOOL} dev=${PORT}@${IP} ${LOGON_SUBCOMMAND} ${COMMAND}
                    RESULT_VARIABLE RESULT_LOCAL
                    OUTPUT_VARIABLE OUTPUT_LOCAL
                    ERROR_VARIABLE ERROR_LOCAL)

    set(${OUTPUT_OUT} ${OUTPUT_LOCAL} PARENT_SCOPE)

    if (RESULT_LOCAL EQUAL 0)
        set(${RESULT_OUT} 1 PARENT_SCOPE)
    else()
        set(${RESULT_OUT} 0 PARENT_SCOPE)
        set(${ERROR_OUT} "${RESULT_LOCAL} -- ${ERROR_LOCAL}" PARENT_SCOPE)
    endif()
endfunction()

########################################################################################################################

# function that checks whether communication with an HSM can be established
#
function (hsm_is_reachable ADMIN_TOOL IP PORT RESULT_OUT ERROR_OUT)
    _private_hsm_execute_command(${ADMIN_TOOL} ${IP} ${PORT} "" "GetState" RESULT_LOCAL OUTPUT_LOCAL ERROR_LOCAL)

    if (${RESULT_LOCAL})
        string(FIND ${OUTPUT_LOCAL} "0x00100004" STATE_INITIALIZED_FOUND)
        if (STATE_INITIALIZED_FOUND EQUAL -1)
            set(${ERROR_OUT} "Initialized state (0x00100004) could not be found in 'GetState' command output."
                PARENT_SCOPE)
            set(${RESULT_OUT} 0 PARENT_SCOPE)
            return()
        endif()
    endif()

    set(${RESULT_OUT} ${RESULT_LOCAL} PARENT_SCOPE)
    set(${ERROR_OUT} ${ERROR_LOCAL} PARENT_SCOPE)
endfunction()

########################################################################################################################

# function that restarts an HSM
#
function (hsm_restart ADMIN_TOOL IP PORT RESULT_OUT ERROR_OUT)
    _private_hsm_execute_command(${ADMIN_TOOL} ${IP} ${PORT} "" "Restart" RESULT_LOCAL OUTPUT_LOCAL ERROR_LOCAL)

    set(${RESULT_OUT} ${RESULT_LOCAL} PARENT_SCOPE)
    set(${ERROR_OUT} ${ERROR_LOCAL} PARENT_SCOPE)
endfunction()

########################################################################################################################

# function that checks whether an MBK (given by its fingerprint) is already loaded into an HSM
#
function (hsm_is_mbk_loaded ADMIN_TOOL IP PORT MBK_FINGERPRINT RESULT_OUT ERROR_OUT)
    _private_hsm_execute_command(${ADMIN_TOOL} ${IP} ${PORT} "" "MBKListKeys" RESULT_LOCAL OUTPUT_LOCAL ERROR_LOCAL)

    if (${RESULT_LOCAL})
        string(FIND ${OUTPUT_LOCAL} ${MBK_FINGERPRINT} MBK_FOUND)
        if (MBK_FOUND EQUAL -1)
            set(${RESULT_OUT} 0 PARENT_SCOPE)
            return()
        endif()
    endif()

    set(${RESULT_OUT} ${RESULT_LOCAL} PARENT_SCOPE)
    set(${ERROR_OUT} ${ERROR_LOCAL} PARENT_SCOPE)
endfunction()

########################################################################################################################

# function that imports a new MBK (given by its components) into an HSM
#
function (hsm_import_mbk ADMIN_TOOL IP PORT LOGON_KEY MBK_KEYS MBK_PASSWORDS MBK_COMPONENT_COUNT RESULT_OUT ERROR_OUT)
    set(MBK_KEYS_LOCAL ${MBK_KEYS})
    list(LENGTH MBK_KEYS_LOCAL MBK_KEYS_COUNT)
    if (MBK_KEYS_COUNT EQUAL 0)
        set(${ERROR_OUT} "MBK keys cannot be a zero-length list." PARENT_SCOPE)
        set(${RESULT_OUT} 0 PARENT_SCOPE)
        return()
    endif()

    if (MBK_KEYS_COUNT GREATER MBK_COMPONENT_COUNT)
        set(${ERROR_OUT} "MBK keys count `${MBK_KEYS_COUNT}` cannot be greater "
                         "than the total keys count `${MBK_COMPONENT_COUNT}`."
              PARENT_SCOPE)
        set(${RESULT_OUT} 0 PARENT_SCOPE)
        return()
    endif()

    set(MBK_PASSWORDS_LOCAL ${MBK_PASSWORDS})
    list(LENGTH MBK_PASSWORDS_LOCAL MBK_PASSWORDS_COUNT)
    if (NOT MBK_KEYS_COUNT EQUAL MBK_PASSWORDS_COUNT)
        set(${ERROR_OUT} "MBK keys count `${MBK_KEYS_COUNT}` does not match passwords count `${MBK_PASSWORDS_COUNT}`."
            PARENT_SCOPE)
        set(${RESULT_OUT} 0 PARENT_SCOPE)
        return()
    endif()

    _private_hsm_compute_import_mbk_command("${MBK_KEYS_LOCAL}" "${MBK_PASSWORDS_LOCAL}" ${MBK_COMPONENT_COUNT} COMMAND)
    _private_hsm_execute_command(${ADMIN_TOOL}
                                 ${IP}
                                 ${PORT}
                                 ${LOGON_KEY}
                                 "${COMMAND}"
                                 RESULT_LOCAL
                                 OUTPUT_LOCAL
                                 ERROR_LOCAL)

    set(${RESULT_OUT} ${RESULT_LOCAL} PARENT_SCOPE)
    set(${ERROR_OUT} ${ERROR_LOCAL} PARENT_SCOPE)
endfunction()

########################################################################################################################

# function that restores a database from a file into an HSM
#
function (hsm_restore_database ADMIN_TOOL IP PORT LOGON_KEY DATABASE RESULT_OUT ERROR_OUT)
    _private_hsm_execute_command(${ADMIN_TOOL}
                                 ${IP}
                                 ${PORT}
                                 ${LOGON_KEY}
                                 "RestoreDatabase=${DATABASE}"
                                 RESULT_LOCAL
                                 OUTPUT_LOCAL
                                 ERROR_LOCAL)

    set(${RESULT_OUT} ${RESULT_LOCAL} PARENT_SCOPE)
    set(${ERROR_OUT} ${ERROR_LOCAL} PARENT_SCOPE)
endfunction()

########################################################################################################################

# function that signs a given firmware with a given key and returns the resulting MTC file
#
function (hsm_sign_firmware ADMIN_TOOL IP PORT SIGN_KEY FIRMWARE RESULT_OUT ERROR_OUT)
    set(COMMAND Model=c50 MMCSignKey=${SIGN_KEY} MakeMTC=${FIRMWARE})
    _private_hsm_execute_command(${ADMIN_TOOL} ${IP} ${PORT} "" "${COMMAND}" RESULT_LOCAL OUTPUT_LOCAL ERROR_LOCAL)

    if (${RESULT_LOCAL})
        get_filename_component(FILENAME ${FIRMWARE} NAME_WE)
        if (NOT FILENAME)
            set(${ERROR_OUT} "Cannot get the filename of firmware `${FIRMWARE}`." PARENT_SCOPE)
            set(${RESULT_OUT} 0 PARENT_SCOPE)
            return()
        endif()

        get_filename_component(PARENT_DIRECTORY ${FIRMWARE} DIRECTORY)
        if (NOT PARENT_DIRECTORY)
            set(${ERROR_OUT} "Cannot get the parent directory of firmware `${FIRMWARE}`." PARENT_SCOPE)
            set(${RESULT_OUT} 0 PARENT_SCOPE)
            return()
        endif()

        if (NOT EXISTS ${PARENT_DIRECTORY} OR NOT IS_DIRECTORY ${PARENT_DIRECTORY})
            set(${ERROR_OUT} "Parent directory of firmware `${FIRMWARE}` does not "
                             "exist or is not a directory: `${PARENT_DIRECTORY}`." PARENT_SCOPE)
            set(${RESULT_OUT} 0 PARENT_SCOPE)
            return()
        endif()

        set(${RESULT_OUT} "${PARENT_DIRECTORY}/${FILENAME}.mtc" PARENT_SCOPE)
        return()
    endif()

    set(${RESULT_OUT} ${RESULT_LOCAL} PARENT_SCOPE)
    set(${ERROR_OUT} ${ERROR_LOCAL} PARENT_SCOPE)
endfunction()

########################################################################################################################

# function that loads a given signed firmware (MTC file) into an HSM
#
function (hsm_load_signed_firmware ADMIN_TOOL IP PORT LOGON_KEY SIGNED_FIRMWARE RESULT_OUT ERROR_OUT)
    _private_hsm_execute_command(${ADMIN_TOOL}
                                 ${IP}
                                 ${PORT}
                                 ${LOGON_KEY}
                                 "LoadFile=${SIGNED_FIRMWARE}"
                                 RESULT_LOCAL
                                 OUTPUT_LOCAL
                                 ERROR_LOCAL)

    set(${RESULT_OUT} ${RESULT_LOCAL} PARENT_SCOPE)
    set(${ERROR_OUT} ${ERROR_LOCAL} PARENT_SCOPE)
endfunction()

########################################################################################################################

# function that launches an HSM simulator in background
#
function (hsm_launch_simulator SIMULATOR RESULT_OUT ERROR_OUT)
    set(SIMULATOR_STDOUT "simulator_stdout.txt")
    set(SIMULATOR_STDERR "simulator_stderr.txt")

    if (CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
        set(COMMAND bash -c "${HSM_SIMULATOR} -h -o &")
    elseif(CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
        set(COMMAND powershell Start-Process '${HSM_SIMULATOR}' -ArgumentList "'-h -o'")
    else()
        set(${ERROR_OUT} "Simulator can be launched only on Linux or "
                         "Windows. `${CMAKE_HOST_SYSTEM_NAME}` is unsupported."
            PARENT_SCOPE)
        set(${RESULT_OUT} 0 PARENT_SCOPE)
        return()
    endif()

    execute_process(COMMAND ${COMMAND}
                    RESULT_VARIABLE RESULT_LOCAL
                    OUTPUT_FILE ${SIMULATOR_STDOUT}
                    ERROR_FILE ${SIMULATOR_STDERR})

    if (NOT RESULT_LOCAL EQUAL 0)
        file(READ ${SIMULATOR_STDOUT} OUTPUT_LOCAL)
        file(READ ${SIMULATOR_STDERR} ERROR_LOCAL)

        set(${ERROR_OUT} "${RESULT_LOCAL} -- ${OUTPUT_LOCAL} -- ${ERROR_LOCAL}" PARENT_SCOPE)
        set(${RESULT_OUT} 0 PARENT_SCOPE)
        return()
    endif()

    file(REMOVE ${SIMULATOR_STDOUT} ${SIMULATOR_STDERR})

    execute_process(COMMAND ${CMAKE_COMMAND} -E sleep 5)

    set(${RESULT_OUT} 1 PARENT_SCOPE)
endfunction()

########################################################################################################################

# function that kills the HSM simulator processes
#
function (hsm_kill_simulator SIMULATOR RESULT_OUT ERROR_OUT)
    get_filename_component(FILENAME ${SIMULATOR} NAME_WE)
    if (NOT FILENAME)
        set(${ERROR_OUT} "Cannot get the filename of HSM simulator `${SIMULATOR}`." PARENT_SCOPE)
        set(${RESULT_OUT} 0 PARENT_SCOPE)
        return()
    endif()

    execute_process(COMMAND pgrep ${FILENAME}
                    RESULT_VARIABLE PGREP_RESULT_LOCAL
                    OUTPUT_VARIABLE PGREP_OUTPUT_LOCAL
                    ERROR_VARIABLE PGREP_ERROR_LOCAL)

    if (NOT PGREP_RESULT_LOCAL EQUAL 0)
        set(${ERROR_OUT} "Cannot get the PIDs of any running processes "
                         "launched from `${SIMULATOR}`. Errors: `${PGREP_RESULT_LOCAL} -- ${PGREP_ERROR_LOCAL}`."
            PARENT_SCOPE)
        set(${RESULT_OUT} 0 PARENT_SCOPE)
        return()
    endif()

    string(REGEX MATCHALL "[0-9]+" SIMULATOR_PIDS ${PGREP_OUTPUT_LOCAL})
    execute_process(COMMAND kill -9 ${SIMULATOR_PIDS}
                    RESULT_VARIABLE KILL_RESULT_LOCAL
                    OUTPUT_VARIABLE KILL_OUTPUT_LOCAL
                    ERROR_VARIABLE KILL_ERROR_LOCAL)

    if (NOT KILL_RESULT_LOCAL EQUAL 0)
        set(${ERROR_OUT} "Cannot kill processes `${PGREP_OUTPUT_LOCAL}`. "
                         "Errors: `${KILL_RESULT_LOCAL} -- ${KILL_ERROR_LOCAL}`."
             PARENT_SCOPE)
        set(${RESULT_OUT} 0 PARENT_SCOPE)
        return()
    endif()

    set(${RESULT_OUT} 1 PARENT_SCOPE)
endfunction()

########################################################################################################################
