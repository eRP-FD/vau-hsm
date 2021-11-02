# CMake script that defines a bunch of configuration values needed by the deployment process

# The script expects the Conan build info CMake script to have been included previously

########################################################################################################################

set(_PRIVATE_DEFAULT_HSM_IP "localhost")
set(_PRIVATE_DEFAULT_HSM_PORT "3001")
set(_PRIVATE_DEFAULT_HSM_ADMIN_LOGON_KEY ${CONAN_USER_CRYPTOSERVERSDK_SIMULATOR_ADMIN_LOGON_KEY})
set(_PRIVATE_DEFAULT_HSM_FIRMWARE_SIGN_KEY ${CONAN_USER_CRYPTOSERVERSDK_SIMULATOR_FIRMWARE_SIGN_KEY})
set(_PRIVATE_DEFAULT_HSM_MBK_FINGERPRINT "65DBDAE426E6E916:83E73FD5A2BF92B3")
set(_PRIVATE_DEFAULT_HSM_MBK_COMPONENT_COUNT "3")
set(_PRIVATE_DEFAULT_HSM_MBK_PASSWORDS "pwd2" "pwd3")
file(GLOB _PRIVATE_DEFAULT_HSM_MBK_KEYS LIST_DIRECTORIES FALSE ${HSM_BACKUP_MBK_DIRECTORY}/*.mbk)
file(GLOB _PRIVATE_DEFAULT_HSM_DATABASES LIST_DIRECTORIES FALSE ${HSM_BACKUP_DATABASES_DIRECTORY}/*.db)

# put all option variables in a list in order to achieve a fallback-to-default-value-unless-defined behaviour
#
set(_PRIVATE_DEPLOYMENT_OPTIONS_VARIABLES "HSM_IP"
                                          "HSM_PORT"
                                          "HSM_ADMIN_LOGON_KEY"
                                          "HSM_FIRMWARE_SIGN_KEY"
                                          "HSM_MBK_FINGERPRINT"
                                          "HSM_MBK_COMPONENT_COUNT"
                                          "HSM_MBK_KEYS"
                                          "HSM_MBK_PASSWORDS"
                                          "HSM_DATABASES")

########################################################################################################################

# function that sets an option variable to its default value (unless it has already been explicitly defined)
#
function (_private_set_default_option_if_not_defined OPTION_VARIABLE)
    set(EXPORTED_OPTION_VARIABLE "DEPLOYMENT_OPTIONS_${OPTION_VARIABLE}")
    if (NOT ${EXPORTED_OPTION_VARIABLE})
        set(${EXPORTED_OPTION_VARIABLE} ${_PRIVATE_DEFAULT_${OPTION_VARIABLE}} PARENT_SCOPE)
    endif()
endfunction()

########################################################################################################################

# function that defines/exports the DEPLOYMENT_OPTIONS_* variables (unless they have already been defined elsewhere)
#
macro (deployment_options_export)
    foreach (OPTION_VARIABLE IN LISTS _PRIVATE_DEPLOYMENT_OPTIONS_VARIABLES)
        _private_set_default_option_if_not_defined(${OPTION_VARIABLE})
    endforeach()
endmacro()

########################################################################################################################

# function that computes the deployment options as a list of arguments to be passed to the CMake deployment script
#
function (deployment_options_get_scripts_arguments RESULT_OUT)
    if (NOT DEPLOYMENT_OPTIONS_EXPORTED)
        set(DEPLOYMENT_OPTIONS_EXPORTED 1 CACHE BOOL "Whether deployment options have been exported globally.")
        deployment_options_export()
    endif()

    string(REPLACE ";" $<SEMICOLON> GENERATOR_HSM_MBK_KEYS "${DEPLOYMENT_OPTIONS_HSM_MBK_KEYS}")
    string(REPLACE ";" $<SEMICOLON> GENERATOR_HSM_MBK_PASSWORDS "${DEPLOYMENT_OPTIONS_HSM_MBK_PASSWORDS}")
    string(REPLACE ";" $<SEMICOLON> GENERATOR_HSM_MBK_DATABASES "${DEPLOYMENT_OPTIONS_HSM_DATABASES}")

    list(APPEND RESULT_LOCAL "HSM_SIMULATOR=${SIMULATOR_EXECUTABLE}")
    list(APPEND RESULT_LOCAL "HSM_IP=${DEPLOYMENT_OPTIONS_HSM_IP}")
    list(APPEND RESULT_LOCAL "HSM_PORT=${DEPLOYMENT_OPTIONS_HSM_PORT}")
    list(APPEND RESULT_LOCAL "HSM_ADMIN_TOOL=${CONAN_USER_CRYPTOSERVERSDK_ADMIN_TOOL}")
    list(APPEND RESULT_LOCAL "HSM_ADMIN_LOGON_KEY=${DEPLOYMENT_OPTIONS_HSM_ADMIN_LOGON_KEY}")
    list(APPEND RESULT_LOCAL "HSM_FIRMWARE_SIGN_KEY=${DEPLOYMENT_OPTIONS_HSM_FIRMWARE_SIGN_KEY}")
    list(APPEND RESULT_LOCAL "HSM_MBK_FINGERPRINT=${DEPLOYMENT_OPTIONS_HSM_MBK_FINGERPRINT}")
    list(APPEND RESULT_LOCAL "HSM_MBK_COMPONENT_COUNT=${DEPLOYMENT_OPTIONS_HSM_MBK_COMPONENT_COUNT}")
    list(APPEND RESULT_LOCAL "HSM_MBK_KEYS=${GENERATOR_HSM_MBK_KEYS}")
    list(APPEND RESULT_LOCAL "HSM_MBK_PASSWORDS=${GENERATOR_HSM_MBK_PASSWORDS}")
    list(APPEND RESULT_LOCAL "HSM_DATABASES=${GENERATOR_HSM_MBK_DATABASES}")

    list(TRANSFORM RESULT_LOCAL PREPEND "-D")

    set(${RESULT_OUT} "${RESULT_LOCAL}" PARENT_SCOPE)
endfunction()

########################################################################################################################
