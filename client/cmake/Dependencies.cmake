# (C) Copyright IBM Deutschland GmbH 2021, 2023
# (C) Copyright IBM Corp. 2021, 2023
#
# non-exclusively licensed to gematik GmbH

########################################################################################################################

# function that returns the list of third party
# libraries (dependencies) that a target needs to link against
#
function (get_libraries_to_link_against RESULT)
    set(${RESULT} CONAN_PKG::csxapi PARENT_SCOPE)
endfunction()

########################################################################################################################

# function that returns the list of third party
# libraries that (only) test targets needs to link against
#
function (get_test_libraries_to_link_against RESULT)
    set(${RESULT} CONAN_PKG::gtest
     CONAN_PKG::openssl
     PARENT_SCOPE)
endfunction()

########################################################################################################################
