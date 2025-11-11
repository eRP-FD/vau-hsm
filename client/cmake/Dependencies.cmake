# (C) Copyright IBM Deutschland GmbH 2021, 2024
# (C) Copyright IBM Corp. 2021, 2024
#
# non-exclusively licensed to gematik GmbH

########################################################################################################################


########################################################################################################################

# function that returns the list of third party
# libraries that (only) test targets needs to link against
#
function (get_test_libraries_to_link_against RESULT)
    set(${RESULT} gtest::gtest
     OpenSSL::SSL OpenSSL::Crypto
     PARENT_SCOPE)
endfunction()

########################################################################################################################
