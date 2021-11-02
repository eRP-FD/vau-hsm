# private function that returns the list of clang-tidy checks that should be skipped
#
function (_private_get_clang_tidy_checks_whitelist RESULT)
    set(${RESULT} "clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling" PARENT_SCOPE)
endfunction()

# private function that returns the full content
# of how the clang-tidy checks flag should look like
#
function (_private_get_clang_tidy_checks RESULT)
	set(RESULT_LOCAL "*")

	_private_get_clang_tidy_checks_whitelist(WHITELIST)
	foreach (EXCEPTION IN LISTS WHITELIST)
		string(APPEND RESULT_LOCAL ",-${EXCEPTION}")
	endforeach()

	set(${RESULT} ${RESULT_LOCAL} PARENT_SCOPE)
endfunction()

# function that sets up static code analysis via clang-tidy
#
function (setup_clang_tidy)
	find_program(CLANG_TIDY "clang-tidy")
	if (NOT CLANG_TIDY)
	    message(STATUS "Cannot find `clang-tidy`. Continuing without static code analysis.")
	    return()
	endif()

	_private_get_clang_tidy_checks(CLANG_TIDY_CHECKS)
	list(APPEND CLANG_TIDY "-checks=${CLANG_TIDY_CHECKS}")

	# TODO: enable these once we are clang-tidy free
	#
	# list(APPEND CLANG_TIDY "--warnings-as-errors=*")
	# set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY}" PARENT_SCOPE)

	set(CMAKE_C_CLANG_TIDY "${CLANG_TIDY}" PARENT_SCOPE)
endfunction()

########################################################################################################################
