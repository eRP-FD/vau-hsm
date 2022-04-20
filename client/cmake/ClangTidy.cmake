# (C) Copyright IBM Deutschland GmbH 2021
# (C) Copyright IBM Corp. 2021
# SPDX-License-Identifier: CC BY-NC-ND 3.0 DE

########################################################################################################################

# private function that returns the list of clang-tidy checks that should be skipped
#
function (_private_get_clang_tidy_checks_whitelist RESULT)
    set(${RESULT}
		# unfortunately these checks have to be disabled because of gtest
		#
		"cert-err58-cpp"
		"cppcoreguidelines-owning-memory"
		"fuchsia-default-arguments-calls"
		"fuchsia-statically-constructed-objects"
		"modernize-use-trailing-return-type"

		# these ones cannot be fixed within our toolchain.
		#
		"clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling"
		"hicpp-use-auto"
		"modernize-use-auto"

	    # Things we need to do anyway.#
		"cppcoreguidelines-pro-type-reinterpret-cast"
		"modernize-avoid-c-arrays"
		"cppcoreguidelines-avoid-c-arrays"
		"hicpp-avoid-c-arrays"
		"cppcoreguidelines-pro-bounds-pointer-arithmetic"
		
		# Things that really aren't worth doing.
		#
		"hicpp-special-member-functions"
		"cppcoreguidelines-special-member-functions"
		"cppcoreguidelines-pro-bounds-constant-array-index"
		"cppcoreguidelines-pro-type-vararg"

		# these ones are just temporarily disabled and CAN be actually fixed
		#
        #"readability-convert-member-functions-to-static"
        #"cppcoreguidelines-pro-type-reinterpret-cast"
        #"cppcoreguidelines-pro-type-cstyle-cast"
        #"modernize-use-equals-default"
        #"hicpp-use-equals-default"
        #"llvm-include-order"
        #"google-readability-casting"
        #"google-readability-todo"
        #"readability-implicit-bool-conversion"
        #"cppcoreguidelines-pro-bounds-array-to-pointer-decay"
        #"hicpp-no-array-decay"
        #"modernize-use-bool-literals"
        #"modernize-loop-convert"
        #"readability-redundant-control-flow"
        #"google-readability-avoid-underscore-in-googletest-name"
        #"clang-analyzer-core.CallAndMessage"
        "hicpp-vararg"
        #"modernize-redundant-void-arg"
        "misc-non-private-member-variables-in-classes"
        #"hicpp-member-init"
        #"cppcoreguidelines-pro-type-member-init"
        #"readability-redundant-declaration"
		"llvm-qualified-auto"
		"readability-qualified-auto"
		"performance-unnecessary-value-param"
		#"readability-isolate-declaration"
		"cppcoreguidelines-macro-usage"
		#"readability-inconsistent-declaration-parameter-name"
		#"cppcoreguidelines-narrowing-conversions"
		#"bugprone-narrowing-conversions"
		#"readability-delete-null-pointer"
		#"readability-container-size-empty"
		#"llvm-namespace-comment"
		#"modernize-use-nullptr"
		#"performance-for-range-copy"
		#"readability-redundant-smartptr-get"
		#"hicpp-use-emplace"
		#"modernize-use-emplace"
		#"cert-msc50-cpp"
		#"cert-msc30-c"
		#"hicpp-use-override"
		#"modernize-use-override"
		#"cppcoreguidelines-explicit-virtual-functions"
		#"google-runtime-references"
		#"readability-else-after-return"
        PARENT_SCOPE)
endfunction()

########################################################################################################################

# private function that returns the full content of how the clang-tidy checks flag should look like
#
function (_private_get_clang_tidy_checks RESULT)
	set(RESULT_LOCAL "*")

	_private_get_clang_tidy_checks_whitelist(WHITELIST)
	foreach (EXCEPTION IN LISTS WHITELIST)
		string(APPEND RESULT_LOCAL ",-${EXCEPTION}")
	endforeach()

	set(${RESULT} ${RESULT_LOCAL} PARENT_SCOPE)
endfunction()

########################################################################################################################

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
	list(APPEND CLANG_TIDY "--warnings-as-errors=*")

	set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY}" PARENT_SCOPE)
	set(CMAKE_C_CLANG_TIDY "${CLANG_TIDY}" PARENT_SCOPE)
endfunction()

########################################################################################################################
