
find_package(csxapi REQUIRED)
find_package(asn1c REQUIRED)

# list its source files
#
set(SOURCE_FILES "ERP_ASNUtils.c"
                 "ERP_Client.c"
                 "ERP_Utils.c")

# list its public API header files
#
set(PUBLIC_HEADERS "ERP_Client.h"
                   "ERP_Error.h")

# list ASN1 files that the target depends on
#
set(ASN1_FILES "ERP_Types.asn1")

add_library(hsmclient ${LIBRARY_TARGET_TYPE} ${SOURCE_FILES})
target_compile_definitions(hsmclient
    PRIVATE $<IF:$<BOOL:${VERBOSE}>,ASN_EMIT_DEBUG=1 TRACE_HSM_API,ASN_EMIT_DEBUG=0>
)
set_property(TARGET hsmclient PROPERTY POSITION_INDEPENDENT_CODE ON)
if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set_target_properties(hsmclient PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS TRUE)
endif()

target_link_libraries(hsmclient PRIVATE csxapi::csxapi asn1c::asn1c)

# generate ASN1 sources and add them to the target
#
add_asn1_support(hsmclient "${ASN1_FILES}")

# install the target
#
install_target(hsmclient "${PUBLIC_HEADERS}")

########################################################################################################################
