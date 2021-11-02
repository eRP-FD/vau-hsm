# define the name of a new target
#
set(TARGET_NAME "hsmclient")

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

########################################################################################################################

# define and configure the target by specifying its name, type and list of source files
#
configure_target(${TARGET_NAME} "SHARED_LIBRARY" "${SOURCE_FILES}")

# generate ASN1 sources and add them to the target
#
add_asn1_support(${TARGET_NAME} "${ASN1_FILES}")

# install the target
#
install_target(${TARGET_NAME} "${PUBLIC_HEADERS}")

########################################################################################################################
