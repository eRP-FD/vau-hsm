# (C) Copyright IBM Deutschland GmbH 2021, 2023
# (C) Copyright IBM Corp. 2021, 2023
#
# non-exclusively licensed to gematik GmbH

########################################################################################################################

########################
# target configuration #
########################

set(TARGET_NAME ERP)

add_library(${TARGET_NAME} SHARED ERP_Audit.c
                                  ERP_ASNUtils.c
                                  ERP_Blob.c
                                  ERP_CryptoUtils.c
                                  ERP_ExternalAPI.c
                                  ERP_GlobalGlue.c
                                  ERP_InternalGlue.c)

configure_target(${TARGET_NAME})

deploy_target_as_firmware(${TARGET_NAME})

########################################################################################################################
