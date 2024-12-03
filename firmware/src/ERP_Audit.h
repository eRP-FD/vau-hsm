/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2024
 * (C) Copyright IBM Corp. 2021, 2024
 *
 * non-exclusively licensed to gematik GmbH
 *
 * Description: Audit log code for the IBM eRezept VAU HSM Custom firmware.
 **************************************************************************************************/

#ifndef ERP_AUDIT_H
#define ERP_AUDIT_H

#include "ERP_AuditIDs.h"

#define ERP_AUDIT_MAX_MESSAGE 200

// Generic handler for an ERP Error code, including E_ERP_SUCCESS
// Will call auditErrWithID
unsigned int auditErr(unsigned int err);
// Handler for an error code for a particular event
// will call auditErrWithIDAndMessage
unsigned int auditErrWithID(unsigned int err, ERP_AuditID_t id);
// Handler for an error code for a particular event with extra message detail.
unsigned int auditErrWithIDAndMessage(unsigned int err, ERP_AuditID_t id, const char* message);


#endif
