#ifndef __ERP_AUDIT_H
#define __ERP_AUDIT_H
// Header file for Audit code for IBM eRezept VAU HSM Firmware.

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
