/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2023
 * (C) Copyright IBM Corp. 2021, 2023
 *
 * non-exclusively licensed to gematik GmbH
 **************************************************************************************************/

#ifndef ERP_UTILS_H_
#define ERP_UTILS_H_

// Writes binary array input into null terminated, non deliminated hex in output buffer,
// Output buffer must be at least InputBuffer + 1 long.
extern void bin2hex(unsigned char* input, unsigned int inputLength, char* output);

#endif
