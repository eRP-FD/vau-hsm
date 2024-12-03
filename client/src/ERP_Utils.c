/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2024
 * (C) Copyright IBM Corp. 2021, 2024
 *
 * non-exclusively licensed to gematik GmbH
 **************************************************************************************************/

#include "ERP_Utils.h"

#include <stdio.h>

// Writes binary array input into null terminated, non deliminated hex in output buffer,
// Output buffer must be at least InputBuffer + 1 long.
void bin2hex(unsigned char* input, unsigned int inputLength, char* output)
{
    size_t i = 0;
    for (i = 0 ; i < inputLength; i++)
    {
        snprintf(&(output[2 * i]), (size_t) inputLength + 1 - 2 * i, "%02x", input[i]);
    }

    output[2 * i] = 0;
}
