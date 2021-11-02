#ifndef ERP_UTILS_H_
#define ERP_UTILS_H_

// Writes binary array input into null terminated, non deliminated hex in output buffer,
// Output buffer must be at least InputBuffer + 1 long.
extern void bin2hex(unsigned char* input, unsigned int inputLength, char* output);

#endif
