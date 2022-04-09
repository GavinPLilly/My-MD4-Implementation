#include <stdint.h>
/* MD4.H - header file for MD4C.C */

// Main data struct for MD4 hash operation
typedef struct {
	uint32_t state[4];		// state (ABCD)
	uint32_t count[2];		// # of bits, modulo 2^64 (lsb first)
	unsigned char buffer[64];	// input buffer
} MD4_t;

void MD4Init(MD4_t *context);
void MD4Update(MD4_t *context, unsigned char *input, unsigned int input_len);
void MD4Final(unsigned char digest[16], MD4_t *context);
