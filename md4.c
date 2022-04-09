#include <stdint.h>
#include <string.h>
#include "md4.h"

/* NOTES
 * Byte is 8  bits, left most bit = msb, right most bit = lsb
 * Word is 32 bits, broken into 4 bytes, left most byte = lsB, right most byte = msB
 *
 */

static unsigned char PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static void MD4Transform(uint32_t state[4], unsigned char block[64]);
static void Encode(char *output, uint32_t *input, unsigned int len);
static void Decode(uint32_t *output, unsigned char *input, unsigned int len);

static inline uint32_t circle_rotate_left(uint32_t x, uint32_t n) {
	return (x << n) | (x >> (32 - n));
}
static inline uint32_t f(uint32_t x, uint32_t y, uint32_t z) {
	return (x & y) | (~x & z);
}
static inline uint32_t g(uint32_t x, uint32_t y, uint32_t z) {
	return (x & y) | (x & z) | (y & z);
}
static inline uint32_t h(uint32_t x, uint32_t y, uint32_t z) {
	return x ^ y ^ z;
}
static inline uint32_t ff(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s) {
	return circle_rotate_left((a + f(b, c, d) + x), s);
}
static inline uint32_t gg(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s) {
	return circle_rotate_left((a + g(b, c, d) + x + 0x5A827999), s);
}
static inline uint32_t hh(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s) {
	return circle_rotate_left((a + h(b, c, d) + x + 0x6ED9EBA1), s);
}

void MD4Init(MD4_t *context) {
	context->state[0] = 0x67452301;
	context->state[1] = 0xEFCDAB89;
	context->state[2] = 0x98BADCFE;
	context->state[3] = 0x10325476;

	context->count[0] = 0;
	context->count[1] = 0;
}

// Process 16 word blocks (128 bits)
void MD4Update(MD4_t *context, unsigned char *input, uint32_t input_len) {
	uint32_t i; // Loop counter
	uint32_t index; // number of bytes mod 64
	uint32_t part_len; //

	// Compute the number of bytes
	index = (uint32_t)((context->count[0] >> 3) & 0x3F);
	// Update number of bits
	context->count[0] += input_len << 3;
	if(context->count[0] < input_len << 3) { // Check for overflow
		context->count[1]++;
	}
	context->count[1] += ((uint32_t)input_len >> 29); // shift of 32 minus the 3 already done
	part_len = 64 - index;
	// Transform repeatedly
	if(input_len >= part_len) {
		memcpy(&context->buffer[index], input, part_len);
		MD4Transform(context->state, context->buffer);

		for(i = part_len; i + 63 < input_len; i += 64) {
			MD4Transform(context->state, &input[i]);
		}
		index = 0;
	}
	else {
		i = 0;
	}
	// Buffer remaining input
	memcpy(&context->buffer[index], &input[i], input_len - i);
}

void MD4Final(unsigned char digest[16], MD4_t *context) {
	unsigned char bits[8];
	unsigned int index, pad_len;

	// Save number of bits
	Encode(bits, context->count, 2);
	// Pad out to 56 mod 64
	index = (uint32_t)((context->count[0] >> 3) & 0x3F);
	pad_len = (index < 56) ? (56 - index) : (120 - index);
	MD4Update(context, PADDING, pad_len);

	MD4Update(context, bits, 8);
	Encode(digest, context->state, 4);

	memset(context, 0, sizeof(*context));
}

/* MD4 basic transformation. Transforms state based on block */
static void MD4Transform(uint32_t state[4], unsigned char block[64]) {
	uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
	uint32_t x[16];

	Decode(x, block, 16);

	/* Round 1 */
	a = ff(a, b, c, d, x[ 0], 3); /* 1 */
	d = ff(d, a, b, c, x[ 1], 7); /* 2 */
	c = ff(c, d, a, b, x[ 2], 11); /* 3 */
	b = ff(b, c, d, a, x[ 3], 19); /* 4 */
	a = ff(a, b, c, d, x[ 4], 3); /* 5 */
	d = ff(d, a, b, c, x[ 5], 7); /* 6 */
	c = ff(c, d, a, b, x[ 6], 11); /* 7 */
	b = ff(b, c, d, a, x[ 7], 19); /* 8 */
	a = ff(a, b, c, d, x[ 8], 3); /* 9 */
	d = ff(d, a, b, c, x[ 9], 7); /* 10 */
	c = ff(c, d, a, b, x[10], 11); /* 11 */
	b = ff(b, c, d, a, x[11], 19); /* 12 */
	a = ff(a, b, c, d, x[12], 3); /* 13 */
	d = ff(d, a, b, c, x[13], 7); /* 14 */
	c = ff(c, d, a, b, x[14], 11); /* 15 */
	b = ff(b, c, d, a, x[15], 19); /* 16 */

	/* Round 2 */
	a = gg(a, b, c, d, x[ 0], 3); /* 17 */
	d = gg(d, a, b, c, x[ 4], 5); /* 18 */
	c = gg(c, d, a, b, x[ 8], 9); /* 19 */
	b = gg(b, c, d, a, x[12], 13); /* 20 */
	a = gg(a, b, c, d, x[ 1], 3); /* 21 */
	d = gg(d, a, b, c, x[ 5], 5); /* 22 */
	c = gg(c, d, a, b, x[ 9], 9); /* 23 */
	b = gg(b, c, d, a, x[13], 13); /* 24 */
	a = gg(a, b, c, d, x[ 2], 3); /* 25 */
	d = gg(d, a, b, c, x[ 6], 5); /* 26 */
	c = gg(c, d, a, b, x[10], 9); /* 27 */
	b = gg(b, c, d, a, x[14], 13); /* 28 */
	a = gg(a, b, c, d, x[ 3], 3); /* 29 */
	d = gg(d, a, b, c, x[ 7], 5); /* 30 */
	c = gg(c, d, a, b, x[11], 9); /* 31 */
	b = gg(b, c, d, a, x[15], 13); /* 32 */

	  /* Round 3 */
	a = hh(a, b, c, d, x[ 0], 3); /* 33 */
	d = hh(d, a, b, c, x[ 8], 9); /* 34 */
	c = hh(c, d, a, b, x[ 4], 11); /* 35 */
	b = hh(b, c, d, a, x[12], 15); /* 36 */
	a = hh(a, b, c, d, x[ 2], 3); /* 37 */
	d = hh(d, a, b, c, x[10], 9); /* 38 */
	c = hh(c, d, a, b, x[ 6], 11); /* 39 */
	b = hh(b, c, d, a, x[14], 15); /* 40 */
	a = hh(a, b, c, d, x[ 1], 3); /* 41 */
	d = hh(d, a, b, c, x[ 9], 9); /* 42 */
	c = hh(c, d, a, b, x[ 5], 11); /* 43 */
	b = hh(b, c, d, a, x[13], 15); /* 44 */
	a = hh(a, b, c, d, x[ 3], 3); /* 45 */
	d = hh(d, a, b, c, x[11], 9); /* 46 */
	c = hh(c, d, a, b, x[ 7], 11); /* 47 */
	b = hh(b, c, d, a, x[15], 15); /* 48 */

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;

	// Zeroize sensitive information.
	memset(x, 0, sizeof (x));
}

// Takes uint32_t's from normal bit order to md4 bit order
// len: how many uint32_t's are getting encoded
static void Encode(char *output, uint32_t *input, unsigned int len) {
	for(unsigned int i = 0, j = 0; i < len; i++, j += 4) {
		output[j    ] = (unsigned char)(input[i] & 0xFF);
		output[j + 1] = (unsigned char)((input[i] >> 8 ) & 0xFF);
		output[j + 2] = (unsigned char)((input[i] >> 16) & 0xFF);
		output[j + 3] = (unsigned char)((input[i] >> 24) & 0xFF);
	}
}

// Takes multiples of 4 chars in MD4 order and converts them into a uint_32
// len: how many uint32_t's are getting returned
static void Decode(uint32_t *output, unsigned char *input, unsigned int len) {
	for(unsigned int i = 0, j = 0; i < len; i++, j += 4) {
		output[i] = ((uint32_t)input[j])
			| (((uint32_t)input[j + 1]) << 8)
			| (((uint32_t)input[j + 2]) << 16)
			| (((uint32_t)input[j + 3]) << 24);
	}
}
