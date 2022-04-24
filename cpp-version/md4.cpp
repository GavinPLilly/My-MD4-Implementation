#include "md4.h"
#include <cstring>

unsigned char PADDING [64] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * Sets MD4 context to starting defaults
 */
MD4::MD4() {
	state[0] = 0x67452301;
	state[1] = 0xEFCDAB89;
	state[2] = 0x98BADCFE;
	state[3] = 0x10325476;

	count[0] = 0;
	count[1] = 0;
}

/*
 * Continues an MD4 message-digest operation.
 * @params:
 * 	input: input to be processed
 * 	input_len: length of input to be processed
 */
void MD4::update(unsigned char *input, unsigned int input_len) {
	uint32_t buf_fill;
	uint32_t input_index; // How much of the input has been processed

	// Compte how full buffer is
	buf_fill = static_cast<uint32_t>((count[0] >> 3) & 0x3F);

	// Update bit count
	count[0] += input_len << 3;
	if(count[0] < input_len << 3) { // check for overflow
		count[1]++;
	}
	count[1] += static_cast<uint32_t>(input_len >> 29); // shift of 32 minus the 3 already done

	// Try to fill buffer from input
	input_index = std::min(64 - buf_fill, input_len);
	memcpy(&buffer[buf_fill], input, input_index);
	buf_fill += input_index;
	input_len -= input_index;

	if(buf_fill == 64) {
		transform();
		while(input_len >= 64) {
			memcpy(buffer, &input[input_index], input_len);
			transform();
			input_index += 64;
			input_len -= 64;
		}
		memcpy(buffer, &input[input_index], input_len); // buffer remaining input
	}
}

/*
 * Finishes the MD4 hashing by appending correct padding and applying a final transform
 * Clears the internal state
 * @returns:
 * 	A printable string of the message digest
 */
std::string MD4::finalize() {
	unsigned char bits[8];
	unsigned int index;
	unsigned int pad_len;
	unsigned char digest[16];

	// Save number of bits
	encode(bits, count, 2);

	// Pad out to 56 mod 64
	index = static_cast<uint32_t>((count[0] >> 3) & 0x3F);
	pad_len = (index < 56) ? (56 - index) : (120 - index);

	// Run last transform with padding and length appended
	update(PADDING, pad_len);
	update(bits, 8);
	encode(digest, state, 4);

	return digest_to_string(digest);
}

/*
 * MD4 basic transformation. Transforms state bases on MD4::buffer
 * Expects that MD4::buffer has been filled
 */
void MD4::transform() {
	uint32_t a = state[0];
	uint32_t b = state[1];
	uint32_t c = state[2];
	uint32_t d = state[3];

	uint32_t x[16];

	decode(x, buffer, 16);

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
	memset(x, 0, sizeof(x));
}

/* Take a 16 byte array and produces a readable string
 * @params:
 * 	digest: the final encoded MD4 state
 * @returns:
 * 	Reable string version of final encoded MD4 state
 */
std::string digest_to_string(unsigned char digest[16]) {
	for(unsigned int i = 0; i < 16; i++) {
		printf("%02X", digest[i]);
	}
	printf("\n");

	std::string result;
	char c[3];
	for(unsigned int i = 0; i < 16; i++) {
		sprintf(&c[0], "%02X", digest[i]);
		// printf("%c%c\n", c[0], c[1]);
		result += c[0];
		result += c[1];
	}
	return result;
}

/*
 * Takes uint32_t's from normal byte order to MD4 byte order
 * @params:
 * 	output: char array to write to
 * 	input: uint32_t array to decode from
 * 	len: how many uint32_t's to encode
 */
void encode(unsigned char *output, uint32_t *input, unsigned int len) {
	for(unsigned int i = 0, j = 0; i < len; i++, j += 4) {
		output[j    ] = (unsigned char)(input[i] & 0xFF);
		output[j + 1] = (unsigned char)((input[i] >> 8 ) & 0xFF);
		output[j + 2] = (unsigned char)((input[i] >> 16) & 0xFF);
		output[j + 3] = (unsigned char)((input[i] >> 24) & 0xFF);
	}
}

/*
 * Takes a char array and rearranged the bytes to work with uint32_t's
 * @params:
 * 	output: uint32_t array to write to
 * 	input: char array to encode from
 * 	len: how many uint32_t's to encod
 */
void decode(uint32_t *output, unsigned char *input, unsigned int len) {
	for(unsigned int i = 0, j = 0; i < len; i++, j += 4) {
		output[i] = ((uint32_t)input[j])
			| (((uint32_t)input[j + 1]) << 8)
			| (((uint32_t)input[j + 2]) << 16)
			| (((uint32_t)input[j + 3]) << 24);
	}
}
