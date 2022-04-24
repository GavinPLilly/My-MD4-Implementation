#include <stdint.h>
#include <string>

class MD4 {
	public:
		MD4();
		void update(unsigned char *input, unsigned int input_len);
		std::string finalize();

	private:
		// MD4 Context
		uint32_t state[4];		// state ABCD
		uint32_t count[2];		// # of bits, modulo 2^64 (lsb first)
		unsigned char buffer[64];	// input buffer

		// High level MD4 mixing function
		void transform();
};

// MD4 internal mixing functions
inline uint32_t circle_rotate_left(uint32_t x, uint32_t n) { return (x << n) | (x >> (32 - n)); }
inline uint32_t f(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
inline uint32_t g(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (x & z) | (y & z); }
inline uint32_t h(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
inline uint32_t ff(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s) { return circle_rotate_left((a + f(b, c, d) + x), s); }
inline uint32_t gg(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s) { return circle_rotate_left((a + g(b, c, d) + x + 0x5A827999), s); }
inline uint32_t hh(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s) { return circle_rotate_left((a + h(b, c, d) + x + 0x6ED9EBA1), s); }

// Other helper functions
std::string digest_to_string(unsigned char digest[16]);

// Changes endianess
void encode(unsigned char *output, uint32_t *input, unsigned int len);
void decode(uint32_t *output, unsigned char *input, unsigned int len);

