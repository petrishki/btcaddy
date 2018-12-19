#include "base58.h"
#include "hash.h"
#include "utils.h"


const char base58_values[58] =
{
	'1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
	'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
	'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p',
	'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
};

// the base number (58) as bytes
const BN_ULONG BASE = 58;

char * base58_encode(unsigned char version_byte, unsigned char * payload, size_t payload_len) {
	// 1. concatenate the version_byte and the payload
	size_t buffer_size = payload_len+1+4;
	unsigned char * buffer = (unsigned char *)malloc(buffer_size);
	buffer[0] = version_byte;
	memcpy(buffer+1, payload, payload_len);

	// calculate the 4 byte checksum sha256(sha256(buffer))
	size_t hash_len = 32;
	unsigned char hash[hash_len];

	if (!sha256(buffer, payload_len+1, hash, &hash_len) || hash_len != 32) {
		free(buffer);
		return NULL;
	}

	if (!sha256(hash, 32, hash, &hash_len) || hash_len != 32) {
		free(buffer);
		return NULL;
	}

	// concatenate the 4 byte checksum to version_byte + payload
	for (int i = 4; i > 0; i = i - 1) {
		buffer[buffer_size - i] = hash[4-i];
	}

	// count how many zeros appear in front of buffer
	int zero_count;
	for (zero_count = 0; zero_count < buffer_size && buffer[zero_count] == 0x00; zero_count = zero_count + 1) {}

	// convert the buffer to a bignumber using openssl's bn
	BIGNUM * bignumTmp = BN_bin2bn(buffer, buffer_size, NULL);

	// first count the number of divisions it takes to get to 0.
	// TODO: can we optimize this by taking the log base 58?
	int output_size = 0;
	while (!BN_is_zero(bignumTmp)) {
		BN_div_word(bignumTmp, BASE);
		output_size = output_size + 1;
	}

	BIGNUM * bignum = BN_bin2bn(buffer, buffer_size, NULL);

	// next we can reallocate the buffer to be the appropriate size
	unsigned char * output = realloc(buffer, output_size+zero_count+1);
	int index_in_output = 0;
	if (!output) {
		BN_free(bignumTmp);
		free(buffer);
		return NULL;
	}

	BN_ULONG rem;
	while (!BN_is_zero(bignum)) {
		rem = BN_div_word(bignum, BASE);
		// add the remainder to an output buffer
		output[index_in_output] = base58_values[rem];
		index_in_output = index_in_output + 1;
	}

	// add '1' for the number of 0-bytes at the beginning of the original buffer
	memset(output+index_in_output, 0x31, zero_count);
	index_in_output = index_in_output + zero_count;

	// reverse the buffer
	reverse_bytes(output, index_in_output);

	// mark the end of the buffer with a null character
	output[index_in_output] = '\0';

	BN_free(bignumTmp);
	BN_free(bignum);

	return (char*)output;
}
