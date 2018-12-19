#include "utils.h"

/*
        Converts the given number of bits to bytes
 */
int bits_to_bytes(int num_bits) {
	return (num_bits) / 8;
}

/*
        Will print the provided bytes in hex format
 */
void print_bytes(unsigned char * arr, int len) {

	for (int i = 0; i < len; i = i + 1) {
		printf("%02x", arr[i]);
	}

	printf("\n");
}

/*
        Will print the openssl BIGNUM in hex format
 */
void print_bn(BIGNUM * num) {
	char * hex = BN_bn2hex(num);
	printf("%s\n", hex);
}

/* Will reverse the provided buffer in-place */
void reverse_bytes(unsigned char * buffer, size_t buffer_size) {
	int start = 0;
	int end = buffer_size - 1;
	unsigned char tmp;

	while (start < end) {
		tmp = buffer[start];
		buffer[start] = buffer[end];
		buffer[end] = tmp;

		start = start + 1;
		end = end - 1;
	}
}
