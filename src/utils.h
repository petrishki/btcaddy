#include <stdio.h>
#include <openssl/bn.h>

int bits_to_bytes(int num_bits);
void print_bytes(unsigned char * arr, int len);
void print_bn(BIGNUM * num);
void reverse_bytes(unsigned char * buffer, size_t buffer_size);