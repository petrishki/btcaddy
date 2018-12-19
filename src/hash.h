#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

int sha256(unsigned char * to_hash, size_t to_hash_len, unsigned char * digest, size_t * digest_len);
int ripemd160(unsigned char * to_hash, size_t to_hash_len, unsigned char * digest, size_t * digest_len);