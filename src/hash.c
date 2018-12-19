#include "hash.h"

// Computes the hash of to_hash (which is to_hash_len bytes long) using the hash_algo provided.
// The resulting hash is stored in digest which is digest_len bytes long. digest_len must be initalized to the length of digest
// The resulting length of the hash will be stored in digest_len
// Returns 1 on success else 0
int _do_hash(const EVP_MD * hash_algo, unsigned char * to_hash, size_t to_hash_len, unsigned char * digest, size_t * digest_len) {

	// make a buffer of the largest size a digest can be
	unsigned char buffer[EVP_MAX_MD_SIZE];
	// this will hold the acutal size of the digest (hash) in bytes
	unsigned int actual_digest_len;

	EVP_MD_CTX * ctx = EVP_MD_CTX_new(); // get a new digest context

	if (!EVP_DigestInit(ctx,hash_algo) || !EVP_DigestUpdate(ctx,(void *) to_hash, to_hash_len) ||
	    !EVP_DigestFinal(ctx, buffer, &actual_digest_len)) {

		EVP_MD_CTX_free(ctx);
		return 0;
	}

	if (*digest_len < actual_digest_len) {
		EVP_MD_CTX_free(ctx);
		return 0;
	}

	memcpy(digest, buffer, actual_digest_len);
	*digest_len = actual_digest_len;
	EVP_MD_CTX_free(ctx);

	return 1;

}

// Calls _do_hash but does some checks to make sure the sizes of the digest and result are correct.
// Checks to make sure digest is big enough and the resulting hash is the correct size.
int _complete_hash(const EVP_MD * hash_algo, unsigned char * to_hash, size_t to_hash_len, unsigned char * digest, size_t * digest_len, size_t hash_size) {
	int ok = 0;

	if (*digest_len < hash_size) {
		return 0;
	}

	ok = _do_hash(hash_algo, to_hash, to_hash_len, digest, digest_len);

	if (*digest_len != hash_size || !ok) {
		return 0;
	}

	return 1;
}

// uses _do_hash to compute the hash of to_hash. The result is stored in digest and the hash len is stored in digest_len.
// digest_len must be initialized as the length of digest.
int sha256(unsigned char * to_hash, size_t to_hash_len, unsigned char * digest, size_t * digest_len) {
	return _complete_hash(EVP_sha256(), to_hash, to_hash_len, digest, digest_len, 32);
}

// uses _do_hash to compute the hash of to_hash. The result is stored in digest and the hash len is stored in digest_len.
// digest_len must be initialized as the length of digest.
int ripemd160(unsigned char * to_hash, size_t to_hash_len, unsigned char * digest, size_t * digest_len) {
	return _complete_hash(EVP_ripemd160(), to_hash, to_hash_len, digest, digest_len, 20);
}
