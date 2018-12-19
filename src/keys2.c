#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include "keys.h"
#include "utils.h"

/*
        set_private_key will set the PrivateKey to the provided bytes
 */
void set_private_key(PrivateKey * key, unsigned char * priv) {
	memcpy(key->key, priv, key->key_size);
}

/*
        gen_priv_key will generate a new, random private key
 */
PrivateKey * gen_priv_key() {
	PrivateKey * key = malloc(sizeof(PrivateKey));
	key->key_size = BYTES_OF_SECURITY;

	// RAND_bytes is a cryptographic secure random number generator from openssl
	if (!RAND_bytes(key->key, key->key_size)) {
		printf("Error code: %lu\n",ERR_get_error());
		return NULL;
	}

	return key;
}

/*
        init_new_pubkey will create a new PublicKey with the provided pub_key bytes
        if pub_key is not null. Otherwise, the bytes are set to 0's
 */
PublicKey * init_new_pubkey(int compressed, unsigned char * pub_key, int pub_key_size) {
	PublicKey * key = malloc(sizeof(PublicKey));

	int size = 0;

	if (!compressed) {
		// a 0x04 prefix so we need an extra byte
		size = (bits_to_bytes(BITS_OF_SECURITY) * 2) + 1;
	} else {
		// Since its compressed only the x value (32 bytes) is stored and an extra byte is added to solve for y
		size = (bits_to_bytes(BITS_OF_SECURITY)) + 1;
	}

	key->key = malloc(size);
	key->key_size = size;

	if (!pub_key) {
		memset(key->key, 0, size);
	} else {
		if (pub_key_size != size) {
			free(key->key);
			free(key);
			return NULL;
		}

		memcpy(key->key, pub_key, size);
	}

	key->compressed = compressed;
	return key;
}

/*
        get_pubkey_from_privkey will write the public key corresponding to the provided
        private key to ret.
 */
int get_pubkey_from_privkey(PrivateKey * priv_key, PublicKey * ret) {
	/*
	        See http://cs.ucsb.edu/~koc/ccs130h/notes/ecdsa-cert.pdf section 6.1
	        for more details
	 */

	// will hold our private key as BIGNUM
	BIGNUM * priv;
	// Get the EC_GROUP by name of curve
	EC_GROUP * group = EC_GROUP_new_by_curve_name(CURVE_ID);
	// will hold our public key as an EC_POINT
	EC_POINT * pub_key = EC_POINT_new(group);
	// will hold our generator as an EC_POINT
	const EC_POINT * generator = EC_GROUP_get0_generator(group);
	// See https://www.openssl.org/docs/manmaster/crypto/EC_GROUP_copy.html for more information
	// between compressed and uncompressed
	int conversion_type = POINT_CONVERSION_UNCOMPRESSED;

	if (!priv_key) {
		return 0;
	}

	// convert our private key as a BIGNUM
	priv = BN_bin2bn(priv_key->key, bits_to_bytes(BITS_OF_SECURITY), NULL);

	/*
	        Multiples our generator and our private key and stores result in pub_key.
	 */
	if (!EC_POINT_mul(group, pub_key, NULL, generator, priv, NULL)) {
		return 0;
	}

	if (ret->compressed) {
		conversion_type = POINT_CONVERSION_COMPRESSED;
	}

	if (ret->key_size != EC_POINT_point2oct(group, pub_key, conversion_type, ret->key, ret->key_size, NULL)) {
		return 0;
	}


	BN_free(priv);
	EC_GROUP_free((EC_GROUP *)group);
	EC_POINT_free(pub_key);

	return 1;
}