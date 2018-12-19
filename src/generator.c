#include <stdio.h>
#include "keys.h"
#include "utils.h"
#include "hash.h"
#include "base58.h"


int main() {

	PrivateKey * priv = gen_priv_key();
	PublicKey * test = init_new_pubkey(0,NULL,-1);

	get_pubkey_from_privkey(priv,test);

	printf("PrivateKey : \n");
	print_bytes(priv->key, priv->key_size);
	printf("PublicKey : \n");
	print_bytes(test->key, test->key_size);

	// calculate ripemd160(sha256(publickey))
	size_t size = 32;
	unsigned char hashed_key[size];
	if (!sha256(test->key, test->key_size, hashed_key, &size)) {
		printf("%s\n", "could not take sha256 hash of key");
		return 1;
	}

	if (!ripemd160(hashed_key, size, hashed_key, &size)) {
		printf("%s\n", "could not take ripemd160 hash of key");
		return 1;
	}

	char * bitcoin_address = base58_encode(0x00, hashed_key, size);
	if (bitcoin_address == NULL) {
		printf("%s\n", "could not take base58 encoding of key");
		return 1;
	}

	printf("Bitcoin Address: \n");
	printf("%s\n", bitcoin_address);

	// clear the private key in memory
	for (int i = 0; i < priv->key_size; i = i + 1) {
		priv->key[i] = 0x00;
	}

	free(priv);
	free(test->key);
	free(test);
	free(bitcoin_address);

	return 0;
}



