#define BITS_OF_SECURITY 256
#define BYTES_OF_SECURITY (BITS_OF_SECURITY / 8)
// The curve id for secp256k1. A list of curve ids can be obtained from
// ' openssl ecparam -list_curves '
#define CURVE_ID 714

typedef struct privatekey {
	int key_size;
	unsigned char key[BYTES_OF_SECURITY];
} PrivateKey;

typedef struct publickey {
	unsigned char compressed;
	int key_size;
	unsigned char * key;
} PublicKey;

void set_private_key(PrivateKey * key, unsigned char * priv);
PrivateKey * gen_priv_key();
PublicKey * init_new_pubkey(int compressed, unsigned char * pub_key, int pub_key_size);
int get_pubkey_from_privkey(PrivateKey * priv_key, PublicKey * ret);