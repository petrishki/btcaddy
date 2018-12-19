OPENSSL_INCLUDE_PATH = /usr/local/include
OPENSSL_LIB_PATH = /usr/local/lib

btcaddy : src/utils.c src/hash.c src/base58.c src/keys.c src/generator.c
	gcc -o bin/btcaddy -I $(OPENSSL_INCLUDE_PATH) -L $(OPENSSL_LIB_PATH) src/utils.c src/hash.c src/base58.c src/keys.c src/generator.c -lcrypto -lssl

clean :
	rm -rf bin/btcaddy 
