OPENSSL_INCLUDE = /usr/local/include
OPENSSL_LIB = /usr/local/lib

btcaddy : src/utils.c src/hash.c src/base58.c src/keys.c src/generator.c
	gcc -o bin/btcaddy -I $(OPENSSL_INCLUDE) -L $(OPENSSL_LIB) src/utils.c src/hash.c src/base58.c src/keys.c src/generator.c -lcrypto -lssl

clean :
	rm -rf bin/btcaddy 
