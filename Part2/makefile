CC = g++
CFLAGS = -Wall -O2 -std=c++11
LDFLAGS = -lssl -lcrypto

ENCRYPT_TARGET = encrypt
DECRYPT_TARGET = decrypt

all: $(ENCRYPT_TARGET) $(DECRYPT_TARGET)

$(ENCRYPT_TARGET): project2_encryption.cpp
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(DECRYPT_TARGET): project2_decryption.cpp
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(ENCRYPT_TARGET) $(DECRYPT_TARGET)
