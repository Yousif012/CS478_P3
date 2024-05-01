# CS478 Programming Assignment 3

# RSA Encryption and Decryption Program

## Compilation
Compile the program using a C++ compiler.
```
make
```

## Running the Programs
### Encryption Program
To encrypt a message, run the encryption program with the following command:
```
./rsa_encryption symm_key.bin publickey.pem priv.pem
```

The encrypted message will be saved in a file named `signed_encrypted_text.txt`.

### Decryption Program
To decrypt a message, run the decryption program with the following command:
```
./rsa_decryption signed_encrypted_text.txt pub.pem symmetric.txt
```

The decrypted message will be saved in a file named `decrypted.txt`.
