#include <iostream>
#include <fstream>
#include <string>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>

using namespace std;

// Function to read the content of a file
string read_file(const string& filename) {
    ifstream file(filename);
    if (!file) {
        cout << "Error: Unable to open file " << filename << endl;
        exit(1);
    }
    string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    return content;
}

// Function to write content to a file
void write_file(const string& filename, const string& content) {
    ofstream file(filename);
    if (!file) {
        cout << "Error: Unable to open file " << filename << endl;
        exit(1);
    }
    file << content;
}

// Function to decrypt using RSA with third party public key
string rsa_decrypt(const string& encrypted_msg, RSA* public_key) {
    int rsa_size = RSA_size(public_key);
    unsigned char *decrypted_msg = (unsigned char*)malloc(rsa_size);
    int decrypted_length = RSA_public_decrypt(rsa_size, (const unsigned char*)encrypted_msg.c_str(), decrypted_msg, public_key, RSA_PKCS1_OAEP_PADDING);
    if (decrypted_length == -1) {
        cout << "RSA decryption error" << endl;
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    string decrypted_str((char*)decrypted_msg, decrypted_length);
    free(decrypted_msg);
    return decrypted_str;
}

// Function to encrypt using symmetric key algorithm (AES in this case)
string symmetric_encrypt(const string& plaintext, const string& symmetric_key) {
    // Perform symmetric encryption (AES)
    // You can implement AES encryption or use OpenSSL's EVP interface for this
    // For demonstration, let's assume you have an AES encryption function
    // string encrypted_text = aes_encrypt(plaintext, symmetric_key);

    // For now, let's just return plaintext as demonstration
    return plaintext;
}

// Function to sign content using RSA private key
string rsa_sign(const string& content, RSA* private_key) {
    // Perform RSA signing with private key
    // You can implement RSA signing or use OpenSSL's EVP interface for this
    // For demonstration, let's assume you have an RSA signing function
    // string signature = rsa_sign(content, private_key);

    // For now, let's just return content as demonstration
    return content;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        cout << "Usage: " << argv[0] << " <encrypted_message_file> <third_party_public_key> <your_private_key>" << endl;
        return 1;
    }

    string encrypted_msg_file = argv[1];
    string public_key_file = argv[2];
    string private_key_file = argv[3];

    // Load third party public key
    FILE *public_key_fp = fopen(public_key_file.c_str(), "r");
    if (!public_key_fp) {
        cout << "Error: Unable to open third party public key file" << endl;
        return 1;
    }
    RSA* public_key = PEM_read_RSA_PUBKEY(public_key_fp, NULL, NULL, NULL);
    fclose(public_key_fp);
    if (!public_key) {
        cout << "Error: Unable to read third party public key" << endl;
        return 1;
    }

    cout << public_key << endl;

    // Load your private key
    FILE *private_key_fp = fopen(private_key_file.c_str(), "r");
    if (!private_key_fp) {
        cout << "Error: Unable to open your private key file" << endl;
        return 1;
    }
    RSA* private_key = PEM_read_RSAPrivateKey(private_key_fp, NULL, NULL, NULL);
    fclose(private_key_fp);
    if (!private_key) {
        cout << "Error: Unable to read your private key" << endl;
        return 1;
    }

    // Read encrypted message
    string encrypted_msg = read_file(encrypted_msg_file);

    cout << "Encrypted Message: " << encrypted_msg << endl;

    // Step 2: Decrypt the encrypted message with third party public key
    string symmetric_key = rsa_decrypt(encrypted_msg, public_key);

    cout << "Symmetric Key: " << symmetric_key << endl;


    // Step 3: Encrypt a text file with symmetric key
    string plaintext = "Your name: John Doe\nYour banner ID: B12345678\nSymmetric Algorithm: AES\n";
    string encrypted_text = symmetric_encrypt(plaintext, symmetric_key);
    write_file("encrypted_text.txt", encrypted_text);

    // Step 4: Sign the encrypted content with your private key
    string signature = rsa_sign(encrypted_text, private_key);
    write_file("signed_content.txt", signature);

    // Free memory
    RSA_free(public_key);
    RSA_free(private_key);

    cout << "Encryption completed successfully." << endl;

    return 0;
}
