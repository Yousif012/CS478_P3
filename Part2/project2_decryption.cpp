#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <openssl/rsa.h>
#include <openssl/pem.h>

using namespace std;


// Function to verify signature with RSA public key
bool verify_signature(const std::string& signature_content, const std::string& file_content,  RSA* public_key) {
    EVP_PKEY* evp_public_key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp_public_key, public_key);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_VerifyInit(ctx, EVP_sha256());
    EVP_VerifyUpdate(ctx, file_content.c_str(), file_content.size());

    int result = EVP_VerifyFinal(ctx, (const unsigned char*)signature_content.c_str(), signature_content.size(), evp_public_key);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(evp_public_key);

    return (result == 1);
}

// Function to verify signature with RSA public key
string rsa_verify(const string &sig, const string &content, EVP_PKEY *public_key)
{
    // Initialize the EVP_MD_CTX structure
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
    {
        // Handle error
        printf("EVP_MD_CTX_create failed\n");
        return "";
    }

    // Initialize the signing operation with the SHA-256 digest algorithm
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, public_key) != 1)
    {
        // Handle error
        EVP_MD_CTX_free(md_ctx);
        printf("EVP_DigestVerifyInit failed\n");
        return "";
    }

    // Perform the signing operation
    if (EVP_DigestVerifyUpdate(md_ctx, content.c_str(), content.length()) != 1)
    {
        // Handle error
        EVP_MD_CTX_free(md_ctx);
        printf("EVP_DigestSignUpdate failed\n");
        return "";
    }

    // Perform the final signing operation
    int rc = EVP_DigestVerifyFinal(md_ctx, (const unsigned char*)sig.c_str(), sig.length());
    if (rc != 1)
    {
        // Handle error
        EVP_MD_CTX_free(md_ctx);
        printf("EVP_DigestVerifyFinal failed\n");
        return "";
    }

    // Convert the signature to a string
    return sig;
}


EVP_PKEY* rsa_to_evp_pkey(RSA* rsa_key) {
    if (!rsa_key) {
        // Handle error
        return nullptr;
    }

    EVP_PKEY* evp_pkey = EVP_PKEY_new();
    if (!evp_pkey) {
        // Handle error
        return nullptr;
    }

    if (EVP_PKEY_assign_RSA(evp_pkey, rsa_key) != 1) {
        // Handle error
        EVP_PKEY_free(evp_pkey);
        return nullptr;
    }

    return evp_pkey;
}


// Function to decrypt content using symmetric key
string symmetric_decrypt(const string &ciphertext, const string &symmetric_key)
{

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        // Handle error
        printf("EVP_CIPHER_CTX_new failed\n");
        return "";
    }

    // Initialize the decryption operation with AES-256 CBC mode
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char *)symmetric_key.c_str(), NULL) != 1)
    {
        // Handle error
        printf("EVP_DecryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // Allocate memory for the plaintext (plaintext + AES block size)
    int plaintext_len = ciphertext.length() + EVP_CIPHER_block_size(EVP_aes_256_cbc());
    unsigned char *plaintext = (unsigned char *)malloc(plaintext_len);
    if (!plaintext)
    {
        // Handle error
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    int len;
    int plaintext_actual_len;

    // Perform the decryption
    if (EVP_DecryptUpdate(ctx, plaintext, &len, (const unsigned char *)ciphertext.c_str(), ciphertext.length()) != 1)
    {
        // Handle error
        printf("EVP_DecryptUpdate failed\n");
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_actual_len = len;


    // Finalize the decryption
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
    {
        // Handle error
        printf("EVP_DecryptFinal_ex failed\n");
        cout << plaintext << endl;
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_actual_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Convert the plaintext to a string
    string decrypted_text(reinterpret_cast<const char *>(plaintext), plaintext_actual_len);

    // Free memory
    free(plaintext);

    return decrypted_text;
}


int main(int argc, char* argv[]) {
    if (argc != 4) {
        cerr << "Usage: " << argv[0] << " <encrypted_file> <public_key_file> <symmetric_key_file>\n";
        return 1;
    }

    string encrypted_file = argv[1];
    string public_key_file = argv[2];
    string symmetric_key_file = argv[3];

    // Read the symmetric key from the file
    ifstream symmetric_key_stream(symmetric_key_file);
    string symmetric_key;
    if (!symmetric_key_stream) {
        cerr << "Error: Failed to open symmetric key file.\n";
        return 1;
    }
    getline(symmetric_key_stream, symmetric_key);


    // Read the public key for signature verification
    FILE* public_key_fp = fopen(public_key_file.c_str(), "r");
    if (!public_key_fp) {
        cerr << "Error: Failed to open public key file.\n";
        return 1;
    }
    RSA* public_key = PEM_read_RSA_PUBKEY(public_key_fp, NULL, NULL, NULL);
    fclose(public_key_fp);
    if (!public_key) {
        cerr << "Error: Failed to read public key from file.\n";
        return 1;
    }

    // Get encrypted text
    ifstream encrypted_stream(encrypted_file);
    stringstream encrypted_buffer;
    encrypted_buffer << encrypted_stream.rdbuf();
    string encrypted_content = encrypted_buffer.str();

    cout << "RSA Size: " << RSA_size(public_key) << endl;

    // Verify the signature
    string signature_content = encrypted_content.substr(encrypted_content.length() - RSA_size(public_key));
    string file_content = encrypted_content.substr(0, encrypted_content.length() - RSA_size(public_key));
    EVP_PKEY* public_key_evp = rsa_to_evp_pkey(public_key);
    string signature_verified = rsa_verify(signature_content, file_content, public_key_evp);
    RSA_free(public_key);

    // Decrypt the encrypted file using the symmetric key
    cout << "Encrypted Message: " << endl << file_content << endl;

    string decrypted_content = symmetric_decrypt(file_content, symmetric_key);

    cout << "Decrypted Message: " << endl << decrypted_content << endl;

    // Write the decrypted content to a plaintext file
    ofstream plaintext_file("decrypted.txt");
    if (!plaintext_file) {
        cerr << "Error: Failed to create plaintext file.\n";
        return 1;
    }
    plaintext_file << signature_verified;
    plaintext_file.close();

    cout << "Decryption and signature verification successful. Decrypted content saved to decrypted.txt.\n";

    return 0;
}
