#include <iostream>
#include <fstream>
#include <string>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>

using namespace std;

// Function to read the content of a file
string read_file(const string &filename)
{
    ifstream file(filename);
    if (!file)
    {
        cout << "Error: Unable to open file " << filename << endl;
        exit(1);
    }
    string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    return content;
}

// Function to write content to a file
void write_file(const string &filename, const string &content)
{
    ofstream file(filename);
    if (!file)
    {
        cout << "Error: Unable to open file " << filename << endl;
        exit(1);
    }
    file << content;
}

// Function to decrypt using RSA with third party public key
string rsa_decrypt(const string &encrypted_msg, RSA *public_key)
{
    int rsa_size = RSA_size(public_key);
    unsigned char *decrypted_msg = (unsigned char *)malloc(rsa_size);
    int decrypted_length = RSA_public_decrypt(rsa_size, (const unsigned char *)encrypted_msg.c_str(), decrypted_msg, public_key, RSA_NO_PADDING);
    if (decrypted_length == -1)
    {
        cout << "RSA decryption error" << endl;
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    string decrypted_str((char *)decrypted_msg, decrypted_length);
    free(decrypted_msg);
    return decrypted_str;
}

// Function to encrypt using symmetric key algorithm (AES in this case)
string symmetric_encrypt(const string &plaintext, const string &symmetric_key)
{
    // Initialize the cipher context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        // Handle error
        return "";
    }

    // Initialize the encryption operation with AES-256 CBC mode
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char *)symmetric_key.c_str(), NULL) != 1)
    {
        // Handle error
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // Allocate memory for the ciphertext (plaintext + AES block size)
    int ciphertext_len = plaintext.length() + EVP_CIPHER_block_size(EVP_aes_256_cbc());
    unsigned char *ciphertext = (unsigned char *)malloc(ciphertext_len);
    if (!ciphertext)
    {
        // Handle error
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    int len;
    int ciphertext_actual_len;

    // Perform the encryption
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char *)plaintext.c_str(), plaintext.length()) != 1)
    {
        // Handle error
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_actual_len = len;

    // Finalize the encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
    {
        // Handle error
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_actual_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Convert the ciphertext to a string
    string encrypted_text(reinterpret_cast<const char *>(ciphertext), ciphertext_actual_len);

    // Free memory
    free(ciphertext);

    return encrypted_text;
}

// Function to sign content using RSA private key
string rsa_sign(const string &content, EVP_PKEY *private_key)
{
    // Initialize the EVP_MD_CTX structure
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
    {
        // Handle error
        printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
        return "";
    }

    // Initialize the signing operation with the SHA-256 digest algorithm
    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, private_key) != 1)
    {
        // Handle error
        EVP_MD_CTX_free(md_ctx);
        printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
        return "";
    }

    // Perform the signing operation
    if (EVP_DigestSignUpdate(md_ctx, content.c_str(), content.length()) != 1)
    {
        // Handle error
        EVP_MD_CTX_free(md_ctx);
        printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
        return "";
    }

    // Get the length of the signature
    size_t sig_len;
    if (EVP_DigestSignFinal(md_ctx, NULL, &sig_len) != 1)
    {
        // Handle error
        EVP_MD_CTX_free(md_ctx);
        printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
        return "";
    }

    // Allocate memory for the signature
    unsigned char *sig = (unsigned char *)malloc(sig_len);
    if (!sig)
    {
        // Handle error
        EVP_MD_CTX_free(md_ctx);
        printf("OPENSSL_malloc failed, error 0x%lx\n", ERR_get_error());
        return "";
    }

    // Perform the final signing operation
    int rc = EVP_DigestSignFinal(md_ctx, sig, &sig_len);
    if (rc != 1)
    {
        // Handle error
        free(sig);
        EVP_MD_CTX_free(md_ctx);
        printf("EVP_DigestSignFinal failed (3), return code %d, error 0x%lx\n", rc, ERR_get_error());
        return "";
    }

    // Convert the signature to a string
    string signature(reinterpret_cast<const char *>(sig), sig_len);

    // Clean up
    free(sig);
    EVP_MD_CTX_free(md_ctx);

    return signature;
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


int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        cout << "Usage: " << argv[0] << " <encrypted_message_file> <third_party_public_key> <your_private_key>" << endl;
        return 1;
    }

    string encrypted_msg_file = argv[1];
    string public_key_file = argv[2];
    string private_key_file = argv[3];
    string passphrase = "Yosif123";

    // Load third party public key
    FILE *public_key_fp = fopen(public_key_file.c_str(), "r");
    if (!public_key_fp)
    {
        cout << "Error: Unable to open third party public key file" << endl;
        return 1;
    }
    RSA *public_key = PEM_read_RSA_PUBKEY(public_key_fp, NULL, NULL, NULL);
    fclose(public_key_fp);
    if (!public_key)
    {
        cout << "Error: Unable to read third party public key" << endl;
        return 1;
    }

    cout << public_key << endl;

    // Load your private key
    FILE *private_key_fp = fopen(private_key_file.c_str(), "r");
    if (!private_key_fp)
    {
        cout << "Error: Unable to open your private key file" << endl;
        return 1;
    }
    RSA *private_key = PEM_read_RSAPrivateKey(private_key_fp, NULL, NULL, NULL);
    EVP_PKEY* private_key_evp = rsa_to_evp_pkey(private_key);
    fclose(private_key_fp);
    if (!private_key)
    {
        cout << "Error: Unable to read your private key" << endl;
        return 1;
    }

    // Read encrypted message
    string encrypted_msg = read_file(encrypted_msg_file);

    // Step 2: Decrypt the encrypted message with third party public key
    string symmetric_key = rsa_decrypt(encrypted_msg, public_key);

    write_file("symmetric.txt", symmetric_key);

    // Step 3: Encrypt a text file with symmetric key
    string plaintext = "Yosif Yosif\nBanner ID: 800743159\nSymmetric Algorithm: AES\n";
    string encrypted_text = symmetric_encrypt(plaintext, symmetric_key);
    write_file("encrypted_text.txt", encrypted_text);

    cout << "Encrypted Text: " << encrypted_msg << endl;

    // Step 4: Sign the encrypted content with your private key
    string signature = rsa_sign(encrypted_text, private_key_evp);
    write_file("signature.txt", signature);

    // Free memory
    RSA_free(public_key);
    RSA_free(private_key);

    cout << "Signature: " << signature << endl;

    string signed_text = encrypted_msg + signature;

    cout << "Signed Content: " << signature << endl;

    cout << "Encryption completed successfully." << endl;

    return 0;
}
