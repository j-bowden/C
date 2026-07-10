#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>


// this program implements a CBC block cipher as per challenge 10, set 2 of the cryptopals challenges.


// auxiliary function: base64 to raw bytes
std::vector<unsigned char> decode_base64(const std::string& input) {
    BIO* b64 = BIO_new(BIO_f_base64());
    // BIO_FLAGS_BASE64_NO_NL ensures it parses lines even if they have weird spacing
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO* bmem = BIO_new_mem_buf(input.data(), static_cast<int>(input.length()));
    b64 = BIO_push(b64, bmem);

    std::vector<unsigned char> output(input.length());
    int decoded_size = BIO_read(b64, output.data(), static_cast<int>(output.size()));

    BIO_free_all(b64);
    if (decoded_size < 0) return {};
    output.resize(decoded_size);
    return output;
}


// auxiliary function: raw bytes to base64
std::string encode_base64(const std::vector<uint8_t>& input) {
    BIO* b64 = BIO_new(BIO_f_base64());
    // BIO_FLAGS_BASE64_NO_NL keeps the encoded string on a single line without newlines
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);

    // write raw bytes to OpenSSL BIO stream
    BIO_write(b64, input.data(), static_cast<int>(input.size()));
    BIO_flush(b64);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);

    // construct final string
    std::string output(bptr->data, bptr->length);
    BIO_free_all(b64);

    return output;
}


// auxiliary function: encrypt by AES in ECB mode, on raw bytes
std::vector<unsigned char> AES_ECB_encrypt(std::vector<unsigned char> raw_plaintxt) {

    if (raw_plaintxt.empty()) {
        // standard error msg
        std::cerr << "Error: Base64 decoding failed.\n";
        return {};
    }

    // initialize OpenSSL encryption context
    const std::string key_str = "YELLOW SUBMARINE"; // cf. cryptopals challenge 10 set 2
    const unsigned char* key = reinterpret_cast<const unsigned char*>(key_str.data());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    // pre-allocate memory for ciphertext
    std::vector<unsigned char> ciphertext(raw_plaintxt.size() + 16);
    int len = 0;
    int ciphertext_len = 0;

    // initialize AES-128-ECB encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr) != 1) goto error;

    // disable OpenSSL auto-padding
    if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) goto error;

    // encrypt data block by block
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, raw_plaintxt.data(), static_cast<int>(raw_plaintxt.size())) != 1) goto error;
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) goto error;
    ciphertext_len += len;

    // resize vector
    ciphertext.resize(ciphertext_len);

    // clean up
    EVP_CIPHER_CTX_free(ctx);

    // output
    return ciphertext;

    error:
    std::cerr << "Error: Encryption process failed.\n";
    EVP_CIPHER_CTX_free(ctx);
    return {};
}


// auxiliary function: decrypt by AES in ECB mode, on raw bytes
std::vector<unsigned char> AES_ECB_decrypt(std::vector<unsigned char> raw_plaintxt) {

    if (raw_plaintxt.empty()) {
        // standard error msg
        std::cerr << "Error: Base64 decoding failed.\n";
        return {};
    }

    // initialize OpenSSL encryption context
    const std::string key_str = "YELLOW SUBMARINE"; // cf. cryptopals challenge 10 set 2
    const unsigned char* key = reinterpret_cast<const unsigned char*>(key_str.data());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    // pre-allocate memory for ciphertext
    std::vector<unsigned char> ciphertext(raw_plaintxt.size() + 16);
    int len = 0;
    int ciphertext_len = 0;

    // initialize AES-128-ECB decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr) != 1) goto error;

    // disable OpenSSL auto-padding
    if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) goto error;

    // decrypt data block by block
    if (EVP_DecryptUpdate(ctx, ciphertext.data(), &len, raw_plaintxt.data(), static_cast<int>(raw_plaintxt.size())) != 1) goto error;
    ciphertext_len = len;

    if (EVP_DecryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) goto error;
    ciphertext_len += len;

    // resize vector
    ciphertext.resize(ciphertext_len);

    // clean up
    EVP_CIPHER_CTX_free(ctx);

    // output
    return ciphertext;

error:
    std::cerr << "Error: Encryption process failed.\n";
    EVP_CIPHER_CTX_free(ctx);
    return {};
}


// auxiliary function: XOR on raw bytes
std::vector<uint8_t> xor_blocks(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    std::vector<uint8_t> result(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}


// auxiliary function: CBC encryption loop
std::vector<uint8_t> encrypt_cbc(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& iv) {
    const size_t block_size = 16;
    // initialise output
    std::vector<uint8_t> ciphertext;
    ciphertext.reserve(plaintext.size());

    // initialise looping inputs
    std::vector<uint8_t> prev_block = iv;

    for (size_t i = 0; i < plaintext.size(); i += block_size) {
        // isolate current 16-byte plaintext chunk
        std::vector<uint8_t> current_plain_block(block_size);
        std::copy(plaintext.begin() + i, plaintext.begin() + i + block_size, current_plain_block.begin());

        // XOR plaintext block with prev. ciphertext block (or IV)
        std::vector<uint8_t> xor_result = xor_blocks(current_plain_block, prev_block);

        // pass to ECB encryption
        std::vector<uint8_t> encrypted_block = AES_ECB_encrypt(xor_result);

        // append encrypted block to ciphertext output
        ciphertext.insert(ciphertext.end(), encrypted_block.begin(), encrypted_block.end());

        // update tracking state
        prev_block = encrypted_block;
    }

    return ciphertext;
}


// auxiliary function: CBC decryption loop
std::vector<uint8_t> decrypt_cbc(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& iv) {
    const size_t block_size = 16;
    // initialise output
    std::vector<uint8_t> ciphertext;
    ciphertext.reserve(plaintext.size());

    // initialise looping inputs
    std::vector<uint8_t> prev_block = iv;

    for (size_t i = 0; i < plaintext.size(); i += block_size) {
        // isolate current 16-byte ciphertext chunk safely
        std::vector<uint8_t> current_plain_block(block_size);
        std::copy(plaintext.begin() + i, plaintext.begin() + i + block_size, current_plain_block.begin());

        // pass to ECB decryption first
        std::vector<uint8_t> decrypted_block = AES_ECB_decrypt(current_plain_block);

        // XOR decrypted block with prev. ciphertext block (or IV)
        std::vector<uint8_t> xor_result = xor_blocks(decrypted_block, prev_block);

        // append XOR result to plaintext output
        ciphertext.insert(ciphertext.end(), xor_result.begin(), xor_result.end());

        // update tracking state with original ciphertext block
        prev_block = current_plain_block;
    }

    return ciphertext;
}


// main body
int main() {

    // init. the initialisation vector
    const std::vector<uint8_t> init_vec(16, 0x00);

    // read file, strip any whitespace/newlines from base64
    std::ifstream file("input.txt");
    if (!file) {
        // standard error msg
        std::cerr << "Error: Could not open input.txt\n";
        return 1;
    }
    std::string plain_content, line;

    while (std::getline(file, line)) {
        plain_content += line + "\n"; // keeps multiline base64 intact
    }

    // decode base64 to raw bytes
    std::vector<uint8_t> plaintext = decode_base64(plain_content);

    // CBC decrypt
    std::vector<uint8_t> ciphertext = decrypt_cbc(plaintext, init_vec);

    // raw plaintext bytes directly to readable string
    std::string final_output(ciphertext.begin(), ciphertext.end());

    // output text
    std::cout << "Decrypted Plaintext:\n" << final_output << std::endl;

    return 0;

}