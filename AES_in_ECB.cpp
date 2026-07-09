#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>


// this program decrypts a fixed known base64 input which is encrypted by AES-128 in ECB mode under the key "YELLOW SUBMARINE", as per Challenge 7, Set 1
// of the cryptopals crypto challenges


// base64 to raw bytes
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

int main() {
    // read file, strip any whitespace/newlines from base64
    std::ifstream file("input.txt");
    if (!file) {
        // standard error msg
        std::cerr << "Error: Could not open input.txt\n";
        return 1;
    }

    std::string base64_content, line;
    while (std::getline(file, line)) {
        base64_content += line;
    }

    // 2. turn ciphertext to raw bytes from base64
    std::vector<unsigned char> ciphertext = decode_base64(base64_content);
    if (ciphertext.empty()) {
        std::cerr << "Error: Base64 decoding failed.\n";
        return 1;
    }

    // initialize OpenSSL decryption context
    const std::string key_str = "YELLOW SUBMARINE"; // cf. cryptopals challenge 7 set 1
    const unsigned char* key = reinterpret_cast<const unsigned char*>(key_str.data());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 1;

    // pre-allocate memory for plaintext
    std::vector<unsigned char> plaintext(ciphertext.size());
    int len = 0;
    int plaintext_len = 0;

    // initialize AES-128-ECB decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr) != 1) goto error;

    // decrypt data block by block
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) goto error;
    plaintext_len = len;

    // handle removal of PKCS#7 padding
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) goto error;
    plaintext_len += len;

    // clean up
    EVP_CIPHER_CTX_free(ctx);

    // output
    std::cout << std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
    return 0;

    error:
    std::cerr << "Error: Decryption process failed.\n";
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}