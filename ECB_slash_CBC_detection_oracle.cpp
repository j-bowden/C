#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <cstring>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <cstdlib>
#include <ctime>


// this program implements challenge 11, set 2 of the cryptopals challenges.

// ------------------------------------

// auxiliary function: generate random 16-byte AES key
std::vector<uint8_t> generate_random_aes_key() {
    std::vector<uint8_t> key(16);
    if (RAND_bytes(key.data(), key.size()) != 1) {
        throw std::runtime_error("Failed to generate secure random bytes for the AES key.");
    }
    return key;
}

// ------------------------------------

// auxiliary function: generate random secure IV of input length
std::vector<uint8_t> generate_random_iv(size_t& size) {
    std::vector<uint8_t> iv(size);
    if (RAND_bytes(iv.data(), iv.size()) != 1) {
        throw std::runtime_error("Failed to generate secure random bytes for the initialisation vector.");
    }
    return iv;
}

// ------------------------------------

// auxiliary function: append 5-10 (count chosen randomly) bytes before + after
std::vector<uint8_t> append_random_bytes(std::vector<uint8_t>& user_input) {

    // generate random counts
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> count_dist(5, 10);
    std::uniform_int_distribution<int> mode_dist(0, 1);
    size_t prefix_len = count_dist(gen);
    size_t suffix_len = count_dist(gen);

    // build the appendages
    std::vector<uint8_t> prefix(prefix_len);
    std::vector<uint8_t> suffix(suffix_len);
    RAND_bytes(prefix.data(), prefix_len);
    RAND_bytes(suffix.data(), suffix_len);

    // initialise output
    std::vector<uint8_t> plaintext;
    plaintext.reserve(prefix_len + user_input.size() + suffix_len);

    // modify output
    plaintext.insert(plaintext.end(), prefix.begin(), prefix.end());
    plaintext.insert(plaintext.end(), user_input.begin(), user_input.end());
    plaintext.insert(plaintext.end(), suffix.begin(), suffix.end());

    // return output
    return plaintext;
}

// ------------------------------------

// auxiliary function: perform AES encryption on raw bytes under fixed key
std::vector<uint8_t> aes_ecb_encrypt_det(std::vector<uint8_t>& plaintxt, const std::string& key_str, bool use_padding = true) {

    // AES encryption key must be exactly 16 bytes long
    if (key_str.size() != 16) {
        std::cerr << "Error: AES-128 requires an exact 16-byte key.\n";
        return {};
    }

    // initialize OpenSSL encryption context
    const unsigned char* key = reinterpret_cast<const unsigned char*>(key_str.data());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error occurred.\n";
        return {};
    }

    // pre-allocate memory for ciphertext
    std::vector<unsigned char> ciphertext(plaintxt.size() + 16); // + 16 to allocate enough memory for output buffer
    int len = 0;
    int ciphertext_len = 0;

    // initialize AES-128-ECB encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr) != 1) goto error;

    // disable automatic padding
    if (!use_padding) {
        if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) goto error;
    }

    // encrypt data block by block
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintxt.data(), static_cast<int>(plaintxt.size())) != 1) goto error;
    ciphertext_len = len;

    // handle removal of PKCS#7 padding
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) goto error;
    ciphertext_len += len;

    // clean up
    EVP_CIPHER_CTX_free(ctx);

    // resize to trim off unused pre-allocated padding space
    ciphertext.resize(ciphertext_len);

    // output
    return ciphertext;

    error:
    std::cerr << "Error: Encryption process failed.\n";
    EVP_CIPHER_CTX_free(ctx);
    return {};
}

// ------------------------------------

// auxiliary function: manual pkcs#7 padding
std::vector<uint8_t> pkcs7_pad(const std::vector<uint8_t>& data, size_t block_size = 16) {
    size_t padding_len = block_size - (data.size() % block_size);
    std::vector<uint8_t> padded_data = data;
    padded_data.insert(padded_data.end(), padding_len, static_cast<uint8_t>(padding_len));
    return padded_data;
}

// ------------------------------------

// auxiliary function: XOR on raw bytes
std::vector<uint8_t> xor_blocks(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    std::vector<uint8_t> result(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

// ------------------------------------

// auxiliary function: CBC encryption loop with fixed key input
std::vector<uint8_t> encrypt_cbc(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& iv, const std::string& key_string) {
    const size_t block_size = 16;
    std::vector<uint8_t> padded_plaintext = pkcs7_pad(plaintext, block_size);

    // initialise output
    std::vector<uint8_t> ciphertext;
    ciphertext.reserve(padded_plaintext.size());

    // initialise looping inputs
    std::vector<uint8_t> prev_block = iv;

    for (size_t i = 0; i < padded_plaintext.size(); i += block_size) {
        // isolate current 16-byte plaintext chunk
        std::vector<uint8_t> current_plain_block(block_size);
        std::copy(padded_plaintext.begin() + i, padded_plaintext.begin() + i + block_size, current_plain_block.begin());

        // XOR plaintext block with prev. ciphertext block (or IV)
        std::vector<uint8_t> xor_result = xor_blocks(current_plain_block, prev_block);

        // pass to ECB encryption
        std::vector<uint8_t> encrypted_block = aes_ecb_encrypt_det(xor_result, key_string, false);

        // append encrypted block to ciphertext output
        ciphertext.insert(ciphertext.end(), encrypted_block.begin(), encrypted_block.end());

        // update tracking state
        prev_block = encrypted_block;
    }

    return ciphertext;
}

// ------------------------------------

// auxiliary function: the oracle
std::vector<uint8_t> encryption_oracle(std::vector<uint8_t>& user_input, std::string& mode_used) {

    // append 5-10 random bytes to both sides via auxiliary function
    std::vector<uint8_t> appd_plaintext = append_random_bytes(user_input);

    // generate fresh 16-byte random key by aux. func. and convert to string for ECB
    std::vector<uint8_t> raw_key = generate_random_aes_key();
    std::string key_str(raw_key.begin(), raw_key.end());

    // randomise choice of cipher (0 = ECB, 1 = CBC)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> mode_dist(0, 1);
    int choice = mode_dist(gen);

    if (choice == 0) {
        mode_used = "ECB";
        // apply AES in ECB function
        return aes_ecb_encrypt_det(appd_plaintext, key_str, true);
    }
    else {
        mode_used = "CBC";
        size_t iv_size = 16;
        // use aux. func. to generate random IV
        std::vector<uint8_t> iv = generate_random_iv(iv_size);
        // apply CBC encryption function
        return encrypt_cbc(appd_plaintext, iv, key_str);
    }
}

// ------------------------------------

// auxiliary function: detect cipher used using pattern leakage of ECB
std::string detect_cipher_mode(const std::vector<uint8_t>& ciphertext) {
    const size_t block_size = 16;

    // ciphertext must be long enough to make useful deductions about repetition
    if (ciphertext.size() < block_size * 2) {
        return "Ciphertext is too short to determine cipher.";
    }

    // compare each 16-byte block against every other
    for (size_t i = 0; i < ciphertext.size(); i += block_size) {
        for (size_t j = i + block_size; j < ciphertext.size(); j += block_size) {
            if (i + block_size <= ciphertext.size() && j + block_size <= ciphertext.size()) {
                // if two distinct blocks match perfectly, it's ECB mode (probabilistically)
                if (std::equal(ciphertext.begin() + i, ciphertext.begin() + i + block_size, ciphertext.begin() + j)) {
                    return "ECB";
                }
            }
        }
    }
    // if no duplicate blocks are found, it is likely CBC mode
    return "CBC";
}

// ------------------------------------

// main body
int main() {
    // send 64 identical bytes to validate the test
    std::vector<uint8_t> chosen_plaintext(64, 'A');

    // choose how many rounds
    int round_num = 25;

    // print user-friendly interface
    std::cout << "--- Running Detection Test over " << round_num << " Rounds ---" << std::endl;
    int successful_guesses = 0;

    // loop over declared number of rounds
    for (int round = 1; round <= round_num; ++round) {
        std::string actual_mode;

        // engage the oracle
        std::vector<uint8_t> ciphertext = encryption_oracle(chosen_plaintext, actual_mode);
        std::string guessed_mode = detect_cipher_mode(ciphertext);

        std::cout << "Round " << round << " | The oracle selected: " << actual_mode
            << " | The detector guessed: " << guessed_mode;

        if (actual_mode == guessed_mode) {
            // success!
            std::cout << " | The detector guessed correctly!\n";
            successful_guesses++;
        }
        else {
            // failure
            std::cout << " | The detector guessed incorrectly.\n";
        }
    }

    // calculate success rate and print
    std::cout << "\nSuccess Rate: " << successful_guesses << "/" << round_num << " rounds." << std::endl;
    return 0;
}