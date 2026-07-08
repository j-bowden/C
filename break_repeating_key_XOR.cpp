#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <bit>
#include <cstdint>
#include <stddef.h>
#include <cctype>
#include <map>
#include <algorithm>
#include <iomanip>


// this program attempts to decrypt a repeated-key XOR


// auxiliary function: base64 to raw bytes
std::vector<uint8_t> base64_to_bytes(const std::string& base64) {
    // set up correspondence to refer to
    const std::string b64_map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    // initialise output
    std::vector<uint8_t> bytes;
    int val = 0, valb = -8;

    for (char c : base64) {
        // padding check; break if complete
        if (c == '=') break;
        // search the reference map
        size_t idx = b64_map.find(c);
        if (idx == std::string::npos) {
            // error message if not a valid character in the base64 alphabet
            throw std::invalid_argument("Invalid character in Base64 string.");
        }
        val = (val << 6) | idx;
        // 6 more bits have been added
        valb += 6;
        if (valb >= 0) {
            // execute when enough bits have been added to produce a new raw byte
            bytes.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return bytes;
}


// auxiliary function; calculate Hamming distance on raw bytes
size_t hamming_distance_bytes(const std::vector<uint8_t>& raw1, const std::vector<uint8_t>& raw2) {
    if (raw1.size() != raw2.size()) {
        throw std::invalid_argument("Both strings must be of equal length to calculate a Hamming distance.");
    }

    size_t total_bit_distance = 0;

    for (size_t i = 0; i < raw1.size(); ++i) {
        // bits are different iff corresponding bit in XOR evaluates to 1
        uint8_t xor_result = raw1[i] ^ raw2[i];

        // count individual bit that is = 1 in this byte
        while (xor_result > 0) {
            total_bit_distance += (xor_result & 1); // add 1 if lowest bit = 1
            xor_result >>= 1;                      // check next bit
        }
    }

    return total_bit_distance;
}


// auxiliary function: calculate Hamming distance on base64 strings (concatenate two previous functions)
size_t hamming_distance_b64(const std::string& base64one, const std::string& base64two) {
    return hamming_distance_bytes(base64_to_bytes(base64one), base64_to_bytes(base64two));
}


// auxiliary function: raw bytes to hex 
std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {

    // each byte corresponds to exactly two hex characters
    std::string hex_str;
    hex_str.reserve(bytes.size() * 2);

    // intialise hex lookup
    const char hex_map[] = "0123456789abcdef";

    for (uint8_t byte : bytes) {
        // separately extract high and low 4-bits
        hex_str.push_back(hex_map[(byte >> 4) & 0x0F]);
        hex_str.push_back(hex_map[byte & 0x0F]);
    }

    return hex_str;
}


// auxiliary function; fixed keysize normalised edit distance between first and second "keysize"-many bytes for a given input
double fixed_keysize_norm_edit_dist(const size_t& keysize, const std::vector<uint8_t>& bytes) {

    if (keysize == 0) {
        // keysize must be positive e.g. for normalisation to be well-defined
        throw std::invalid_argument("Keysize must be a positive integer.");
    }

    if (bytes.size() < 2 * keysize) {
        // 2 * keysize many bytes must exist for the edit distance to be well-defined
        throw std::length_error("Input vector is too short for the given keysize.");
    }

    // isolate the two blocks we want
    std::vector<uint8_t> block1(bytes.begin(), bytes.begin() + keysize);
    std::vector<uint8_t> block2(bytes.begin() + keysize, bytes.begin() + (2 * keysize));

    size_t edit_dist = hamming_distance_bytes(block1, block2);
    double norm_edit_dist = static_cast<double>(edit_dist) / keysize;

    return norm_edit_dist;

}


// auxiliary function; take a raw-byte ciphertext and fixed N, break the text into blocks of length N, and transpose into N blocks
// each containing the ith bytes of each block for i from 1 to N
std::vector<std::vector<uint8_t>> transposeCipherBlocks(size_t N, const std::vector<uint8_t>& bytes) {
    if (N == 0 || bytes.empty()) {
        // empty array if empty cipher or keysize is zero
        return {};
    }

    // round up
    size_t numBlocks = (bytes.size() + N - 1) / N;
    // initialise output
    std::vector<std::vector<uint8_t>> transposed(N);

    for (size_t i = 0; i < numBlocks; ++i) {
        for (size_t j = 0; j < N; ++j) {
            size_t index = i * N + j;
            if (index < bytes.size()) {
                transposed[j].push_back(bytes[index]);
            }
        }
    }
    return transposed;
}


// auxiliary function: scoring system based on character frequency for single-character XOR
double score_text(const std::string& text) {

    // quote standard character frequencies for English alphabet + spaces
    static const std::map<char, double> weights = {
        {'a', 0.0817}, {'b', 0.0149}, {'c', 0.0278}, {'d', 0.0425}, {'e', 0.1270},
        {'f', 0.0223}, {'g', 0.0202}, {'h', 0.0609}, {'i', 0.0697}, {'j', 0.0015},
        {'k', 0.0077}, {'l', 0.0402}, {'m', 0.0241}, {'n', 0.0675}, {'o', 0.0751},
        {'p', 0.0193}, {'q', 0.0009}, {'r', 0.0599}, {'s', 0.0633}, {'t', 0.0906},
        {'u', 0.0276}, {'v', 0.0098}, {'w', 0.0236}, {'x', 0.0015}, {'y', 0.0197},
        {'z', 0.0007}, {' ', 0.1300}
    };

    // initialise output score as double
    double score = 0.0;

    for (char c : text) {
        char lower_c = std::tolower(static_cast<unsigned char>(c));

        if (weights.count(lower_c)) {
            // if an English letter or space, apply the map above
            score += weights.at(lower_c);
        }
        else if (std::isprint(static_cast<unsigned char>(c))) {
            // if other print (numbers, punctuation etc.), apply a standard small fixed score
            score += 0.005;
        }
        else if (std::isspace(static_cast<unsigned char>(c))) {
            // if newline/tab, very small fixed score
            score += 0.01;
        }
        else {
            // penalise unprintable control bytes (binary noise)
            score -= 10.0;
        }
    }
    return score;
}


// auxiliary function: single-character XOR
size_t single_char_XOR_key(const std::vector<uint8_t> ciphertext_bytes) {
    // initialise (clearly only truly "best" after execution)
    double best_score = -999999.0;
    int best_key = -1;
    std::string best_plaintext = "";

    // brute-force all 1-byte keys, using that XOR is self-inverse
    for (int key = 0; key < 256; ++key) {
        // loop over all 256 available single character keys
        std::string current_decryption = "";

        for (unsigned char b : ciphertext_bytes) {
            // perform XOR hex-characterwise assuming the current key
            current_decryption += static_cast<char>(b ^ key);
        }

        // call auxiliary function to assign a score
        double current_score = score_text(current_decryption);

        if (current_score > best_score) {
            // update variables if new best is found
            best_score = current_score;
            best_key = key;
            best_plaintext = current_decryption;
        }
    }

    return best_key;
}


// auxiliary function: hex to raw bytes
std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Hex strings must have an even length.");
    } // hex strings which represent raw bytes must have length congruent to 0 mod 2

    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);
    // pre-allocate memory; 2 characters in a hex string represent 1 raw byte

    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        // isolate two characters in the hex string
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}


// main body
int main() {

    try {
        // read in the ciphertext in base64 from the file input.txt
        std::string ciphertxt = "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";
        std::vector<uint8_t> cipherBytes = base64_to_bytes(ciphertxt);

        // initialise output
        size_t key1 = 1;
        size_t key2 = 1;
        size_t key3 = 1;
        double dist1 = 40.0; 
        double dist2 = 40.0;
        double dist3 = 40.0;

        // trial keysizes up to a fixed maximum (keysizeMax), which must be greater than or equal to 2, to find probable keysize
        size_t keysizeMax = 40;
        for (size_t i = 2; i <= keysizeMax; i += 1) {
            if (cipherBytes.size() < 2 * i) continue;
            double current_norm_edit_dist = fixed_keysize_norm_edit_dist(i, cipherBytes);

            if (current_norm_edit_dist < dist1) {
                dist3 = dist2; key3 = key2;
                dist2 = dist1; key2 = key1;
                dist1 = current_norm_edit_dist; key1 = i;
            }
            else if (current_norm_edit_dist < dist2) {
                dist3 = dist2; key3 = key2;
                dist2 = current_norm_edit_dist; key2 = i;
            }
            else if (current_norm_edit_dist < dist3) {
                key3 = i; dist3 = current_norm_edit_dist;
            }

        } // key1, key2, key3 should now be the keysizes corresponding to the smallest normalised edit distances in ascending order

        // concatenate the chosen keysizes into a vector for easy referencing
        std::vector<size_t> keysizes = { key1, key2, key3 };

        for (size_t i = 0; i < 3; i += 1) {
            // perform the transpositions for each keysize on the ciphertext (as bytes)
            size_t currentKeysize = keysizes[i];
            if (currentKeysize <= 1) continue;

            std::vector<std::vector<uint8_t>> transCiph = transposeCipherBlocks(currentKeysize, cipherBytes);
            std::vector<uint8_t> raw_key_bytes;
            raw_key_bytes.reserve(currentKeysize);


            size_t numBlocks = cipherBytes.size() / currentKeysize;
            // initialise output
            std::vector<std::size_t> single_key_vec(numBlocks);

            for (size_t j = 0; j < currentKeysize; j += 1) {
                std::vector<uint8_t> currentBlock = transCiph[j];
                size_t single_char_key = single_char_XOR_key(currentBlock);
                
                raw_key_bytes.push_back(static_cast<uint8_t>(single_char_key));

            }

            std::cout << "The most probable key for keysize " << currentKeysize << " is (hex bytes): " << bytes_to_hex(raw_key_bytes) << std::endl;
        }

    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}