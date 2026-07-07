#include <iostream>
#include <vector>
#include <cstdint>
#include <fstream>

// This program converts hex to base64 via raw bytes

// initialise base64
const std::string base64_map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// auxiliary function: hex to raw bytes
std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Hex strings must have an even length.");
    }
    // hex strings which represent raw bytes must have length congruent to 0 mod 2

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

// auxiliary function: convert raw bytes into base64
std::string bytes_to_base64(const std::vector<uint8_t>& bytes) {
    std::string base64;
    int val = 0;
    int valb = -6;

    for (uint8_t b : bytes) {
        val = (val << 8) + b;
        valb += 8;
        // if we have at least 6 bits unused (valb >= 0) then we can translate a new base64 character
        while (valb >= 0) {
            base64.push_back(base64_map[(val >> valb) & 0x3F]);
            valb -= 6;
            // subtracts the 6 bits we just used from the available count
        }
    }

    // check if any partial (not a full 6-bit block) remains
    if (valb > -6) {
        base64.push_back(base64_map[((val << (8 - (valb + 8))) >> 2) & 0x3F]);
        // pad with zeros to create a full 6-bit block and convert to base64 character
    }

    // final base64 output text must have length congruent to 0 mod 4: pad with "=" to ensure
    while (base64.size() % 4 != 0) {
        base64.push_back('=');
    }

    return base64;
}

// auxiliary function which concatenates the previous two auxiliaries into a unified function
std::string hex_to_base64(const std::string& hex) {
    return bytes_to_base64(hex_to_bytes(hex));
}

// main body
int main() {
    try {
        // input test vector as given in cryptopals set 1 challenge 1
        std::string hex_input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

        // apply the function to the input
        std::string result_b64 = hex_to_base64(hex_input);

        // pretty-print outputs to console
        std::cout << "Hex Input: " << hex_input << std::endl;
        std::cout << "Base64 Output: " << result_b64 << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}