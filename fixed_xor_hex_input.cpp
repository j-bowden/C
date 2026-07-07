#include <iostream>
#include <fstream>
#include <vector>
#include <string>

// this program applies a fixed XOR symmetric encryption to two fixed hex buffers of the same length.

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

// auxiliary function: XOR the two byte vectors
std::vector<uint8_t> fixed_xor(const std::vector<uint8_t>& buffer, const std::vector<uint8_t>& key) {

    // both buffer and key must have the same length: error message o/w
    if (buffer.size() != key.size()) {
        throw std::invalid_argument("Buffer and key must be of equal length to perform fixed XOR.");
    }

    // pre-allocate the memory for the output
    std::vector<uint8_t> outputXOR;
    outputXOR.reserve(buffer.size());

    // execute a componentwise XOR (^)
    for (size_t i = 0; i < buffer.size(); ++i) {
        outputXOR.push_back(buffer[i] ^ key[i]);
    }

    return outputXOR;
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

// auxiliary function: concatenate the three above
std::string hex_to_hex_XOR(const std::string& buffer_hex, const std::string& key_hex) {
    return bytes_to_hex(fixed_xor(hex_to_bytes(buffer_hex), hex_to_bytes(key_hex)));
}

// main body
int main() {
    try {
        // input test vectors as given in cryptopals set 1 challenge 2
        std::string buffer_input = "1c0111001f010100061a024b53535009181c";
        std::string key_input = "686974207468652062756c6c277320657965";

        // apply the function to the inputs
        std::string result = hex_to_hex_XOR(buffer_input, key_input);
        std::string check = hex_to_hex_XOR(result, key_input);

        // pretty-print outputs to console
        std::cout << "Hex Buffer Input: " << buffer_input << std::endl;
        std::cout << "Hex Key Input: " << key_input << std::endl;
        std::cout << "Hex XOR Output: " << result << std::endl;
        std::cout << "Output XOR Key: " << check << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}