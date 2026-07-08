#include <iostream>
#include <fstream>
#include <vector>
#include <string>

// this program applies a repeated-key XOR symmetric encryption with hex key, buffer and ciphertext.

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

// auxiliary function: repeated-key XOR on raw bytes
std::vector<uint8_t> repeated_xor(const std::vector<uint8_t>& buffer, const std::vector<uint8_t>& key) {

    // pre-allocate the memory for the output
    std::vector<uint8_t> outputXOR;
    outputXOR.reserve(buffer.size());

    // execute a componentwise XOR (^)
    for (size_t i = 0; i < buffer.size(); ++i) {
        int j = i % key.size();
        outputXOR.push_back(buffer[i] ^ key[j]);
    }

    return outputXOR;
}

// auxiliary function: concatenate the three above
std::string hex_to_hex_XOR(const std::string& buffer_hex, const std::string& key_hex) {
    return bytes_to_hex(repeated_xor(hex_to_bytes(buffer_hex), hex_to_bytes(key_hex)));
}

// main body
int main() {
    try {
        // input test vectors as given in cryptopals set 1 challenge 5
        std::string buffer_input = "4275726e696e672027656d2c20696620796f752061696e277420717569636b20616e64206e696d626c650d0a4920676f206372617a79207768656e2049206865617220612063796d62616c";
        std::string key_input = "494345";

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