#include <iostream>
#include <vector>
#include <cstdint>
#include <fstream>

// This program converts hex to base64, using a raw hex file called input.bin, 
// which is encoded as a string as 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

// initialise base64 lookup
const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void hexToBase64(const std::vector<uint8_t>& rawBytes) {
    size_t i = 0;
    size_t length = rawBytes.size();

    // process data in blocks of 3 raw bytes
    for (; i + 2 < length; i += 3) {
        // combine 3 bytes into one 24-bit block
        uint32_t block = (rawBytes[i] << 16) | (rawBytes[i + 1] << 8) | rawBytes[i + 2];

        // decompose into four 6-bit chunks and print characters
        char c1 = b64_table[(block >> 18) & 0x3F];
        char c2 = b64_table[(block >> 12) & 0x3F];
        char c3 = b64_table[(block >> 6) & 0x3F];
        char c4 = b64_table[block & 0x3F];

        std::cout << c1 << c2 << c3 << c4;
    }

    // padding leftover bytes
    if (i < length) {
        size_t remaining = length - i;

        if (remaining == 1) {
            uint32_t block = (rawBytes[i] << 16);
            std::cout << b64_table[(block >> 18) & 0x3F];
            std::cout << b64_table[(block >> 12) & 0x3F];
            std::cout << "==";
        }
        else if (remaining == 2) {
            uint32_t block = (rawBytes[i] << 16) | (rawBytes[i + 1] << 8);
            std::cout << b64_table[(block >> 18) & 0x3F];
            std::cout << b64_table[(block >> 12) & 0x3F];
            std::cout << b64_table[(block >> 6) & 0x3F];
            std::cout << "=";
        }
    }
    std::cout << "\n";
}

int main() {
    std::string filePath = "input.bin";

    // open file in binary mode and jump to end
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);

    if (!file.is_open()) {
        std::cerr << "Error: Could not open file " << filePath << "\n";
        return 1;
    }

    // get file size from current end position
    std::streamsize size = file.tellg();

    // vector of raw bytes of that size
    std::vector<uint8_t> rawBytes(size);

    // jump to beginning of file
    file.seekg(0, std::ios::beg);

    // read file data into vector buffer
    file.read(reinterpret_cast<char*>(rawBytes.data()), size);

    file.close();

    std::cout << "Base64 Output: ";
    hexToBase64(rawBytes);

    return 0;
}