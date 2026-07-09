#include <vector>
#include <cstdint>
#include <stdexcept>
#include <iostream>


// This program receives a plaintext, determines whether it has a valid PKCS#7 padding, and if so, strips the padding. Else, it returns an appropriate 
// warning message. This is as proscribed in Challenge 15, Set 2 of the cryptopals challenges.


// main body
int main() {

    try {
        // input based on Challenge 15, Set 2 of the cryptopals challenges
        std::string plaintext = "ICE ICE BABY\x01\x02\x03\x04";

        if (plaintext.empty()) {
            // error msg for empty inputs
            throw std::invalid_argument("Error: input cannot be empty.");
        }

        // PKCS#7 padding length is determined by the final byte
        uint8_t padding_len = static_cast<uint8_t>(plaintext.back());

        // PKCS#7 padding values must be between 1 and block size and cannot exceed total size of plaintext
        if (padding_len == 0 || padding_len > plaintext.size()) {
            throw std::invalid_argument("Error: invalid PKCS#7 padding length.");
        }

        // valid padding requires that all padding bytes match padding length value
        for (size_t i = plaintext.size() - padding_len; i < plaintext.size(); ++i) {
            if (static_cast<uint8_t>(plaintext[i]) != padding_len) {
                throw std::invalid_argument("This PKCS#7 padding is invalid. Beware.");
                // may suggest e.g. that cipher has been tampered with?
            }
        }

        // strip padding and output
        std::string depadded = plaintext.substr(0, plaintext.size() - padding_len);

        // output
        std::cout << "The depadded plaintext is: " << depadded << "." << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}