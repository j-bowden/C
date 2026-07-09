#include <iostream>
#include <string>
#include <vector>


// this program implements PKCS#7 standard padding given an input string and fixed block size


// auxiliary function: do the padding of an input string
std::string pad_pkcs7(const std::string& input, size_t block_size) {
    if (block_size == 0 || block_size > 255) {
        // padding value is stored in a single byte therefore must be of appropriate size
        throw std::invalid_argument("Block size must be between 1 and 255.");
    }

    // calculate how many bytes needed to fill to a full block
    size_t padding_length = block_size - (input.length() % block_size);

    // initialisw output
    std::string padded_output = input;
    // append the padding bytes
    padded_output.append(padding_length, static_cast<char>(padding_length));

    return padded_output;
}

// Helper function to print a string with non-printable characters escaped as hex
void print_escaped(const std::string& str) {
    for (unsigned char ch : str) {
        if (ch >= 32 && ch <= 126) {
            // checks ASCII value is printable as a keyboard character
            std::cout << ch;
        }
        else {
            // otherwise resort to hex for pretty-printing
            std::cout << "\\x";
            std::cout << "0123456789abcdef"[ch >> 4];
            std::cout << "0123456789abcdef"[ch & 0x0F];
        }
    }
    std::cout << "\n";
}


// main body
int main() {
    std::string message = "YELLOW SUBMARINE"; // input as for Challenge 9, Set 2 of the cryptopals challenges
    size_t target_block_size = 20; // as in prev. comment

    try {
        std::string padded = pad_pkcs7(message, target_block_size);

        std::cout << "Original length: " << message.length() << " bytes\n";
        std::cout << "Padded length: " << padded.length() << " bytes\n";
        std::cout << "Padded output: ";
        print_escaped(padded);
    }
    catch (const std::exception& e) {
        // standard error catch
        std::cerr << "Error: " << e.what() << "\n";
    }

    return 0;
}