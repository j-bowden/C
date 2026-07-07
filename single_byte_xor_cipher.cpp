#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <map>
#include <algorithm>
#include <iomanip>

// this program decrypts a single-byte XOR symmetric encryption based on a character frequency metric.

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

// auxiliary function: scoring system based on character frequency
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

// main body
int main() {

    // input ciphertext as given in set 1, challenge 3 of the cryptopals crypto challenges
    std::string hex_ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    // cast to raw bytes using auxiliary function
    std::vector<unsigned char> ciphertext_bytes = hex_to_bytes(hex_ciphertext);

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

    // output to console
    std::cout << "Hex Ciphertext: " << hex_ciphertext << std::endl;
    std::cout << "Best Key: " << best_key << std::endl;
    std::cout << "Best Plaintext: " << best_plaintext << std::endl;

}