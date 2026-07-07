#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cctype>
#include <map>
#include <algorithm>
#include <iomanip>

// this program applies the body of the program single_byte_XOR_cipher to determine which of a list of XOR ciphertexts used a single-byte key.
// This is challenge 4, set 1 of the cryptopals crypto challenges.

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

// auxiliary function: decrypt assuming single-byte key, based on character frequency analysis
std::string single_byte_plaintext(const std::string& hex_ciphertext) {

    // cast to raw bytes using auxiliary function
    std::vector<unsigned char> ciphertext_bytes = hex_to_bytes(hex_ciphertext);

    // initialise (clearly only truly "best" after execution)
    double best_score = -999999.0;
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
            best_plaintext = current_decryption;
        }
    }
    return best_plaintext;
}

// main output: apply to all 60
int main() {

    // open the file of input hex ciphertexts as given in challenge 4, set 1 of the cryptopales crypto challenges
    std::ifstream infile("input.txt");

    // standard error message
    if (!infile.is_open()) {
        std::cerr << "Error: Could not open input.txt. Make sure it is in the same directory.\n";
        return 1;
    }

    // initialise output
    double best_score = -999999.0;
    std::string global_plaintext = "";
    std::string global_cipher = "";
    std::string line;


    while (std::getline(infile, line)) {

        // strip trailing Windows (\r) or Unix (\n) newlines
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
            line.pop_back();
        }

        // skip empty lines to prevent false scoring matches
        if (line.empty()) {
            continue;
        }

        // iterate through the ciphertext vector, apply the previous function and output
        std::string plaintext = single_byte_plaintext(line);
        double current_score = score_text(plaintext);

        if (current_score > best_score) {
            // update variables if new global best is found
            best_score = current_score;
            global_plaintext = plaintext;
            global_cipher = line;
        }
    }

    infile.close();

    // output to console
    std::cout << "Likely Single-Byte Key Ciphertext: " << global_cipher << std::endl;
    std::cout << "Corresponding Best Plaintext: " << global_plaintext << std::endl;

}