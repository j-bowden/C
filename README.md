This repository documents all significant scripts I have written in C++ (Visual Studio), based largely around the cryptography assignments on cryptopals.com and some of the number theoretic content I studied at university. All scripts are my own, and I have used them as exercises both to learn the C++ language and to develop a broader knowledge of cryptography and its major methods. As a result, they may contain errors or inefficiencies.

----------------------------------------

The program solovay_strassen applies one interation of the Solovay-Strassen primality test to an input odd positive integer N, and (in the appropriate case):
- declares N to be composite;
- exhibits a nontrivial factor of N;
- states the base to which N has passed the test, and that therefore its primality is undetermined.

----------------------------------------

The program miller_rabin applies one interation of the Miller-Rabin primality test to an input odd positive integer N, and (in the appropriate case):
- declares N to be composite;
- exhibits a nontrivial factor of N;
- states the base to which N has passed the test, and that therefore its primality is undetermined.

----------------------------------------

The program fermat_factorisation_algorithm applies the obvious algorithm to an input positive integer up to a fixed number of attempts, and (in the appropriate case):
- declares N to be even;
- exhibits a nontrivial factorisation of N;
- states that Fermat factorisation failed in the given bound on atttempts.

----------------------------------------

The program convert_hex_to_base64 reads a hex input and converts the string to base64, acting only on raw bytes. This is Challenge 1, Set 1 of the cryptopals challenges.

----------------------------------------

The program fixed_xor_hex_input reads a hex input buffer and key and perform a fixed XOR acting only raw bytes. This is Challenge 2, Set 1 of the cryptopals challenges. The output includes a check by using that XOR is a self-inverse operation, i.e. the program applied to the first output and the input key should yield the input buffer.

----------------------------------------

The program single_byte_XOR_cipher performs a brute-force decryption attempt on a hex cipher known to have a single-byte key, and outputs the most probable plaintext based on a fixed probability character analysis. This is Challenge 3, Set 1 of the cryptopals challenges.

----------------------------------------

The program detect_single_character_XOR builds on single_byte_XOR_cipher to determine (based on the same metric as above) which of the hix ciphertext of an input .txt file (which it reads in) is most likely from a single-byte XOR cipher, and outputs the corresponding most probable plaintext (by the same metric). This is Challenge 4, Set 1 of the cryptopals challenges.

----------------------------------------

The program repeated_key_XOR reads a hex input buffer and key where now, unlike in fixed_xor_hex_input, the key may be repeated (or indeed exceed the length of the buffer), again acting only on raw bytes. This is Challenge 5, Set 1 of the cryptopals challenges.

----------------------------------------

The program break_repeating_key_XOR executes Challenge 6, Set 1 of the cryptopals challenges.

----------------------------------------

The program AES_in_ECB executes Challenge 7, Set 1 of the cryptopals challenges.

----------------------------------------

The program pkcs#7_padding executes Challenge 9, Set 2 of the cryptopals challenges.

----------------------------------------

The program CBC_mode executes Challenge 10, Set 2 of the cryptopals challenges, as well as the option for the corresponding encryption.

----------------------------------------
