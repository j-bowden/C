The program solovay_strassen applies one interation of the Solovay-Strassen primality test to an input odd positive integer N, and (in the appropriate case):
- declares N to be composite;
- exhibits a nontrivial factor of N;
- states the base to which N has passed the test, and that therefore its primality is undetermined.

The program miller_rabin applies one interation of the Miller-Rabin primality test to an input odd positive integer N, and (in the appropriate case):
- declares N to be composite;
- exhibits a nontrivial factor of N;
- states the base to which N has passed the test, and that therefore its primality is undetermined.

The program fermat_factorisation_algorithm applies the obvious algorithm to an input positive integer up to a fixed number of attempts, and (in the appropriate case):
- declares N to be even;
- exhibits a nontrivial factorisation of N;
- states that Fermat factorisation failed in the given bound on atttempts.

The program convert_hex_to_base64 reads a hex input and converts the string to base64, acting only on raw bytes. This is Challenge 1, Set 1 of the cryptopals challenges.
