#include <iostream>
#include <random>

// This program implements the Solovay-Strassen primality test


int findGCD(int b, int N) {
    // This function computes the greatest common divisor of the two inputs by the division algorithm

    while (b != 0) {
        int remainder = N % b; // isolate the remainder of N divided by b
        N = b;                 // replace N by the quotient
        b = remainder;         // replace b by the remainder
    }
    return N;
}

int Jacobi(int b, int N) {
    // This function computes the Jacobi symbol of b over N, assuming b and N are coprime and N is odd

    int result = 1;

    while (b != 0) {
        while (b % 2 == 0) {
            b /= 2;
            long long N_mod_8 = N % 8;
            if (N_mod_8 == 3 || N_mod_8 == 5) {
                // by standard formula for the Jacobi symbol (2/N)
                result = (-1) * result;
            }
        }

        // now the variable b is odd, i.e. b is now 2-power free

        if ((b % 4 == 3) && (N % 4 == 3)) {
            // by applying the Jacobi reciprocity law
            result = (-1) * result;
        }

        int temp = b;
        b = N;
        N = temp;

        b = b % N;
    }

    if (N == 1) {
        return result;
    }

    return 0;

}

long long psprimeEuler(long long b, long long N) {
    // This function tests whether a composite odd input N is an Euler pseudoprime to base b
    long long exponent = (N - 1) / 2;
    long long output = 1; // initialise the output
    long long original_b = b;

    while (exponent > 0) {
        if (exponent % 2 == 1) {
            output = (output * b) % N;
        }

        b = (b * b) % N; // exponent is now even; replace base with its square
        exponent = exponent / 2;

    }

    // output now represents b^{(N-1)/2} mod N

    b = original_b;
    int Jsymb = Jacobi(b, N);
    if (Jsymb < 0) {
        Jsymb += N;
    }

    if (Jsymb % N == output % N) {
        return true;
    }
    else {
        return false;
    }

}

int main() {

    int N = 100003; // fix the number to be factorised

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> distrib(2, N - 1); // bases should be between 1 and N exclusive

    int b = distrib(gen); // generate a pseudorandom number

    b = b % N; // bring the number b into the correct range 0 < b < N

    int gcd = findGCD(b, N); // if this fails then b is a nontrivial factor of N, i.e. N is composite

    if (gcd > 1) {
        std::cout << N << " contains " << gcd << " as a factor. It is composite." << std::endl;
        return 0;
    }
    else {
        bool test = psprimeEuler(b, N);
        if (test == true) {
            std::cout << N << " passes the Solovay-Strassen primality test using the base " << b << "." << std::endl;
            std::cout << "It is not yet known whether " << N << " is prime or composite." << std::endl;
        }
        else {
            std::cout << N << " fails the Solovay-Strassen primality test using the base " << b << ". " << N << " is composite." << std::endl;
        }

    }


}