#include <iostream>
#include <fstream>
#include <cmath>
#include <string>
#include <limits>
#include <vector>

// Default common prime numbers and generators used in cryptography
const std::vector<long long> COMMON_PRIMES = {23, 47, 97, 199, 307, 521};
const std::vector<long long> COMMON_GENERATORS = {2, 3, 5, 7};

// Function to calculate modular exponentiation: (base^exp) % mod
long long mod_exp(long long base, long long exp, long long mod) {
    long long result = 1;
    while (exp > 0) {
        if (exp % 2 == 1)  // If exp is odd
            result = (result * base) % mod;
        base = (base * base) % mod;
        exp /= 2;
    }
    return result;
}

// Function to perform Diffie-Hellman key exchange
void diffie_hellman(long long p, long long g, long long private_a, long long private_b) {
    if (p <= 1 || g <= 0) {
        std::cerr << "Error: Invalid prime number (p) or generator (g). Attempting recovery...\n";
        p = COMMON_PRIMES[0];  // Fallback to a common prime
        g = COMMON_GENERATORS[0];  // Fallback to a common generator
        std::cout << "Using default values: p = " << p << ", g = " << g << std::endl;
    }

    // Calculate public keys
    long long public_a = mod_exp(g, private_a, p);
    long long public_b = mod_exp(g, private_b, p);

    // Calculate shared secret key
    long long shared_key_a = mod_exp(public_b, private_a, p);
    long long shared_key_b = mod_exp(public_a, private_b, p);

    std::cout << "Public Key (A): " << public_a << std::endl;
    std::cout << "Public Key (B): " << public_b << std::endl;
    std::cout << "Shared Secret Key (A's View): " << shared_key_a << std::endl;
    std::cout << "Shared Secret Key (B's View): " << shared_key_b << std::endl;
}

// Function to find the closest match for a missing or incorrect value
long long find_closest_value(const std::vector<long long>& candidates, long long input) {
    long long closest = candidates[0];
    for (const auto& candidate : candidates) {
        if (std::abs(candidate - input) < std::abs(closest - input)) {
            closest = candidate;
        }
    }
    return closest;
}

// Function to validate numeric input or suggest a closest value
long long get_valid_or_guessed_input(const std::string& prompt, const std::vector<long long>& candidates) {
    long long value;
    while (true) {
        std::cout << prompt;
        std::cin >> value;

        if (std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cerr << "Invalid input. Suggesting a common value.\n";
            return candidates[0];  // Return a default value
        } else if (value <= 0) {
            std::cerr << "Invalid number. Using closest valid value.\n";
            return find_closest_value(candidates, value);
        } else {
            return value;
        }
    }
}

// Function to read parameters from a file with recovery attempts
bool read_params_from_file(const std::string& filename, long long &p, long long &g, long long &private_a, long long &private_b) {
    std::ifstream infile(filename);
    if (!infile) {
        std::cerr << "Error: Unable to open file " << filename << std::endl;
        return false;
    }

    if (!(infile >> p >> g >> private_a >> private_b)) {
        std::cerr << "Error: Missing or invalid data in the file. Attempting recovery...\n";
        p = COMMON_PRIMES[0];
        g = COMMON_GENERATORS[0];
        private_a = 6;  // Example private key
        private_b = 15;  // Example private key
    }

    if (p <= 1 || g <= 0 || private_a <= 0 || private_b <= 0) {
        std::cerr << "Error: One or more parameters are invalid. Using default values.\n";
        p = find_closest_value(COMMON_PRIMES, p);
        g = find_closest_value(COMMON_GENERATORS, g);
        private_a = std::max(1LL, private_a);
        private_b = std::max(1LL, private_b);
    }

    infile.close();
    return true;
}

// Menu to select options
void display_menu() {
    std::cout << "\n--- Diffie-Hellman Key Exchange ---\n";
    std::cout << "1. Enter Parameters Manually\n";
    std::cout << "2. Load Parameters from File\n";
    std::cout << "3. Exit\n";
    std::cout << "Select an option: ";
}

int main() {
    int choice;
    long long p, g, private_a, private_b;

    while (true) {
        display_menu();
        std::cin >> choice;

        if (std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cerr << "Invalid option. Please enter a valid number.\n";
            continue;
        }

        switch (choice) {
            case 1:
                p = get_valid_or_guessed_input("Enter Prime Number (p): ", COMMON_PRIMES);
                g = get_valid_or_guessed_input("Enter Generator (g): ", COMMON_GENERATORS);
                private_a = get_valid_or_guessed_input("Enter Private Key for A: ", {});
                private_b = get_valid_or_guessed_input("Enter Private Key for B: ", {});
                diffie_hellman(p, g, private_a, private_b);
                break;

            case 2: {
                std::string filename;
                std::cout << "Enter filename: ";
                std::cin >> filename;
                if (read_params_from_file(filename, p, g, private_a, private_b)) {
                    diffie_hellman(p, g, private_a, private_b);
                }
                break;
            }

            case 3:
                std::cout << "Exiting...\n";
                return 0;

            default:
                std::cerr << "Invalid option. Please try again.\n";
        }
    }
}
