#include <iostream>
#include <random>
#include <cmath>
#include <ctime>
#include <vector>
#include <cstring>
#include <string>
#include <sstream>
#include <regex>

bool is_prime(long long n);
long long putere(long long baza, long long exponent, long long rest);
long long gen_prim();
void gen_chei(long long& p, long long& g, long long& x, long long& q, long long& k);
long long inversa(long long a, long long p);
void incriptie(long long m, long long g, long long p, long long y, long long k, long long &y1, long long &y2);
long long decriptie(long long y1, long long y2, long long x, long long p);
std::vector<long long> text_to_ascii(const std::string &text);
std::string ascii_to_text(const std::vector<long long> &numbers);
std::vector<std::pair<long long, long long>> regex_parse(const std::string &encrypted);

int main() {
    int choice;
    std::cout<<"Choose an option: "<<'\n'<<"1: Generate keys for encryption "<<'\n'<<"2: Input keys for decryption "<<'\n'<<std::endl;
    std::cin>>choice;
    std::cin.ignore();
    if (choice == 1) {
        srand(time(0));
        long long p, g, x, q, k;
        gen_chei(p, g, x, q, k);
        std::cout<<"Generated keys: \n";
        std::cout<<"p: " << p << "\n";
        std::cout<<"g: " << g << "\n";
        std::cout<<"q: " << q << "\n";
        std::cout<<"x (private key): " << x << "\n";
        std::string input_text;
        std::cout<<"Enter text to encrypt: \n\n";
        getline(std::cin, input_text);

        std::vector<long long> message_numbers = text_to_ascii(input_text);
        std::vector<std::pair<long long, long long>> encrypted_message;
        for (long long m : message_numbers) {
            long long y1, y2;
            std::mt19937 gen(rand());
            std::uniform_int_distribution<long long> dist_k(1, p - 2);
            long long unique_k = dist_k(gen);
            incriptie(m, g, p, q, unique_k, y1, y2);
            encrypted_message.push_back({y1, y2});
        }
        std::cout<<"Encrypted message: \n\n";
        for (const auto &pair : encrypted_message) {
            std::cout<<"("<<pair.first<<", "<<pair.second<<") ";
        }
        std::cout<<"\n";
    } else if (choice == 2) {
        long long p, g, x;
        std::cout<<"Enter values for decryption: \n";
        std::cout<<"p: "; std::cin >> p;
        std::cout<<"g: "; std::cin >> g;
        std::cout<<"x (private key): "; std::cin >> x;
        std::cin.ignore();
        std::cout<<"Enter encrypted message: \n";
        std::string encrypted_message;
        getline(std::cin, encrypted_message);
        std::vector<std::pair<long long, long long>> pairs = regex_parse(encrypted_message);
        std::vector<long long> decrypted_numbers;
        for (const auto &pair : pairs) {
            long long decrypted = decriptie(pair.first, pair.second, x, p);
            decrypted_numbers.push_back(decrypted);
        }
        std::string decrypted_text = ascii_to_text(decrypted_numbers);
        std::cout<<"Decrypted text: \n\n" << decrypted_text << "\n";
    }
    return 0;
}

bool is_prime(long long n) {
    if (n < 2) return false;
    if (n == 2 || n == 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    for (long long i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0)
            return false;
    }
    return true;
}

long long putere(long long baza, long long exponent, long long rest) {
    long long result = 1;
    baza = baza % rest;
    while (exponent > 0) {
        if (exponent % 2 == 1)
            result = (result * baza) % rest;
        exponent = exponent >> 1;
        baza = (baza * baza) % rest;
    }
    return result;
}

long long gen_prim() {
    std::mt19937 gen(time(0) + rand());
    std::uniform_int_distribution<long long> dist(1, 1000);
    long long p;
    do {
        p = dist(gen);
    } while (!is_prime(p));
    return p;
}

void gen_chei(long long& p, long long& g, long long& x, long long& q, long long& k) {
    p = gen_prim();
    std::mt19937 gen(time(0) + rand());
    std::uniform_int_distribution<long long> dist_g(2, p - 1);
    std::uniform_int_distribution<long long> dist_x(1, p - 2);
    std::uniform_int_distribution<long long> dist_k(1, p - 2);
    g = dist_g(gen);
    x = dist_x(gen);
    q = putere(g, x, p);
    k = dist_k(gen);
}

long long inversa(long long a, long long p) {
    return putere(a, p - 2, p);
}

void incriptie(long long m, long long g, long long p, long long y, long long k, long long &y1, long long &y2) {
    y1 = putere(g, k, p);
    y2 = (m * putere(y, k, p)) % p;
}

long long decriptie(long long y1, long long y2, long long x, long long p) {
    long long s = putere(y1, x, p);
    long long s_inv = inversa(s, p);
    return ((y2 % p) * (s_inv % p)) % p;
}

std::vector<long long> text_to_ascii(const std::string &text) {
    std::vector<long long> numbers;
    for (char c : text) {
        numbers.push_back(static_cast<long long>(c));
    }
    return numbers;
}

std::string ascii_to_text(const std::vector<long long> &numbers) {
    std::string text;
    for (long long num : numbers) {
        text.push_back(static_cast<char>(num));
    }
    return text;
}

std::vector<std::pair<long long, long long>> regex_parse(const std::string &encrypted) {
    std::vector<std::pair<long long, long long>> result;
    
    std::regex pair_regex("\\(\\s*(\\d+)\\s*,\\s*(\\d+)\\s*\\)");
    std::sregex_iterator iter(encrypted.begin(), encrypted.end(), pair_regex);
    std::sregex_iterator end;
    
    while (iter != end) {
        std::smatch match = *iter;
        if (match.size() == 3) { 
            long long y1 = std::stoll(match[1].str());
            long long y2 = std::stoll(match[2].str());
            result.push_back({y1, y2});
        }
        ++iter;
    }
    
    return result;
}