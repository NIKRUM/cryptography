#include <iostream>
#include <fstream>
#include <openssl/evp.h> // Biblioteka OpenSSL do operacji szyfrowania
#include <openssl/rand.h> // Biblioteka OpenSSL do generowania losowych liczb (kluczy i wektorów inicjalizujących)
#include <chrono> // Biblioteka do mierzenia czasu

using namespace std;

const int BUFFER_SIZE = 4096; // Bufor
const int KEY_SIZE = 24; // AES używa 192-bitowego klucza, czyli 24 bajty
const int IV_SIZE = 16; // Wektor inicjalizujący (IV) dla AES (16 bajtów)

// Funkcja do szyfrowania pliku
void encryptFile(const string &inputFile, const string &outputFile, const unsigned char *key, const unsigned char *iv) {
    ifstream in(inputFile, ios::binary);
    ofstream out(outputFile, ios::binary);

    // Tworzymy kontekst szyfrowania oraz inicjalizujemy algorytm AES w trybie CTR
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_192_ctr(), nullptr, key, iv);

    unsigned char buffer[BUFFER_SIZE];  // Bufor do przechowywania danych do szyfrowania
    unsigned char encrypted[BUFFER_SIZE]; // Bufor na zaszyfrowane dane
    int outLen; // Zmienna do przechowywania długości zaszyfrowanych danych

    while (in.read(reinterpret_cast<char *>(buffer), BUFFER_SIZE)) {
        EVP_EncryptUpdate(ctx, encrypted, &outLen, buffer, in.gcount());
        out.write(reinterpret_cast<char *>(encrypted), outLen);
    }
    EVP_EncryptFinal_ex(ctx, encrypted, &outLen);
    out.write(reinterpret_cast<char *>(encrypted), outLen);

    EVP_CIPHER_CTX_free(ctx);
    in.close();
    out.close();
}

// Funkcja do deszyfrowania pliku
void decryptFile(const string &inputFile, const string &outputFile, const unsigned char *key, const unsigned char *iv) {
    ifstream in(inputFile, ios::binary);
    ofstream out(outputFile, ios::binary);

    // Tworzymy kontekst deszyfrowania oraz inicjalizujemy algorytm AES w trybie CTR
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_192_ctr(), nullptr, key, iv);

    unsigned char buffer[BUFFER_SIZE];  // Bufor do przechowywania danych do deszyfrowania
    unsigned char decrypted[BUFFER_SIZE]; // Bufor na odszyfrowane dane
    int outLen; // Zmienna do przechowywania długości odszyfrowanych danych

    while (in.read(reinterpret_cast<char *>(buffer), BUFFER_SIZE)) {
        EVP_DecryptUpdate(ctx, decrypted, &outLen, buffer, in.gcount());
        out.write(reinterpret_cast<char *>(decrypted), outLen);
    }
    EVP_DecryptFinal_ex(ctx, decrypted, &outLen);
    out.write(reinterpret_cast<char *>(decrypted), outLen);

    EVP_CIPHER_CTX_free(ctx);
    in.close();
    out.close();
}

// Funkcja do zapisywania czasów szyfrowania i deszyfrowania do pliku
void writeTimesToFile(double encryptionTime, double decryptionTime) {
    ofstream timeFile("czasy.txt", ios::app);
    if (timeFile.is_open()) {
        timeFile << "Czas szyfrowania: " << encryptionTime << " s" << endl;
        timeFile << "Czas deszyfrowania: " << decryptionTime << " s" << endl;
        timeFile << endl;
        timeFile.close();
    } else {
        cerr << "Błąd otwierania pliku czasy.txt" << endl;
    }
}

int main() {
    unsigned char key[KEY_SIZE]; // Tablica klucza
    unsigned char iv[IV_SIZE]; // Tablica wektora inicjalizującego

    // Generowanie losowego klucza i wektora IV
    RAND_bytes(key, KEY_SIZE);
    RAND_bytes(iv, IV_SIZE);

    string inputFile = "plik_10gb.bin";  // Plik wejściowy
    string encryptedFile = "encryptedFile.bin"; // Plik wyjściowy (zaszyfrowany)
    string decryptedFile = "decryptedFile.bin"; // Plik wyjściowy (odszyfrowany)

    // Mierzenie czasu szyfrowania
    auto start = chrono::high_resolution_clock::now();
    encryptFile(inputFile, encryptedFile, key, iv);  // Szyfrujemy plik
    auto end = chrono::high_resolution_clock::now();
    double encryptionTime = chrono::duration<double>(end - start).count();
    cout << "Czas szyfrowania: " << encryptionTime << " s" << endl;

    // Mierzenie czasu deszyfrowania
    start = chrono::high_resolution_clock::now();
    decryptFile(encryptedFile, decryptedFile, key, iv);  // Deszyfrujemy plik
    end = chrono::high_resolution_clock::now();
    double decryptionTime = chrono::duration<double>(end - start).count();
    cout << "Czas deszyfrowania: " << decryptionTime << " s" << endl;

    writeTimesToFile(encryptionTime, decryptionTime); // Zapisz czasy do pliku

    return 0;
}