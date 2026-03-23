#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <chrono>

using namespace std;

const int BUFFER_SIZE = 4096;
const int KEY_SIZE = 16; // AES-128
const int IV_SIZE = 16;  // Rozmiar IV dla AES

// 1. SZYFROWANIE: Samodzielnie generuje IV i zapisuje na początku pliku
void encryptFile(const string &inputFile, const string &outputFile, const unsigned char *key) {
    // Generujemy losowy wektor IV bezpośrednio w funkcji szyfrującej
    unsigned char iv[IV_SIZE];
    RAND_bytes(iv, IV_SIZE);

    ifstream in(inputFile, ios::binary);
    ofstream out(outputFile, ios::binary);

    // KLUCZOWY MOMENT: Najpierw zapisujemy jawny wektor IV do pliku wyjściowego
    out.write(reinterpret_cast<char *>(iv), IV_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    unsigned char buffer[BUFFER_SIZE];
    unsigned char encrypted[BUFFER_SIZE + 16];
    int outLen;

    while (true) {
        in.read(reinterpret_cast<char *>(buffer), BUFFER_SIZE);
        streamsize bytesRead = in.gcount();

        if (bytesRead > 0) {
            EVP_EncryptUpdate(ctx, encrypted, &outLen, buffer, static_cast<int>(bytesRead));
            out.write(reinterpret_cast<char *>(encrypted), outLen);
        }

        if (in.eof()) break;
    }

    EVP_EncryptFinal_ex(ctx, encrypted, &outLen);
    out.write(reinterpret_cast<char *>(encrypted), outLen);

    EVP_CIPHER_CTX_free(ctx);
    in.close();
    out.close();
}

// 2. DESZYFROWANIE: Najpierw czyta IV z pliku, potem odszyfrowuje resztę
void decryptFile(const string &inputFile, const string &outputFile, const unsigned char *key) {
    ifstream in(inputFile, ios::binary);
    ofstream out(outputFile, ios::binary);

    // KLUCZOWY MOMENT: Odczytujemy pierwsze 16 bajtów z zaszyfrowanego pliku
    // Wiemy, że tam czeka na nas wektor IV!
    unsigned char iv[IV_SIZE];
    in.read(reinterpret_cast<char *>(iv), IV_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    // Używamy odczytanego IV do zainicjowania deszyfrowania
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    unsigned char buffer[BUFFER_SIZE];
    unsigned char decrypted[BUFFER_SIZE + 16];
    int outLen;

    while (true) {
        // Czytamy resztę pliku (kursor w pliku jest już przesunięty o te 16 bajtów IV)
        in.read(reinterpret_cast<char *>(buffer), BUFFER_SIZE);
        streamsize bytesRead = in.gcount();

        if (bytesRead > 0) {
            EVP_DecryptUpdate(ctx, decrypted, &outLen, buffer, static_cast<int>(bytesRead));
            out.write(reinterpret_cast<char *>(decrypted), outLen);
        }

        if (in.eof()) break;
    }

    EVP_DecryptFinal_ex(ctx, decrypted, &outLen);
    out.write(reinterpret_cast<char *>(decrypted), outLen);

    EVP_CIPHER_CTX_free(ctx);
    in.close();
    out.close();
}

void writeTimesToFile(double encryptionTime, double decryptionTime) {
    ofstream timeFile("czasy.txt", ios::app);
    if (timeFile.is_open()) {
        timeFile << "Czas szyfrowania (AES-128 CTR z dołączonym IV): " << encryptionTime << " s" << endl;
        timeFile << "Czas deszyfrowania (AES-128 CTR z odczytanym IV): " << decryptionTime << " s" << endl;
        timeFile << "-----------------------------------" << endl;
        timeFile.close();
    }
}

int main() {
    unsigned char key[KEY_SIZE];

    // Generujemy TYLKO klucz. Jest on jedynym sekretem.
    // W prawdziwej aplikacji ten klucz pochodziłby np. z hasła wpisanego przez użytkownika.
    RAND_bytes(key, KEY_SIZE);

    string inputFile = "plik_10gb.bin";
    string encryptedFile = "encryptedFileWithZeroCTR_AES.bin";
    string decryptedFile = "decryptedFileWithZeroCTR_AES.bin";

    auto start = chrono::high_resolution_clock::now();
    // Przekazujemy tylko klucz - funkcja sama ogarnie IV
    encryptFile(inputFile, encryptedFile, key);
    auto end = chrono::high_resolution_clock::now();
    double encryptionTime = chrono::duration<double>(end - start).count();
    cout << "Czas szyfrowania: " << encryptionTime << " s" << endl;

    start = chrono::high_resolution_clock::now();
    // Przekazujemy tylko klucz - funkcja sama wyciągnie IV z pliku
    decryptFile(encryptedFile, decryptedFile, key);
    end = chrono::high_resolution_clock::now();
    double decryptionTime = chrono::duration<double>(end - start).count();
    cout << "Czas deszyfrowania: " << decryptionTime << " s" << endl;

    writeTimesToFile(encryptionTime, decryptionTime);

    return 0;
}