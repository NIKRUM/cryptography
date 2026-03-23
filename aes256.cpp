#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <chrono>

using namespace std;

const int BUFFER_SIZE = 4096;
const int KEY_SIZE = 32; // 256-bitowy klucz AES
const int IV_SIZE = 16;

void encryptFile(const string &inputFile, const string &outputFile, const unsigned char *key, const unsigned char *iv) {
    ifstream in(inputFile, ios::binary);
    ofstream out(outputFile, ios::binary);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key, iv);

    unsigned char buffer[BUFFER_SIZE];
    unsigned char encrypted[BUFFER_SIZE];
    int outLen;

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

void decryptFile(const string &inputFile, const string &outputFile, const unsigned char *key, const unsigned char *iv) {
    ifstream in(inputFile, ios::binary);
    ofstream out(outputFile, ios::binary);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key, iv);

    unsigned char buffer[BUFFER_SIZE];
    unsigned char decrypted[BUFFER_SIZE];
    int outLen;

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
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];

    RAND_bytes(key, KEY_SIZE);
    RAND_bytes(iv, IV_SIZE);

    string inputFile = "plik_10gb.bin";
    string encryptedFile = "encryptedFile.bin";
    string decryptedFile = "decryptedFile.bin";

    auto start = chrono::high_resolution_clock::now();
    encryptFile(inputFile, encryptedFile, key, iv);
    auto end = chrono::high_resolution_clock::now();
    double encryptionTime = chrono::duration<double>(end - start).count();
    cout << "Czas szyfrowania: " << encryptionTime << " s" << endl;

    start = chrono::high_resolution_clock::now();
    decryptFile(encryptedFile, decryptedFile, key, iv);
    end = chrono::high_resolution_clock::now();
    double decryptionTime = chrono::duration<double>(end - start).count();
    cout << "Czas deszyfrowania: " << decryptionTime << " s" << endl;

    writeTimesToFile(encryptionTime, decryptionTime);

    return 0;
}