#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <chrono>

using namespace std;

const int BUFFER_SIZE = 4096;
const int KEY_SIZE = 32; // 256-bitowy klucz AES (32 bajty)
const int IV_SIZE = 16;  // Wektor IV dla AES zawsze ma 16 bajtów

// 1. SZYFROWANIE Z WSTRZYKIWANIEM IV
void encryptFile(const string &inputFile, const string &outputFile, const unsigned char *key) {
    ifstream in(inputFile, ios::binary);
    ofstream out(outputFile, ios::binary);

    // Zabezpieczenie przed brakiem pliku (bardzo ważne przy 10 GB!)
    if (!in.is_open() || !out.is_open()) {
        cerr << "Błąd otwarcia plików do szyfrowania!" << endl;
        return;
    }

    // Generujemy unikalny, losowy wektor IV wewnątrz funkcji
    unsigned char iv[IV_SIZE];
    RAND_bytes(iv, IV_SIZE);

    // WSTRZYKNIĘCIE: Zapisujemy 16 bajtów IV na sam początek pliku wynikowego
    out.write(reinterpret_cast<char *>(iv), IV_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0); // Wyłączamy padding (standard dla CTR)

    unsigned char buffer[BUFFER_SIZE];
    unsigned char encrypted[BUFFER_SIZE + 16]; // Bezpieczny margines bufora
    int outLen;

    // Bezpieczna pętla chroniąca przed utratą końcówki pliku
    while (true) {
        in.read(reinterpret_cast<char *>(buffer), BUFFER_SIZE);
        streamsize bytesRead = in.gcount(); // Sprawdzamy, ile faktycznie przeczytano

        if (bytesRead > 0) {
            EVP_EncryptUpdate(ctx, encrypted, &outLen, buffer, static_cast<int>(bytesRead));
            out.write(reinterpret_cast<char *>(encrypted), outLen);
        }

        if (in.eof()) break; // Przerywamy dopiero po osiągnięciu końca pliku
    }

    EVP_EncryptFinal_ex(ctx, encrypted, &outLen);
    out.write(reinterpret_cast<char *>(encrypted), outLen);

    EVP_CIPHER_CTX_free(ctx);
    in.close();
    out.close();
}

// 2. DESZYFROWANIE Z ODCZYTEM IV
void decryptFile(const string &inputFile, const string &outputFile, const unsigned char *key) {
    ifstream in(inputFile, ios::binary);
    ofstream out(outputFile, ios::binary);

    if (!in.is_open() || !out.is_open()) {
        cerr << "Błąd otwarcia plików do deszyfrowania!" << endl;
        return;
    }

    // POBRANIE IV: Czytamy pierwsze 16 bajtów, wiedząc, że ukryliśmy tam wektor IV
    unsigned char iv[IV_SIZE];
    in.read(reinterpret_cast<char *>(iv), IV_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key, iv); // Używamy pobranego IV
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    unsigned char buffer[BUFFER_SIZE];
    unsigned char decrypted[BUFFER_SIZE + 16]; // Bezpieczny margines bufora
    int outLen;

    // Bezpieczna pętla chroniąca przed utratą końcówki pliku
    while (true) {
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
        timeFile << "Czas szyfrowania (AES-256 CTR): " << encryptionTime << " s" << endl;
        timeFile << "Czas deszyfrowania (AES-256 CTR): " << decryptionTime << " s" << endl;
        timeFile << "-----------------------------------" << endl;
        timeFile.close();
    } else {
        cerr << "Błąd otwierania pliku czasy.txt" << endl;
    }
}

int main() {
    unsigned char key[KEY_SIZE];

    // W main() losujemy TYLKO klucz główny (256 bitów)
    RAND_bytes(key, KEY_SIZE);

    string inputFile = "plik_10gb.bin";
    string encryptedFile = "encryptedFile.bin";
    string decryptedFile = "decryptedFile.bin";

    auto start = chrono::high_resolution_clock::now();
    encryptFile(inputFile, encryptedFile, key); // IV zniknęło z argumentów!
    auto end = chrono::high_resolution_clock::now();
    double encryptionTime = chrono::duration<double>(end - start).count();
    cout << "Czas szyfrowania: " << encryptionTime << " s" << endl;

    start = chrono::high_resolution_clock::now();
    decryptFile(encryptedFile, decryptedFile, key); // IV zniknęło z argumentów!
    end = chrono::high_resolution_clock::now();
    double decryptionTime = chrono::duration<double>(end - start).count();
    cout << "Czas deszyfrowania: " << decryptionTime << " s" << endl;

    writeTimesToFile(encryptionTime, decryptionTime);

    return 0;
}
