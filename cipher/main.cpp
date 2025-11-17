#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>

using namespace std;

void DeriveKeyAndIV(const string& password, CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE]) {
    CryptoPP::byte salt[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA1> pbkdf;
    pbkdf.DeriveKey(
        key, CryptoPP::AES::DEFAULT_KEYLENGTH,
        0,
        (const CryptoPP::byte*)password.data(), password.size(),
        salt, sizeof(salt),
        1000
    );
    
    CryptoPP::byte iv_salt[] = {0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    pbkdf.DeriveKey(
        iv, CryptoPP::AES::BLOCKSIZE,
        0,
        (const CryptoPP::byte*)password.data(), password.size(),
        iv_salt, sizeof(iv_salt),
        1000
    );
}

void EncryptFile(const string& inputFilename, const string& outputFilename, const string& password) {
    CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];

    DeriveKeyAndIV(password, key, iv);

    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, sizeof(key), iv);

        CryptoPP::FileSource fs(inputFilename.c_str(), true,
            new CryptoPP::StreamTransformationFilter(encryptor,
                new CryptoPP::FileSink(outputFilename.c_str())
            )
        );
    } catch (const CryptoPP::Exception& e) {
        cerr << "Ошибка шифрования: " << e.what() << endl;
        exit(1);
    }
}

void DecryptFile(const string& inputFilename, const string& outputFilename, const string& password) {
    CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];

    DeriveKeyAndIV(password, key, iv);

    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(key, sizeof(key), iv);

        CryptoPP::FileSource fs(inputFilename.c_str(), true,
            new CryptoPP::StreamTransformationFilter(decryptor,
                new CryptoPP::FileSink(outputFilename.c_str())
            )
        );
    } catch (const CryptoPP::Exception& e) {
        cerr << "Ошибка расшифрования: " << e.what() << endl;
        exit(1);
    }
}

void printUsage(const char* progName) {
    cout << "Программа шифрования/расшифрования файлов (AES-128-CBC, ключ из пароля через SHA-1).\n";
    cout << "  " << progName << " -e <входной_файл> <выходной_файл> <пароль>\n";
    cout << "  " << progName << " -d <входной_файл> <выходной_файл> <пароль>\n";
    cout << "  " << progName << " -h\n";
    cout << "  " << progName << " --help\n\n";
}

int main(int argc, char* argv[]) {
    if (argc == 2) {
        string arg = argv[1];
        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        }
    }

    if (argc != 5) {
        cerr << "Ошибка: неверное количество аргументов.\n\n";
        printUsage(argv[0]);
        return 1;
    }

    string mode = argv[1];
    string inFile = argv[2];
    string outFile = argv[3];
    string password = argv[4];

    if (mode == "-e") {
        EncryptFile(inFile, outFile, password);
        cout << "Файл успешно зашифрован.\n";
    } else if (mode == "-d") {
        DecryptFile(inFile, outFile, password);
        cout << "Файл успешно расшифрован.\n";
    } else {
        cerr << "Ошибка: неизвестный режим '" << mode << "'.\n\n";
        printUsage(argv[0]);
        return 1;
    }

    return 0;
}
