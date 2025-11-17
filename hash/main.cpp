#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

using namespace std;
using namespace CryptoPP;

void print_usage() {
    cout << "Использование: ./hash_tool <filename>" << endl;
    cout << "Вычисляет SHA-1 хэш файла" << endl;
}

string calculate_file_hash(const string& filename) {
    try {
        ifstream file(filename, ios::binary);
        if (!file) {
            throw runtime_error("Не удалось открыть файл: " + filename);
        }

        SHA1 hash;
        string digest;
        FileSource file_source(filename.c_str(), true, 
            new HashFilter(hash, new HexEncoder(new StringSink(digest))));
        
        return digest;
    }
    catch (const exception& e) {
        throw runtime_error("Ошибка при вычислении хэша: " + string(e.what()));
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        print_usage();
        return 1;
    }

    string filename = argv[1];
    
    try {
        string hash_result = calculate_file_hash(filename);
        cout << "Файл: " << filename << endl;
        cout << "SHA-1: " << hash_result << endl;
    }
    catch (const exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
        return 1;
    }

    return 0;
}
