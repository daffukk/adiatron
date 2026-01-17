#include <filesystem>
#include <fstream>
#include <iostream>
#include <sodium.h>
#include <sodium/core.h>
#include <sodium/crypto_box.h>
#include <vector>
#include "headers.h"


namespace fs = std::filesystem;


int decrypt(int argc, char* argv[]) {

   if(!fs::is_directory("keys")) {
    std::cout << "Generating keys...\n";
    generateKeypair();
  }


  if(argc < 3) {
    return 1;
  }


  if(sodium_init() != 0) {
    std::cerr << "Error sodium\n";
  }

  unsigned char publicKey[crypto_box_PUBLICKEYBYTES];
  unsigned char secretKey[crypto_box_SECRETKEYBYTES];

  fs::path pubPath, secPath;
  findKeys(pubPath, secPath);

  std::ifstream pubFile(pubPath, std::ios::binary);
  std::ifstream secFile(secPath, std::ios::binary);

  pubFile.read(reinterpret_cast<char*>(publicKey), crypto_box_PUBLICKEYBYTES);
  secFile.read(reinterpret_cast<char*>(secretKey), crypto_box_SECRETKEYBYTES);


  std::size_t fileSize = fs::file_size(argv[2]);
  std::size_t encryptedFileSize = fileSize - crypto_box_NONCEBYTES;
  std::size_t decryptedContentFileSize = encryptedFileSize - crypto_box_MACBYTES;

  unsigned char nonce[crypto_box_NONCEBYTES];
  std::vector<unsigned char> encryptedContent(encryptedFileSize);

  std::ifstream cipherFile(argv[2], std::ios::binary);
  cipherFile.read(reinterpret_cast<char*>(nonce), sizeof nonce);
  cipherFile.read(reinterpret_cast<char*>(encryptedContent.data()), encryptedFileSize);

//  std::vector<unsigned char> encryptedContent(std::istreambuf_iterator<char>(cipherFile), {});


  std::vector<unsigned char> decryptedContent(decryptedContentFileSize);
  if(crypto_box_open_easy(decryptedContent.data(), encryptedContent.data(), encryptedFileSize, nonce, publicKey, secretKey) != 0) {
    std::cerr << "Failed to decrypt\n";
  }

  std::string outputName = std::string(argv[2]) + ".out";

  std::ofstream out(outputName.c_str(), std::ios::binary);
  out.write(reinterpret_cast<char*>(decryptedContent.data()), decryptedContentFileSize);

  return 0;

}
