#include <filesystem>
#include <fstream>
#include <iostream>
#include <sodium.h>
#include <sodium/core.h>
#include <sodium/crypto_box.h>
#include <vector>
#include "headers.h"


namespace fs = std::filesystem;


int encrypt(int argc, char* argv[]) {
 
  if(!fs::is_directory("keys")) {
    std::cout << "Generating keys...\n";
    generateKeypair();
  }

  if(argc < 2) {
    return -1;
  }

  std::ifstream file(argv[2],  std::ios::binary);
  std::vector<unsigned char> fileContent(std::istreambuf_iterator<char>(file),{});
  const std::size_t fileContent_len = crypto_box_MACBYTES + fileContent.size();


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


  unsigned char nonce[crypto_box_NONCEBYTES];
  std::vector<unsigned char> encryptedContent(fileContent_len);
  randombytes_buf(nonce, sizeof nonce);
  const unsigned char* m = reinterpret_cast<const unsigned char*>(fileContent.data());

  if(crypto_box_easy(encryptedContent.data(), m, fileContent.size(), nonce, publicKey, secretKey) != 0) {
    std::cerr << "Failed to encrypt.\n";
    return 1;
  }
  
  std::ofstream out("output.enc", std::ios::binary);
  out.write(reinterpret_cast<char*>(nonce), sizeof nonce);
  out.write(reinterpret_cast<char*>(encryptedContent.data()), fileContent_len);

  return 0;
}
