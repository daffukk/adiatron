#include <filesystem>
#include <fstream>
#include <ios>
#include <iostream>
#include <sodium.h>
#include <sodium/core.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <vector>
#include "headers.h"




int decrypt(int argc, char* argv[]) {
namespace fs = std::filesystem;

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


  std::ifstream file(argv[2],  std::ios::binary);
  if(!file) {
    std::cerr << "Cannot open input file\n";
    return -1;
  }

  // Reading keys

  unsigned char publicKey[crypto_box_PUBLICKEYBYTES];
  unsigned char secretKey[crypto_box_SECRETKEYBYTES];

  fs::path pubPath, secPath;
  findKeys(pubPath, secPath);

  std::ifstream pubFile(pubPath, std::ios::binary);
  pubFile.read(reinterpret_cast<char*>(publicKey), crypto_box_PUBLICKEYBYTES);
  std::ifstream secFile(secPath, std::ios::binary);
  secFile.read(reinterpret_cast<char*>(secretKey), crypto_box_SECRETKEYBYTES);



  // Reading official data and decrypting stream key

  unsigned char boxNonce[crypto_box_NONCEBYTES];
  file.read(reinterpret_cast<char*>(boxNonce), sizeof boxNonce);
  unsigned char boxedKey[crypto_box_MACBYTES + crypto_secretstream_xchacha20poly1305_KEYBYTES];
  file.read(reinterpret_cast<char*>(boxedKey), sizeof boxedKey);
  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  file.read(reinterpret_cast<char*>(header), sizeof header);

  unsigned char streamKey[crypto_secretstream_xchacha20poly1305_KEYBYTES];
  if(crypto_box_open_easy(streamKey, boxedKey, sizeof boxedKey, boxNonce, publicKey, secretKey) != 0) {
    std::cerr << "Failed to decrypt streamKey\n";
    return -1;
  }


  crypto_secretstream_xchacha20poly1305_state state;
  crypto_secretstream_xchacha20poly1305_init_pull(&state, header, streamKey);
  std::ofstream out("output.out", std::ios::binary);


  // Decrypting file by chunks
  
  unsigned char fileBuffer[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
  unsigned char outBuffer[CHUNK_SIZE];

  while(file.good()) {
    file.read(reinterpret_cast<char*>(fileBuffer), CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
    std::streamsize readBytes = file.gcount();

    if(readBytes <= 0) break;

    unsigned long long out_len;
    unsigned char tag;
    if(crypto_secretstream_xchacha20poly1305_pull(&state, outBuffer, &out_len, &tag, fileBuffer, readBytes, nullptr, 0) != 0) {
      std::cerr << "Failed to decrypt file. Maybe it's corrupted or forged.\n";
      return -1;
    }

    out.write(reinterpret_cast<char*>(outBuffer), out_len);
  }


  std::cout << "Decrypted successfully\n";
  return 0;
}
