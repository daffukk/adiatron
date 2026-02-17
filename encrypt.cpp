#include <filesystem>
#include <string>
#include <fstream>
#include <iostream>
#include <sodium.h>
#include <sodium/core.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include "headers.h"




int encrypt(Config cfg) {
namespace fs = std::filesystem;
 
  if(!fs::is_directory(cfg.keysDir)) {
    std::cout << "Generating keys...\n";
    generateKeypair();
  }


  if(sodium_init() != 0) {
    std::cerr << "Error sodium\n";
    return -1;
  }


  std::string inputfile = cfg.file;
  if(cfg.isDir) {
    tarArchive(cfg.file);
    inputfile = "archive.tar";
  }


  std::ifstream file(inputfile,  std::ios::binary);
  if(!file) {
    std::cerr << "Cannot open input file\n";
    return -1;
  }

  // Reading keys

  unsigned char publicKey[crypto_box_PUBLICKEYBYTES];
  unsigned char secretKey[crypto_box_SECRETKEYBYTES];

  fs::path pubPath, secPath;
  findKeys(pubPath, secPath, cfg);

  std::ifstream pubFile(pubPath, std::ios::binary);
  std::ifstream secFile(secPath, std::ios::binary);

  pubFile.read(reinterpret_cast<char*>(publicKey), crypto_box_PUBLICKEYBYTES);
  secFile.read(reinterpret_cast<char*>(secretKey), crypto_box_SECRETKEYBYTES);


  // Generating stream key 

  unsigned char streamKey[crypto_secretstream_xchacha20poly1305_KEYBYTES];
  crypto_secretstream_xchacha20poly1305_keygen(streamKey);

  unsigned char boxNonce[crypto_box_NONCEBYTES];
  randombytes_buf(boxNonce, sizeof boxNonce);

  unsigned char boxedKey[crypto_box_MACBYTES + crypto_secretstream_xchacha20poly1305_KEYBYTES];
  if(crypto_box_easy(boxedKey, streamKey, sizeof streamKey, boxNonce, publicKey, secretKey) != 0) {
    std::cerr << "Failed to encrypt.\n";
    return 1;
  }


  crypto_secretstream_xchacha20poly1305_state state;
  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

  crypto_secretstream_xchacha20poly1305_init_push(&state, header, streamKey);


  // Writing official data into file 

  std::string filename;
  if(cfg.filename != "" && cfg.filename.size() > 0) {
    filename = cfg.filename;
  } else {
    filename = cfg.file + ".enc";
  }

  std::ofstream out(filename.c_str(), std::ios::binary);
  out.write(reinterpret_cast<char*>(boxNonce), sizeof boxNonce);
  out.write(reinterpret_cast<char*>(boxedKey), sizeof boxedKey);
  out.write(reinterpret_cast<char*>(header), sizeof header);


  // Encypting file by chunks

  unsigned char fileBuffer[CHUNK_SIZE];
  unsigned char outBuffer[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];

  while(file.good()) {
    file.read(reinterpret_cast<char*>(fileBuffer), CHUNK_SIZE);
    std::streamsize readBytes = file.gcount();

    if(readBytes <= 0) break;

    unsigned long long out_len;
    crypto_secretstream_xchacha20poly1305_push(
        &state,
        outBuffer,
        &out_len,
        fileBuffer,
        readBytes,
        nullptr, 0,
        crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
    );
    out.write(reinterpret_cast<char*>(outBuffer), out_len);
  }

  if(cfg.isDir) {
    fs::remove("archive.tar");
  }

  std::cout << "Encrypted successfully\n";
  return 0;
}
