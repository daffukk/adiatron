#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <ios>
#include <iostream>
#include <ostream>
#include <sodium.h>
#include <sodium/core.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sodium/crypto_kdf.h>
#include <sodium/crypto_secretbox.h>
#include <sys/types.h>
#include <vector>
#include "headers.h"





bool decryptMeta(const uint8_t* data, size_t len, uint64_t entryId, const unsigned char * streamKey, FileEntry& outEntry) {
  if(len < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) return false;

  const unsigned char* nonce = data;
  const unsigned char* ciphertext = data + crypto_secretbox_NONCEBYTES;
  size_t ciphertextLen = len - crypto_secretbox_NONCEBYTES;

  unsigned char metaKey[crypto_secretbox_KEYBYTES];
  crypto_kdf_derive_from_key(metaKey, sizeof metaKey, entryId, "FILEMETA", streamKey);

  std::vector<uint8_t> plaintext(ciphertextLen - crypto_secretbox_MACBYTES);
  if(crypto_secretbox_open_easy(plaintext.data(), ciphertext, ciphertextLen, nonce, metaKey) != 0) {
    return false;
  }

  ByteReader r(plaintext.data(), plaintext.size());
  outEntry.id = entryId;
  outEntry.path = r.readString();
  outEntry.dataSize = r.readU64();
  return true;
}



bool decryptFileData(std::ifstream& in, uint64_t dataLen, uint64_t entryId, const unsigned char* streamKey, const fs::path& outPath) {
  unsigned char dataKey[crypto_secretstream_xchacha20poly1305_KEYBYTES];
  crypto_kdf_derive_from_key(dataKey, sizeof dataKey, entryId, "FILEDATA", streamKey);

  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  in.read(reinterpret_cast<char*>(header), sizeof header);
  if(in.gcount() != static_cast<std::streamsize>(sizeof header)) {
    std::cerr << "Unexpected end of file while reading stream header\n";
    return false;
  }

  crypto_secretstream_xchacha20poly1305_state state;
  if(crypto_secretstream_xchacha20poly1305_init_pull(&state, header, dataKey) != 0) {
    std::cerr << "Failed to init decryption stream\n";
    return false;
  }

  uint64_t remaining = dataLen - sizeof header;

  fs::create_directories(outPath.parent_path());
  std::ofstream out(outPath, std::ios::binary);
  if(!out) {
    std::cerr << "Cannot create output file: " << outPath << "\n";
    return false;
  }

  unsigned char fileBuffer[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
  unsigned char outBuffer[CHUNK_SIZE];

  while (remaining > 0) {
    size_t toRead = std::min<uint64_t>(remaining, sizeof fileBuffer);
    in.read(reinterpret_cast<char*>(fileBuffer), toRead);
    std::streamsize readBytes = in.gcount();
    if(readBytes <= 0) {
      std::cerr << "Unexpected end of line while reading chunk\n";
      return false;
    }

    unsigned long long outLen;
    unsigned char tag;
    if(crypto_secretstream_xchacha20poly1305_pull(&state, outBuffer, &outLen, &tag, fileBuffer, readBytes, nullptr, 0) != 0) {
      std::cerr << "Failed to decrypt chunk. File may be corrupted or forged.\n";
      return false;
    }

    out.write(reinterpret_cast<char*>(outBuffer), outLen);
    remaining -= readBytes;

    if(tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && remaining != 0) {
      std::cerr << "Stream ended early, file may be truncated.\n";
      return false;
    }
  }
  return true;
}






int decrypt(Config cfg) {

  if(cfg.pubDir.length() < 1 && cfg.secDir.length() < 1) {
    if(!fs::is_directory(cfg.keysDir)) {
      std::cout << "Generating keys...\n";
      generateKeypair();
    }
  }


  if(sodium_init() != 0) {
    std::cerr << "Error sodium\n";
  }


  std::ifstream file(cfg.file, std::ios::binary);
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
  pubFile.read(reinterpret_cast<char*>(publicKey), crypto_box_PUBLICKEYBYTES);
  std::ifstream secFile(secPath, std::ios::binary);
  secFile.read(reinterpret_cast<char*>(secretKey), crypto_box_SECRETKEYBYTES);



  // Reading official data and decrypting stream key

  unsigned char boxNonce[crypto_box_NONCEBYTES];
  file.read(reinterpret_cast<char*>(boxNonce), sizeof boxNonce);
  unsigned char boxedKey[crypto_box_MACBYTES + crypto_secretstream_xchacha20poly1305_KEYBYTES];
  file.read(reinterpret_cast<char*>(boxedKey), sizeof boxedKey);


  unsigned char streamKey[crypto_secretstream_xchacha20poly1305_KEYBYTES];
  if(crypto_box_open_easy(streamKey, boxedKey, sizeof boxedKey, boxNonce, publicKey, secretKey) != 0) {
    std::cerr << "Failed to decrypt streamKey\n";
    return -1;
  }



  std::string outDirName;
  if(cfg.filename != "" && cfg.filename.size() > 0) {
    outDirName = cfg.filename;
  } else {
    outDirName = cfg.file + ".out";
  }

  fs::create_directories(outDirName);
  

  uint64_t fileCount = 0;
  file.read(reinterpret_cast<char*>(&fileCount), sizeof fileCount);
  if(file.gcount() != static_cast<std::streamsize>(sizeof fileCount)) {
    std::cerr << "Failed to read file count, archive may be corrupted\n";
    return -1;
  }

  std::cout << "Decrypting " << fileCount<< " file(s)\n";


  for(uint64_t i=0; i < fileCount; i++) {
    uint64_t metaLen = 0;
    file.read(reinterpret_cast<char*>(&metaLen), sizeof metaLen);
    if(file.gcount() != static_cast<std::streamsize>(sizeof metaLen)) {
      std::cerr << "Unexpected end  of file while reading meta lengh\n";
      return -1;
    }

    std::vector<uint8_t> metaBlock(metaLen);
    file.read(reinterpret_cast<char*>(metaBlock.data()), metaLen);
    if(file.gcount() != static_cast<std::streamsize>(metaLen)) {
      std::cerr << "Unexpected end of file while reading meta block\n";
      return -1;
    }

    FileEntry e;
    if(!decryptMeta(metaBlock.data(), metaBlock.size(), i, streamKey, e)) {
      std::cerr << "Failed to decrypt metadata for entry " << i << "\n";
      return -1;
    }

    uint64_t dataLen = 0;
    file.read(reinterpret_cast<char*>(&dataLen), sizeof dataLen);
    if(file.gcount() != static_cast<std::streamsize>(sizeof dataLen)) {
      std::cerr << "Unexpected end of file while reading data length\n";
      return -1;
    }

    fs::path outPath = fs::path(outDirName) / e.path;
    if(!decryptFileData(file, dataLen, e.id, streamKey, outPath)) {
      std::cerr << "Failed to decrypt file: " << e.path << "\n";
      return -1;
    }

    std::string sign;
    std::cout << (cfg.verbose ? "" : "\r\033[K") 
      << "Decrypted: " 
      << e.path 
      << " (" << convertBytes(e.dataSize, sign) << sign << ")";
    cfg.verbose ? std::cout << "\n" : std::cout << std::flush;
  }


  std::cout << "\nDecrypted successfully\n";
  return 0;
}
