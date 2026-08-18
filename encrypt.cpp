#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <ostream>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <sodium.h>
#include <sodium/core.h>
#include <sodium/randombytes.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sodium/crypto_kdf.h>
#include <sodium/crypto_secretbox.h>
#include "headers.h"





std::vector<fs::path> collectFiles(const Config& cfg) {
  std::vector<fs::path> files;

  if(fs::is_directory(cfg.file)) {
    for(const auto& dirEntry : fs::recursive_directory_iterator(cfg.file)) {
      if(!fs::is_directory(dirEntry)) {
        files.push_back(dirEntry.path());
      }
    }
  } else {
    files.push_back(cfg.file);
  }
  return files;
}



std::vector<uint8_t> encryptMeta(const FileEntry& e, const unsigned char* streamKey) {
  ByteWriter w;
  w.writeString(e.path);
  w.writeU64(e.dataSize);

  unsigned char metaKey[crypto_secretbox_KEYBYTES];
  crypto_kdf_derive_from_key(metaKey, sizeof metaKey, e.id, "FILEMETA", streamKey);

  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  randombytes_buf(nonce, sizeof nonce);

  std::vector<uint8_t> ciphertext(w.buf.size() + crypto_secretbox_MACBYTES);
  crypto_secretbox_easy(ciphertext.data(), w.buf.data(), w.buf.size(), nonce, metaKey);

  std::vector<uint8_t> result;
  result.insert(result.end(), nonce, nonce + sizeof nonce);
  result.insert(result.end(), ciphertext.begin(), ciphertext.end());
  return result;
}



uint64_t encryptFileData(std::ofstream& out, const fs::path& filePath, uint64_t entryId, const unsigned char* streamKey) {
  unsigned char dataKey[crypto_secretstream_xchacha20poly1305_KEYBYTES];
  crypto_kdf_derive_from_key(dataKey, sizeof dataKey, entryId, "FILEDATA", streamKey);

  crypto_secretstream_xchacha20poly1305_state state;
  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  crypto_secretstream_xchacha20poly1305_init_push(&state, header, dataKey);

  out.write(reinterpret_cast<char*>(header), sizeof header);
  uint64_t written = sizeof header;

  std::ifstream file(filePath, std::ios::binary);
  unsigned char fileBuffer[CHUNK_SIZE];
  unsigned char outBuffer[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];

  while(true) {
    file.read(reinterpret_cast<char*>(fileBuffer), CHUNK_SIZE);
    size_t readBytes = file.gcount();
    if(readBytes <= 0) break;

    bool isLast = file.eof();
    unsigned char tag = isLast ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

    unsigned long long outLen;
    crypto_secretstream_xchacha20poly1305_push(&state, outBuffer, &outLen, fileBuffer, readBytes, nullptr, 0, tag);
    out.write(reinterpret_cast<char*>(outBuffer), outLen);
    written += outLen;
  }
  return written;
}






int encrypt(Config cfg) {

  if(cfg.pubDir.length() > 0 && cfg.secDir.length() > 0) {
    std::cout << "Keys found.\n";
  } else {
    if(!fs::is_directory(cfg.keysDir)) {
      std::cout << "Generating keys...\n";
      generateKeypair();
    }
  }


  if(sodium_init() != 0) {
    std::cerr << "Error sodium\n";
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


  // Writing official data into file 

  std::string filename;
  if(cfg.filename != "" && cfg.filename.size() > 0) {
    filename = cfg.filename;
  } else {
    fs::path p(cfg.file);

    if(p.filename().empty()) {
      p = p.parent_path();
    }
    filename = p.string() + ".enc";
  }

  std::ofstream out(filename.c_str(), std::ios::binary);

  out.write(reinterpret_cast<char*>(boxNonce), sizeof boxNonce);
  out.write(reinterpret_cast<char*>(boxedKey), sizeof boxedKey);


  std::vector<fs::path> files = collectFiles(cfg);

  uint64_t fileCount = files.size();
  out.write(reinterpret_cast<char*>(&fileCount), sizeof fileCount);

  uint64_t nextId = 0;
  bool isDirSource = fs::is_directory(cfg.file);

  int terminalWidth = getTerminalWidth();

  for(const auto& filePath : files) {
    FileEntry e;
    e.id = nextId++;
    e.type = EntryType::file;

    if(isDirSource) {
      e.path = fs::relative(filePath, cfg.file).generic_string();
    } else {
      e.path = filePath.filename().generic_string();
    }

    e.dataSize = fs::file_size(filePath);

    auto metaBlock = encryptMeta(e, streamKey);
    uint64_t metaLen = metaBlock.size();
    out.write(reinterpret_cast<char*>(&metaLen), sizeof metaLen);
    out.write(reinterpret_cast<char*>(metaBlock.data()), metaBlock.size());

    std::streampos lenPos = out.tellp();
    uint64_t placeholder = 0;
    out.write(reinterpret_cast<char*>(&placeholder), sizeof placeholder);

    uint64_t encLen = encryptFileData(out, filePath, e.id, streamKey);

    std::streampos afterPos = out.tellp();
    out.seekp(lenPos);
    out.write(reinterpret_cast<char*>(&encLen), sizeof encLen);
    out.seekp(afterPos);

    
    std::string sign;
    double precent = (double(e.id) / files.size()) * 100;

    std::cout << (cfg.verbose ? "" : "\r\033[K") 
      << e.id << "/" << files.size() << "(" << std::fixed << std::setprecision(2) << precent << "%) "
      << "Encrypted: " 
      << truncateMiddle(e.path, terminalWidth)
      << " (" << convertBytes(e.dataSize, sign) << sign << ")";
    cfg.verbose ? std::cout << "\n" : std::cout << std::flush;
  }


  std::cout << "\n==> Encrypted successfully.\n";
  return 0;
}
