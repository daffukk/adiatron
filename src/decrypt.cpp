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
#include <adiatron/config.h>
#include <adiatron/filesystem.h>
#include <adiatron/serialization.h>
#include <adiatron/commands.h>
#include <adiatron/terminal.h>
#include <adiatron/utils.h>

namespace fs = std::filesystem;



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






int decrypt(const Config& cfg) {

  if(cfg.pubDir.length() < 1 && cfg.secDir.length() < 1) {
    if(!fs::is_directory(cfg.keysDir)) {
      std::cout << "Generating keys...\n";
      generateKeypair();
    }
  }

  if(sodium_init() != 0) {
    std::cerr << "Error sodium\n";
  }



  OpenedArchive archive;
  if(!openArchive(cfg, archive)) return -1;


  std::string outDirName;
  if(cfg.filename != "" && cfg.filename.size() > 0) {
    outDirName = cfg.filename;
  } else {
    fs::path p(cfg.file);

    if(p.filename().empty()) {
      p = p.parent_path();
    }
    outDirName = p.string() + ".out";
  }
  fs::create_directories(outDirName);


  std::cout << "Decrypting " << archive.fileCount << " file(s)\n";

  int terminalWidth = getTerminalWidth();
  for(uint64_t i=0; i < archive.fileCount; i++) {
    uint64_t metaLen = 0;
    archive.file.read(reinterpret_cast<char*>(&metaLen), sizeof metaLen);
    if(archive.file.gcount() != static_cast<std::streamsize>(sizeof metaLen)) {
      std::cerr << "Unexpected end  of file while reading meta lengh\n";
      return -1;
    }

    std::vector<uint8_t> metaBlock(metaLen);
    archive.file.read(reinterpret_cast<char*>(metaBlock.data()), metaLen);
    if(archive.file.gcount() != static_cast<std::streamsize>(metaLen)) {
      std::cerr << "Unexpected end of file while reading meta block\n";
      return -1;
    }

    FileEntry e;
    if(!decryptMeta(metaBlock.data(), metaBlock.size(), i, archive.streamKey, e)) {
      std::cerr << "Failed to decrypt metadata for entry " << i << "\n";
      return -1;
    }

    uint64_t dataLen = 0;
    archive.file.read(reinterpret_cast<char*>(&dataLen), sizeof dataLen);
    if(archive.file.gcount() != static_cast<std::streamsize>(sizeof dataLen)) {
      std::cerr << "Unexpected end of file while reading data length\n";
      return -1;
    }

    fs::path outPath = fs::path(outDirName) / e.path;
    if(!decryptFileData(archive.file, dataLen, e.id, archive.streamKey, outPath)) {
      std::cerr << "Failed to decrypt file: " << e.path << "\n";
      return -1;
    }

    std::string sign;
    double precent = (double(e.id) / archive.fileCount) * 100;

    std::cout << (cfg.verbose ? "" : "\r\033[K") 
      << e.id << "/" << archive.fileCount << "(" << std::fixed << std::setprecision(2) <<precent << "%) "
      << "Decrypted: " 
      << truncateMiddle(e.path, terminalWidth)
      << " (" << convertBytes(e.dataSize, sign) << sign << ")";
    cfg.verbose ? std::cout << "\n" : std::cout << std::flush;
  }


  std::cout << "\n==> Decrypted successfully\n";
  return 0;
}
