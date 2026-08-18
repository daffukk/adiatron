#include <asm-generic/ioctls.h>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sys/ioctl.h>
#include <sys/unistd.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_generichash.h>
#include <string>
#include <sodium.h>
#include <filesystem>
#include <unistd.h>
#include "headers.h"



void generateKeypair() {

  std::filesystem::create_directories("keys/publicKey");
  std::filesystem::create_directories("keys/secretKey");

  unsigned char publicKey[crypto_box_PUBLICKEYBYTES];
  unsigned char secretKey[crypto_box_SECRETKEYBYTES];
  crypto_box_keypair(publicKey, secretKey);


  unsigned char hash[crypto_generichash_BYTES];
  crypto_generichash(hash, sizeof(hash), publicKey, crypto_box_PUBLICKEYBYTES, nullptr, 0);

  char hex[crypto_generichash_BYTES * 2 + 1];
  sodium_bin2hex(hex, sizeof(hex), hash, sizeof(hash));


  std::string shortHex = std::string(hex).substr(0, 6);


  std::string publicName = shortHex + ".pub";

  std::ofstream pk(("keys/publicKey/" + publicName).c_str(), std::ios::binary);
  std::ofstream sc(("keys/secretKey/" + shortHex).c_str(), std::ios::binary);

  pk.write(reinterpret_cast<const char*>(publicKey), crypto_box_PUBLICKEYBYTES);
  sc.write(reinterpret_cast<const char*>(secretKey), crypto_box_SECRETKEYBYTES);
  pk.close();
  sc.close();
}


void findKeys(fs::path& pubPath, fs::path&secPath, Config cfg){

  if(cfg.pubDir.length() > 1) {
    pubPath = cfg.pubDir;
  }

  if(cfg.secDir.length() > 1) {
    secPath = cfg.secDir;
  }

  if(cfg.pubDir.empty() || cfg.secDir.empty()) {
    for (const auto& entry : fs::recursive_directory_iterator(cfg.keysDir)) {
      const auto& path = entry.path();
      if(cfg.pubDir.length() < 1) {
        if(entry.path().extension() == ".pub") {
          pubPath = entry.path();
        }
      }

      if(cfg.secDir.length() < 1) {
        if(!path.has_extension() && entry.is_regular_file()) {
          secPath = entry.path();
        }
      }
    }
  }
}

double convertBytes(double n, std::string& sign) {
  if((n / TiB) >= 1) {
    sign = "TiB";
    return n / TiB;
  }

  else if((n / GiB) >= 1) {
    sign = "GiB";
    return n / GiB;
  }

  else if((n / MiB) >= 1) {
    sign = "MiB";
    return n / MiB;
  }

  else if((n / KiB) >= 1) {
    sign = "KiB";
    return n / KiB;
  }
  sign = "B";
  return n;

}

int getTerminalWidth() {
  struct winsize w;
  if(ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0) return w.ws_col - 40;
  return 80;
}


std::string truncateMiddle(const std::string& path, size_t maxLen) {
  if(path.size() <= maxLen) return path;

  size_t keep = maxLen - 3;
  size_t headLen = keep /2 ;
  size_t tailLen = keep - headLen;

  return path.substr(0, headLen) + "..." + path.substr(path.size() - tailLen);
}


// ==================
//  FILESYSTEM
// ==================

void writeEntry(ByteWriter& w, const FileEntry& e) {
  w.writeU64(e.id);
  w.writeU8(static_cast<uint8_t>(e.type));
  w.writeString(e.path);
  w.writeU64(e.dataSize);
  w.writeU64(e.encryptedSize);
  w.writeU64(e.dataOffset);
}

FileEntry readEntry(ByteReader &r) {
  FileEntry e;
  e.id            = r.readU64();
  e.type          = static_cast<EntryType>(r.readU8());
  e.path          = r.readString();
  e.dataSize      = r.readU64();
  e.encryptedSize = r.readU64();
  e.dataOffset    = r.readU64();
  return e;
}


