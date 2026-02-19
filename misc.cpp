#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sodium/crypto_box.h>
#include <sodium/crypto_generichash.h>
#include <string>
#include <sodium.h>
#include <filesystem>
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

bool tarArchive(const std::string& dir) {

  if(system("tar --version > /dev/null 2>&1") != 0) {
    std::cerr << "Tar not found.\n";
    return false;
  }

  std::string cmd = "tar -cf archive.tar --numeric-owner --owner=0 --group=0"
                    " --mtime='1970-01-01' --sort=name " + dir;
  return system(cmd.c_str()) == 0;
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
