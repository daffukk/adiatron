#include <cmath>
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
