#pragma once
#include <cstdint>
#include <sodium/crypto_secretbox.h>
#include <string>
#include <vector>

// =================
//  CONSTANTS
// =================

constexpr size_t CHUNK_SIZE = 2 << 20;
constexpr uint64_t KiB = 1ULL << 10;
constexpr uint64_t MiB = 1ULL << 20;
constexpr uint64_t GiB = 1ULL << 30;
constexpr uint64_t TiB = 1ULL << 40;

constexpr size_t ENC_U64_SIZE =
  crypto_secretbox_NONCEBYTES +
  crypto_secretbox_MACBYTES + 
  sizeof(uint64_t); // 48

// =================
//  CONFIG
// =================

struct Config {
  std::string mode;

  std::string archive;
  std::vector<std::string> inputs; // input files (encrypt/add)
  std::vector<uint64_t> ids;
  std::string filename = "";
  std::string destPath = "";
  bool plainCount = false; // disable filecount encryption/decryption
  bool plainBF = false;

  std::string keysDir = "keys";
  std::string pubPath= "";
  std::string secPath = ""; 
  bool usePassphrase = false;
  bool noKeyFormat = false;
  
  bool verbose = false;

  bool recordFtime = false;
  bool recordAtime = false;
};
