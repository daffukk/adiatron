#pragma once
#include <cstdint>
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

// =================
//  CONFIG
// =================

struct Config {
  std::string mode;

  std::string file;
  std::vector<std::string> files;
  std::string filename = "";
  std::string target;
  uint64_t fileId;

  std::string keysDir = "keys";
  std::string pubPath= "";
  std::string secPath = ""; 
  bool usePassphrase = false;
  bool noKeyFormat = false;
  
  bool verbose = false;

  bool recordFtime = false;
  bool recordAtime = false;
};
