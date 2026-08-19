#pragma once
#include <cstdint>
#include <string>


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
  std::string filename = "";

  std::string keysDir = "keys";
  std::string pubDir = "";
  std::string secDir = "";
  
  bool verbose = false;
};
