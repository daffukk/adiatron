#pragma once
#include <string_view>
#include <cstdint>
#include <string>
#include <array>

// =================
//  CONSTANTS
// =================

constexpr size_t CHUNK_SIZE = 2 << 20;
constexpr uint64_t KiB = 1ULL << 10;
constexpr uint64_t MiB = 1ULL << 20;
constexpr uint64_t GiB = 1ULL << 30;
constexpr uint64_t TiB = 1ULL << 40;

constexpr std::array<std::string_view, 6> modes = {
  "keygen",
  "list",
  "extract",
  "encrypt",
  "decrypt",
  "--help"
};



// =================
//  CONFIG
// =================

struct Config {
  std::string mode;

  std::string file;
  std::string filename = "";
  uint64_t fileId;

  std::string keysDir = "keys";
  std::string pubDir = "";
  std::string secDir = "";
  
  bool verbose = false;

  bool recordFtime = false;
  bool recordAtime = false;
};
