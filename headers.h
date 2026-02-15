#pragma once
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>


constexpr size_t CHUNK_SIZE = 64 * 1024;


struct Config {
  std::string mode;
  std::string file;
  bool isDir = false;
  std::string filename = "";
};


void generateKeypair();
int encrypt(Config cfg);
int decrypt(Config cfg);


// Adiatron flags

namespace fs = std::filesystem;
inline void findKeys(fs::path& pubPath, fs::path&secPath){
  for (const auto& entry : fs::recursive_directory_iterator("keys")) {

    const auto& path = entry.path();
    
    if (entry.path().extension() == ".pub") {
      pubPath = entry.path();
    }
    else if(!path.has_extension() && entry.is_regular_file()){
      secPath = entry.path();
    }
  }
}

inline void printHelp(int argc, char* argv[]) {
  std::cout
    << "Usage: " << argv[0] << " <ENCRYPT/DECRYPT> <OPTIONS>\n"
    << "\n"
    << "Examples:\n"
    << "\t" << argv[0] << " ecnrypt file.txt\n"
    << "\t" << argv[0] << " decrypt file.enc\n"
    << "\t" << argv[0] << " keygen\n";
}


