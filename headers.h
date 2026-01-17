#pragma once
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>

void generateKeypair();
int encrypt(int argc, char* argv[]);
int decrypt(int argc, char* argv[]);


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

