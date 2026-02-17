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
  std::string keysDir = "keys";
  std::string pubDir = "";
  std::string secDir = "";
};


namespace fs = std::filesystem;
void findKeys(fs::path& pubPath, fs::path&secPath, Config cfg);
void generateKeypair();
int encrypt(Config cfg);
int decrypt(Config cfg);
bool tarArchive(const std::string& dir);




inline void printHelp(int argc, char* argv[]) {
  std::cout
    << "Usage: " << argv[0] << " <ENCRYPT/DECRYPT> <OPTIONS>\n"
    << "\n"
    << "Examples:\n"
    << "\t" << argv[0] << " ecnrypt file.txt\n"
    << "\t" << argv[0] << " decrypt file.enc\n"
    << "\t" << argv[0] << " keygen\n"
    << "\n"
    << "Options:\n"
    << "Flags can be used in --filename cookies.png or --filename=cookies.png format\n"
    << "\t-d, --dir \t You can specify a folder, it will automatically be archived into anonymous .tar archive and encrypted.\n"
    << "\t--filename \t Specify an output filename.\n";
}


