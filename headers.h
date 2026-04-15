#pragma once
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>


constexpr size_t CHUNK_SIZE = 2 << 20;
constexpr uint64_t KiB = 1ULL << 10;
constexpr uint64_t MiB = 1ULL << 20;
constexpr uint64_t GiB = 1ULL << 30;
constexpr uint64_t TiB = 1ULL << 40;

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


double convertBytes(double n, std::string& sign);

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
    << "\t-o, --filename \t Specify an output filename.\n"
    << "\t--keydir \t Specify 'keys' directory location.\n";
}


