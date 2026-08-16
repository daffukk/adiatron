#pragma once
#include <stdexcept>
#include <vector>
#include <cstdint>
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
  std::string filename = "";

  std::string keysDir = "keys";
  std::string pubDir = "";
  std::string secDir = "";
  
  bool verbose = false;
};


namespace fs = std::filesystem;
void findKeys(fs::path& pubPath, fs::path&secPath, Config cfg);
void generateKeypair();
int encrypt(Config cfg);
int decrypt(Config cfg);


double convertBytes(double n, std::string& sign);


// ==================
//  FILESYSTEM
// ==================

enum class EntryType : uint8_t {
  file = 1,
  directory = 2
};

struct FileEntry {
  uint64_t id;
  EntryType type;

  std::string path;

  uint64_t dataSize;
  uint64_t encryptedSize;
  uint64_t dataOffset;
};


class ByteWriter {
public:
  std::vector<uint8_t> buf;

  void writeU8(uint8_t v) {
    buf.push_back(v);
  }

  void writeU64(uint64_t v) {
    for(int i=0; i<8; i++) {
      buf.push_back(static_cast<uint8_t>(v >> (8 * i)));
    }
  }

  void writeString(const std::string& s) {
    writeU64(static_cast<uint64_t>(s.size()));
    buf.insert(buf.end(), s.begin(), s.end());
  }
};

class ByteReader {
public:
  const uint8_t* data;
  size_t size;
  size_t pos=0;

  ByteReader(const uint8_t* d, size_t s) : data(d), size(s) {}

  uint8_t readU8() {
    if(pos + 1 > size) throw std::runtime_error("out of bounds");
    return data[pos++];
  }

  uint64_t readU64() {
    if(pos + 8 > size) throw std::runtime_error("out of bounds");
    uint64_t v = 0;
    for(int i=0; i < 8; i++) { 
      v |= static_cast<uint64_t>(data[pos + i]) << (8 * i);
    }
    pos += 8;
    return v;
  }

  std::string readString() {
    uint64_t len = readU64();
    if(pos + len > size) throw std::runtime_error("out of bounds");
    std::string s(reinterpret_cast<const char*>(data + pos), len);
    pos+=len;
    return s;
  }
};



void writeEntry(ByteWriter& w, const FileEntry& e);
FileEntry readEntry(ByteReader& r);





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


