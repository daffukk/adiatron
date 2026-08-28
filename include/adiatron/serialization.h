#pragma once
#include <filesystem>
#include <cstdint>
#include <vector>
#include <string>
#include "config.h"





enum class EntryType : uint8_t {
  file = 1,
  directory = 2
};


struct FileEntry {
  uint64_t id;
  EntryType type;

  std::string path;
  int64_t mtime;

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


// =================
// BITFLAGS
// =================

struct BitFlags {
  bool Ftime=false;
};

namespace BitFlag {
  constexpr uint64_t FTIME = 1ULL << 0;
}

uint64_t writeBitFlags(const Config& cfg);
BitFlags readBitFlags(uint64_t flags);


// =================
//  FILETIME
// =================

int64_t toUnixTime(std::filesystem::file_time_type ftime);
std::filesystem::file_time_type fromUnixTime(int64_t unixTime);
