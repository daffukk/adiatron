#pragma once
#include <filesystem>
#include <sodium.h>
#include <cstdint>
#include <fstream>
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

  uint64_t dataSize;
  uint64_t encryptedSize;
  uint64_t dataOffset;
};

struct OpenedArchive {
  std::ifstream file;
  unsigned char streamKey[crypto_secretstream_xchacha20poly1305_KEYBYTES];
  uint64_t fileCount;
};

bool openArchive(const Config& cfg, OpenedArchive& out);

bool decryptMeta(
    const uint8_t* data, 
    size_t len, 
    uint64_t entryId, 
    const unsigned char * streamKey, 
    FileEntry& outEntry
);

void findKeys(
    std::filesystem::path& pubPath,
    std::filesystem::path&secPath,
    const Config& cfg
);
