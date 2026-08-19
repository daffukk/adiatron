#pragma once
#include <cstdint>
#include <string>
#include <filesystem>
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

void findKeys(
    std::filesystem::path& pubPath,
    std::filesystem::path&secPath,
    const Config& cfg
);
