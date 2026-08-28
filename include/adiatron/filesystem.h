#pragma once
#include <filesystem>
#include <sodium.h>
#include <cstdint>
#include <fstream>
#include "config.h"
#include "serialization.h"





void findKeys(
    std::filesystem::path& pubPath,
    std::filesystem::path&secPath,
    const Config& cfg
);


// =================
//  DECRYPT
// =================

struct OpenedArchive {
  std::ifstream file;
  unsigned char streamKey[crypto_secretstream_xchacha20poly1305_KEYBYTES];
  uint64_t fileCount;
  uint64_t flags;
};


bool openArchive(const Config& cfg, OpenedArchive& out);

bool decryptMeta(
    const uint8_t* data, 
    size_t len, 
    uint64_t entryId, 
    const unsigned char * streamKey, 
    FileEntry& outEntry,
    const BitFlags& bf
);

bool decryptFileData(
    std::ifstream& in, 
    uint64_t dataLen, 
    uint64_t entryId, 
    const unsigned char* streamKey, 
    const std::filesystem::path& outPath
);


