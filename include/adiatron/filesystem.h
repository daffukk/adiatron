#pragma once
#include <filesystem>
#include <sodium.h>
#include <cstdint>
#include <fstream>
#include "config.h"
#include "serialization.h"





bool findKeys(
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


// =================
//  ENCRYPT
// =================



struct CreatedArchive {
  std::ofstream file;
  unsigned char streamKey[crypto_secretstream_xchacha20poly1305_KEYBYTES];
  uint64_t flags;
};


bool createArchive(const Config& cfg, CreatedArchive &out, uint64_t fileCount);

std::vector<std::filesystem::path> collectFiles(const std::string& file);

std::vector<uint8_t> encryptMeta(
    const FileEntry& e, 
    const unsigned char* streamKey,
    const BitFlags& bf
);

uint64_t encryptFileData(
    std::ostream& out, 
    const std::filesystem::path& filePath, 
    uint64_t entryId, 
    const unsigned char* streamKey
);
