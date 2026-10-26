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



bool readEncU64(std::istream& f, uint64_t& v,
                const unsigned char* streamKey,
                const char (&ctx)[9], uint64_t subkeyId = 0);

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
    std::istream& in, 
    uint64_t dataLen, 
    uint64_t entryId, 
    const unsigned char* streamKey, 
    const std::filesystem::path& outPath
);


int decryptEntryMeta(std::istream& archive, const unsigned char* streamKey,
                 FileEntry& e, auto& bf, const uint64_t& id);


// =================
//  ENCRYPT
// =================

struct InputFile {
  std::filesystem::path path;
  std::string archivePath;
};

struct CreatedArchive {
  std::ofstream file;
  unsigned char streamKey[crypto_secretstream_xchacha20poly1305_KEYBYTES];
  uint64_t flags;
};



bool writeEncU64(std::ostream& f, uint64_t v,
                 const unsigned char* streamKey,
                 const char (&ctx)[9], uint64_t subkeyId = 0);

bool createArchive(const Config& cfg, CreatedArchive &out, uint64_t fileCount);

std::vector<InputFile> collectFiles(const std::vector<std::string>& sources);

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

void encryptEntry(std::ostream& archive, const unsigned char* streamKey,
                  FileEntry& e, auto& bf, const std::string& fp);
