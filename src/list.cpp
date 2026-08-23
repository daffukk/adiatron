#include <adiatron/serialization.h>
#include <adiatron/filesystem.h>
#include <adiatron/commands.h>
#include <adiatron/config.h>
#include <adiatron/utils.h>
#include <cstdint>
#include <iostream>




int list(const Config& cfg) {

  OpenedArchive archive;
  if(!openArchive(cfg, archive)) return -1;

  std::cout << "Archive contains " << archive.fileCount << " file(s):\n";

  for(uint64_t i=0; i < archive.fileCount; i++) {
    uint64_t metaLen = 0;
    archive.file.read(reinterpret_cast<char*>(&metaLen), sizeof metaLen);
    if(archive.file.gcount() != static_cast<std::streamsize>(sizeof metaLen)) {
      std::cerr << "Unexpected end  of file while reading meta lengh\n";
      return -1;
    }

    std::vector<uint8_t> metaBlock(metaLen);
    archive.file.read(reinterpret_cast<char*>(metaBlock.data()), metaLen);
    if(archive.file.gcount() != static_cast<std::streamsize>(metaLen)) {
      std::cerr << "Unexpected end of file while reading meta block\n";
      return -1;
    }

    FileEntry e;
    if(!decryptMeta(metaBlock.data(), metaBlock.size(), i, archive.streamKey, e)) {
      std::cerr << "Failed to decrypt metadata for entry " << i << "\n";
      return -1;
    }

    std::string sign;
    std::cout << "  " << e.path << " (" << convertBytes(e.dataSize, sign) << sign << ")\n";

    uint64_t dataLen = 0;
    archive.file.read(reinterpret_cast<char*>(&dataLen), sizeof dataLen);
    archive.file.seekg(dataLen, std::ios::cur);
  }

  return 0;
}
