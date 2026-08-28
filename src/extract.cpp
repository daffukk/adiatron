#include <adiatron/filesystem.h>
#include <adiatron/terminal.h>
#include <adiatron/config.h>
#include <adiatron/utils.h>
#include <iostream>
#include <vector>





int extract(const Config& cfg) {
namespace fs = std::filesystem;

  if(sodium_init() != 0) {
    std::cerr << "Error sodium\n";
  }



  OpenedArchive archive;
  if(!openArchive(cfg, archive)) return -1;

  BitFlags bf = readBitFlags(archive.flags);


  if(archive.fileCount + 1 < cfg.fileId) {
    std::cout << "Id out of range\n";
    return -1;
  }

  std::string outDirName;
  if(cfg.filename != "" && cfg.filename.size() > 0) {
    outDirName = cfg.filename;
  } else {
    fs::path p(cfg.file);

    if(p.filename().empty()) {
      p = p.parent_path();
    }
    outDirName = p.string() + ".out";
  }
  fs::create_directories(outDirName);


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
    if(!decryptMeta(metaBlock.data(), metaBlock.size(), i, archive.streamKey, e, bf)) {
      std::cerr << "Failed to decrypt metadata for entry " << i << "\n";
      return -1;
    }

    uint64_t dataLen = 0;
    archive.file.read(reinterpret_cast<char*>(&dataLen), sizeof dataLen);
    if(archive.file.gcount() != static_cast<std::streamsize>(sizeof dataLen)) {
      std::cerr << "Unexpected end of file while reading data length\n";
      return -1;
    }

    if(e.id == cfg.fileId) {
      std::string sign;
      std::cout << "File found. Decrypting...\n";
      std::cout << e.id << "  " << e.path << " (" << convertBytes(e.dataSize, sign) << sign << ")\n";
      

      fs::path outPath = fs::path(outDirName) / e.path;
      if(!decryptFileData(archive.file, dataLen, e.id, archive.streamKey, outPath)) {
        std::cerr << "Failed to decrypt file: " << e.path << "\n";
        return -1;
      }

      if(bf.Ftime) fs::last_write_time(outPath, fromUnixTime(e.mtime));


      break;
    }

    archive.file.seekg(dataLen, std::ios::cur);
  }


  std::cout << "\n==> Decrypted successfully\n";
  return 0;
}
