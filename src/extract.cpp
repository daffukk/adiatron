#include "adiatron/serialization.h"
#include <adiatron/filesystem.h>
#include <adiatron/terminal.h>
#include <adiatron/config.h>
#include <adiatron/utils.h>
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <vector>





int extract(const Config& cfg) {
namespace fs = std::filesystem;

  if(sodium_init() != 0) {
    std::cerr << "Error sodium\n";
  }



  OpenedArchive archive;
  if(!openArchive(cfg, archive)) return -1;

  BitFlags bf = readBitFlags(archive.flags);


  for(auto i : cfg.ids) {
    if(archive.fileCount + 1 < i) {
      throw std::runtime_error("Id out of range");
    }
  }

  std::string outDirName;
  if(cfg.filename != "" && cfg.filename.size() > 0) {
    outDirName = cfg.filename;
  } else {
    fs::path p(cfg.archive);

    if(p.filename().empty()) {
      p = p.parent_path();
    }
    outDirName = p.string() + ".out";
  }
  fs::create_directories(outDirName);

  int terminalWidth = getTerminalWidth() - 45;
  uint64_t done=0;
  for(uint64_t i=0; i < archive.fileCount; i++) {
    FileEntry e;
    if(!decryptEntryMeta(archive.file, archive.streamKey, e, bf, i))
      throw std::runtime_error("Failed to decrypt metadata for entry " + i);

    uint64_t dataLen = 0;
    if(!readEncU64(archive.file, dataLen, archive.streamKey, "DATASIZE")) {
      std::cerr << "Failed to read data length for entry " << i << "\n";
      return -1;
    }

    if(std::find(cfg.ids.begin(), cfg.ids.end(), e.id) != cfg.ids.end()) {
      std::string sign;
      std::cout << (cfg.verbose ? "" : "\r\033[K")
        << e.id << "  " 
        << color::cyan
        << truncateMiddle(e.path, terminalWidth)
        << color::yellow
        << " (" << convertBytes(e.dataSize, sign) << sign << ")"
        << color::reset;
      cfg.verbose ? std::cout << "\n" : std::cout << std::flush;
      

      fs::path outPath = fs::path(outDirName) / e.path;
      if(!decryptFileData(archive.file, dataLen, e.id, archive.streamKey, outPath)) {
        std::cerr << "Failed to decrypt file: " << e.path << "\n";
        return -1;
      }

      if(bf.Ftime) fs::last_write_time(outPath, fromUnixTime(e.mtime));

      ++done;
      if(done == cfg.ids.size()) break;
    } else{
      archive.file.seekg(dataLen, std::ios::cur);
    }
  }


  std::cout << "\n==> Decrypted successfully\n";
  return 0;
}
