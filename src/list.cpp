#include <adiatron/serialization.h>
#include <adiatron/filesystem.h>
#include <adiatron/terminal.h>
#include <adiatron/commands.h>
#include <adiatron/config.h>
#include <adiatron/utils.h>
#include <iostream>
#include <cstdint>




int list(const Config& cfg) {
  if(sodium_init() != 0) {
    std::cerr << "Error sodium\n";
  }

  OpenedArchive archive;
  if(!openArchive(cfg, archive)) return -1;

  BitFlags bf = readBitFlags(archive.flags);
  int terminalWidth = getTerminalWidth() - 20;

  std::cout << "Archive contains " << archive.fileCount << " file(s):\n";

  for(uint64_t i=0; i < archive.fileCount; i++) {

    FileEntry e;
    decryptEntryMeta(archive.file, archive.streamKey, e, bf, i);

    std::string sign;
    std::cout
      << std::fixed << std::setprecision(2)
      << std::setw(4) << e.id << " | "
      << color::cyan
      << truncateMiddle(e.path, terminalWidth) 
      << color::yellow
      << " (" << convertBytes(e.dataSize, sign) << sign << ")\n"
      << color::reset;

    uint64_t dataLen = 0;
    if(!readEncU64(archive.file, dataLen, archive.streamKey, "DATASIZE")) {
      std::cerr << "Failed to read data length for entry " << i << "\n";
      return -1;
    }
    archive.file.seekg(dataLen, std::ios::cur);
  }

  return 0;
}
