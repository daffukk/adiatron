#include <adiatron/filesystem.h>
#include <adiatron/terminal.h>
#include <adiatron/config.h>
#include <adiatron/utils.h>
#include <cstdint>
#include <fstream>
#include <ios>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>






bool updateFileCount(const std::string& file, uint64_t newFileCount) {
  std::fstream f(file, std::ios::binary | std::ios::in | std::ios::out);
  if(!f) {
    std::cerr << "Failed to reopen archive for updating file count\n";
    return false;
  }

  constexpr std::streamoff FILE_COUNT_OFFSET =
    crypto_secretbox_NONCEBYTES +
    (crypto_secretbox_MACBYTES + crypto_secretstream_xchacha20poly1305_KEYBYTES) +
    sizeof(uint64_t);

  f.seekp(FILE_COUNT_OFFSET);
  f.write(reinterpret_cast<char*>(&newFileCount), sizeof newFileCount);

  return true;
}





int add(const Config& cfg) {
namespace fs=std::filesystem;

  if(sodium_init() != 0) {
    std::cerr << "Error sodium\n";
  }


  std::vector<fs::path> newFiles = collectFiles(cfg.target);
  uint64_t newFileCount = newFiles.size();

  OpenedArchive archive;
  if(!openArchive(cfg, archive)) return -1; // open first stream
  BitFlags bf = readBitFlags(archive.flags);
  archive.file.close(); // close first stream


  uint64_t nextId   = archive.fileCount;
  bool isDirSource  = fs::is_directory(cfg.target);
  int terminalWidth = getTerminalWidth() - 40;

  std::fstream appendFile(cfg.file, std::ios::binary | std::ios::in | std::ios::out); // open second stream for append 
  if(!appendFile) {
    std::cerr << "Failed to open archive\n";
    return -1;
  }

  appendFile.seekp(0, std::ios::end);

  for(const auto& filePath : newFiles) {
    FileEntry e;
    e.id   = nextId++;
    e.type = EntryType::file;

    if(isDirSource) {
      e.path = fs::relative(filePath, cfg.target).generic_string();
    } else {
      e.path = filePath.filename().generic_string();
    }

    e.dataSize = fs::file_size(filePath);

    if(bf.Ftime) e.mtime        = toUnixTime(fs::last_write_time(filePath));
    if(cfg.recordAtime) e.mtime = 0;


    auto metaBlock   = encryptMeta(e, archive.streamKey, bf);
    uint64_t metaLen = metaBlock.size();
    appendFile.write(reinterpret_cast<char*>(&metaLen), sizeof metaLen);
    appendFile.write(reinterpret_cast<char*>(metaBlock.data()), metaBlock.size());

    std::streampos lenPos = appendFile.tellp();
    uint64_t placeholder  = 0;
    appendFile.write(reinterpret_cast<char*>(&placeholder), sizeof placeholder);

    uint64_t encLen = encryptFileData(appendFile, filePath, e.id, archive.streamKey);

    std::streampos afterPos = appendFile.tellp();
    appendFile.seekp(lenPos);
    appendFile.write(reinterpret_cast<char*>(&encLen), sizeof encLen);
    appendFile.seekp(afterPos);

    
    std::string sign;
    double percent = (double(e.id) / newFiles.size()) * 100;

    std::cout << (cfg.verbose ? "" : "\r\033[K") 
      << e.id << "/" << newFiles.size() << "(" << std::fixed << std::setprecision(2) << percent << "%) "
      << "Encrypted: " 
      << color::cyan
      << truncateMiddle(e.path, terminalWidth)
      << color::yellow
      << " (" << convertBytes(e.dataSize, sign) << sign << ")"
      << color::reset;
    cfg.verbose ? std::cout << "\n" : std::cout << std::flush;


  }

  appendFile.close(); // close second stream, appending done


  uint64_t totalFileCount = archive.fileCount + newFileCount;
  if(!updateFileCount(cfg.file, totalFileCount)) {
    std::cerr << "Warning: files were added, but file count could not be updated\n";
    return -1;
  } // third and last stream, updating filecount.


  std::cout << "\n==> Added successfully.\n";
  return 0;
}
