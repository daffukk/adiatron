#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/randombytes.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_kdf.h>
#include <sodium/core.h>
#include <sodium.h>
#include <adiatron/serialization.h>
#include <adiatron/filesystem.h>
#include <adiatron/commands.h>
#include <adiatron/terminal.h>
#include <adiatron/config.h>
#include <adiatron/utils.h>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <cstdint>
#include <iosfwd>
#include <stdexcept>
#include <string>
#include <vector>
#include <set>

namespace fs = std::filesystem;


std::vector<InputFile> collectFiles(const std::vector<std::string>& sources) {
  std::vector<InputFile> result;
  std::set<std::string> seen;

  auto add = [&](const fs::path& p, std::string inArchive) {
    if(!seen.insert(inArchive).second)
      throw std::runtime_error("Duplicate path in archive: " + inArchive);
    result.push_back({p, std::move(inArchive)});
  };

  for(const auto& src : sources) {
    if(!fs::exists(src))
      throw std::runtime_error("No such file or directory: " + src);

    if(fs::is_directory(src)) {
      for(const auto& e : fs::recursive_directory_iterator(src)) {
        if(e.is_regular_file())
          add(e.path(), fs::relative(e.path(), src).generic_string());
      }
    } else {
      add(src, fs::path(src).filename().generic_string());
    }
  }

  return result;
}



std::vector<uint8_t> encryptMeta(
    const FileEntry& e, 
    const unsigned char* streamKey,
    const BitFlags& bf
) {
  ByteWriter w;
  w.writeString(e.path);
  w.writeU64(e.dataSize);

  // BITFLAGS
  if(bf.Ftime) w.writeU64(e.mtime);

  unsigned char metaKey[crypto_secretbox_KEYBYTES];
  crypto_kdf_derive_from_key(metaKey, sizeof metaKey, e.id, "FILEMETA", streamKey);

  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  randombytes_buf(nonce, sizeof nonce);

  std::vector<uint8_t> ciphertext(w.buf.size() + crypto_secretbox_MACBYTES);
  crypto_secretbox_easy(ciphertext.data(), w.buf.data(), w.buf.size(), nonce, metaKey);

  std::vector<uint8_t> result;
  result.insert(result.end(), nonce, nonce + sizeof nonce);
  result.insert(result.end(), ciphertext.begin(), ciphertext.end());
  return result;
}



uint64_t encryptFileData(
    std::ostream& out, 
    const fs::path& filePath, 
    uint64_t entryId, 
    const unsigned char* streamKey
) {
  unsigned char dataKey[crypto_secretstream_xchacha20poly1305_KEYBYTES];
  crypto_kdf_derive_from_key(dataKey, sizeof dataKey, entryId, "FILEDATA", streamKey);

  crypto_secretstream_xchacha20poly1305_state state;
  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  crypto_secretstream_xchacha20poly1305_init_push(&state, header, dataKey);

  out.write(reinterpret_cast<char*>(header), sizeof header);
  uint64_t written = sizeof header;

  std::ifstream file(filePath, std::ios::binary);
  unsigned char fileBuffer[CHUNK_SIZE];
  unsigned char outBuffer[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];

  while(true) {
    file.read(reinterpret_cast<char*>(fileBuffer), CHUNK_SIZE);
    size_t readBytes = file.gcount();

    bool isLast = file.peek() == std::ifstream::traits_type::eof();
    unsigned char tag = isLast ? 
      crypto_secretstream_xchacha20poly1305_TAG_FINAL : 
      crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

    unsigned long long outLen;
    crypto_secretstream_xchacha20poly1305_push(
        &state,
        outBuffer,
        &outLen,
        fileBuffer,
        readBytes,
        nullptr,
        0,
        tag
    );
    out.write(reinterpret_cast<char*>(outBuffer), outLen);
    written += outLen;

    if(isLast) break;
  }
  return written;
}






int encrypt(const Config& cfg) {
  if(sodium_init() != 0) {
    std::cerr << "Error sodium\n";
    return -1;
  }


  std::vector<InputFile> files = collectFiles(cfg.files);

  CreatedArchive archive;
  if(!createArchive(cfg, archive, files.size())) return -1;

  auto bf           = readBitFlags(archive.flags);
  int terminalWidth = getTerminalWidth() - 45;
  uint64_t nextId   = 0;

  for(const auto& f : files) {
    FileEntry e;
    e.id       = nextId++;
    e.type     = EntryType::file;
    e.path     = f.archivePath;
    e.dataSize = fs::file_size(f.path);

    // BITFLAGS
    if(cfg.recordFtime) e.mtime = toUnixTime(fs::last_write_time(f.path));
    else if(cfg.recordAtime) e.mtime = 0;



    auto metaBlock   = encryptMeta(e, archive.streamKey, bf);
    uint64_t metaLen = metaBlock.size();
    archive.file.write(reinterpret_cast<char*>(&metaLen), sizeof metaLen);
    archive.file.write(reinterpret_cast<char*>(metaBlock.data()), metaBlock.size());

    std::streampos lenPos = archive.file.tellp();
    uint64_t placeholder  = 0;
    archive.file.write(reinterpret_cast<char*>(&placeholder), sizeof placeholder);

    uint64_t encLen = encryptFileData(archive.file, f.path, e.id, archive.streamKey);

    std::streampos afterPos = archive.file.tellp();
    archive.file.seekp(lenPos);
    archive.file.write(reinterpret_cast<char*>(&encLen), sizeof encLen);
    archive.file.seekp(afterPos);

    
    std::string sign;
    double percent = (double(e.id + 1) / files.size()) * 100;

    std::cout << (cfg.verbose ? "" : "\r\033[K") 
      << e.id + 1 << "/" << files.size() << "(" << std::fixed << std::setprecision(2) << percent << "%) "
      << "Encrypted: " 
      << color::cyan
      << truncateMiddle(e.path, terminalWidth)
      << color::yellow
      << " (" << convertBytes(e.dataSize, sign) << sign << ")"
      << color::reset;
    cfg.verbose ? std::cout << "\n" : std::cout << std::flush;
  }


  std::cout << "\n==> Encrypted successfully.\n";
  return 0;
}
