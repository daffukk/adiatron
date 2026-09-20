#include <adiatron/serialization.h>
#include <adiatron/filesystem.h>
#include <adiatron/commands.h>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <ios>
#include <sodium/crypto_box.h>
#include <sodium/randombytes.h>
#include <string>





bool findKeys(
    std::filesystem::path& pubPath, 
    std::filesystem::path& secPath, 
    const Config& cfg
){
namespace fs = std::filesystem;

  if(!cfg.pubDir.empty()) {
    pubPath = cfg.pubDir;
  }

  if(!cfg.secDir.empty()) {
    secPath = cfg.secDir;
  }

  if(pubPath.empty() || secPath.empty()) {
    try {
      for (const auto& entry : fs::recursive_directory_iterator(cfg.keysDir)) {
        const auto& path = entry.path();

        if(pubPath.empty()) {
          if(entry.path().extension() == ".pub") {
            pubPath = entry.path();
          }
        }

        if(secPath.empty()) {
          if(!path.has_extension() && entry.is_regular_file()) {
            secPath = entry.path();
          }
        }
      }
    } catch(const fs::filesystem_error& e) {
      std::cerr << e.what() << "\n";
      return false;
    }
  }

  if(pubPath.empty() && secPath.empty()) return false;

  return true;
}

// =================
//  ARCHIVE
// =================

bool openArchive(const Config& cfg, OpenedArchive &out) {
  out.file.open(cfg.file, std::ios::binary);
  if(!out.file) {
    std::cerr << "Cannot open input file\n";
    return false;
  }

  unsigned char publicKey[crypto_box_PUBLICKEYBYTES];
  unsigned char secretKey[crypto_box_SECRETKEYBYTES];

  std::filesystem::path pubPath, secPath;
  if(!findKeys(pubPath, secPath, cfg)) {
    std::cerr << "Error: keys not found. Cannot open the archive.\n";
    return false;
  }

  std::ifstream pubFile(pubPath, std::ios::binary);
  pubFile.read(reinterpret_cast<char*>(publicKey), crypto_box_PUBLICKEYBYTES);

  std::ifstream secFile(secPath, std::ios::binary);
  secFile.read(reinterpret_cast<char*>(secretKey), crypto_box_SECRETKEYBYTES);

  unsigned char boxNonce[crypto_box_NONCEBYTES];
  out.file.read(reinterpret_cast<char*>(boxNonce), sizeof boxNonce);

  unsigned char boxedKey[crypto_box_MACBYTES + crypto_secretstream_xchacha20poly1305_KEYBYTES];
  out.file.read(reinterpret_cast<char*>(boxedKey), sizeof boxedKey);

  if(crypto_box_open_easy(out.streamKey, boxedKey, sizeof boxedKey, boxNonce, publicKey, secretKey) != 0) {
    std::cerr << "Failed to decrypt streamKey. Maybe you used wrong keys?\n";
    return false;
  }

  out.file.read(reinterpret_cast<char*>(&out.flags), sizeof out.flags);

  out.file.read(reinterpret_cast<char*>(&out.fileCount), sizeof out.fileCount);
  if(out.file.gcount() != static_cast<std::streamsize>(sizeof out.fileCount)) {
    std::cerr << "Failed to read file count, archive may be corrupted\n";
    return false;
  }

  return true;
}

bool createArchive(const Config& cfg, CreatedArchive &out, uint64_t fileCount) {
  std::string filename;
  if(cfg.filename != "" && cfg.filename.size() > 0) {
    filename = cfg.filename;
  } else {
    std::filesystem::path p(cfg.file);

    if(p.filename().empty()) {
      p = p.parent_path();
    }
    filename = p.string() + ".enc";
  }

  out.file.open(filename, std::ios::binary);
  if(!out.file) {
    std::cerr << "Cannot create output file.\n";
    return false;
  }


  unsigned char publicKey[crypto_box_PUBLICKEYBYTES];
  unsigned char secretKey[crypto_box_SECRETKEYBYTES];

  std::filesystem::path pubPath, secPath;
  if(!findKeys(pubPath, secPath, cfg)) {
    std::cerr << "Error: keys not found.\n";
    std::cout << "Create new keypair? [Y/n]: ";

    std::string answer;
    std::getline(std::cin, answer);

    if(answer.empty() || answer == "y" || answer == "Y") {
      generateKeypair();
      findKeys(pubPath, secPath, cfg);
    } else if(answer == "n" || answer == "N") {
      return false;
    } else {
      return false;
    }
  }

  std::ifstream pubFile(pubPath, std::ios::binary);
  pubFile.read(reinterpret_cast<char*>(publicKey), crypto_box_PUBLICKEYBYTES);

  std::ifstream secFile(secPath, std::ios::binary);
  secFile.read(reinterpret_cast<char*>(secretKey), crypto_box_SECRETKEYBYTES);


  crypto_secretstream_xchacha20poly1305_keygen(out.streamKey);


  unsigned char boxNonce[crypto_box_NONCEBYTES];
  randombytes_buf(boxNonce, sizeof boxNonce);
  out.file.write(reinterpret_cast<char*>(boxNonce), sizeof boxNonce);

  unsigned char boxedKey[crypto_box_MACBYTES + crypto_secretstream_xchacha20poly1305_KEYBYTES];
  if(crypto_box_easy(boxedKey, out.streamKey, sizeof out.streamKey, boxNonce, publicKey, secretKey) != 0) {
    std::cerr << "Failed to encrypt.\n";
    return false;
  }
  out.file.write(reinterpret_cast<char*>(boxedKey), sizeof boxedKey);


  out.flags = writeBitFlags(cfg);
  out.file.write(reinterpret_cast<char*>(&out.flags), sizeof out.flags);

  out.file.write(reinterpret_cast<char*>(&fileCount), sizeof fileCount);

  return true;
}

