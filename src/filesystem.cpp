#include <adiatron/serialization.h>
#include <adiatron/filesystem.h>
#include <adiatron/commands.h>
#include <adiatron/terminal.h>
#include <filesystem>
#include <iostream>
#include <ios>
#include <sodium/crypto_box.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>
#include <string>





// =================
//  KEYS
// =================

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

bool loadSecretKey(const std::filesystem::path& secPath, unsigned char* secretKeyOut, const bool noFormat) {
  std::ifstream secFile(secPath, std::ios::binary);
  if(!secFile) {
    std::cerr << "Cannot open secret key file.\n";
    return false;
  }

  if(noFormat) {
    secFile.read(reinterpret_cast<char*>(secretKeyOut), crypto_box_SECRETKEYBYTES);
    return true;
  }

  unsigned char format;
  secFile.read(reinterpret_cast<char*>(&format), 1);
  if(secFile.gcount() != 1) {
    std::cerr << "Secret key file is empty or corrupted.\n";
    return false;
  }

  if(format == 0x00) {
    secFile.read(reinterpret_cast<char*>(secretKeyOut), crypto_box_SECRETKEYBYTES);
    return true;
  } 

  if(format == 0x01) { 
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char encryptedSecretKey[crypto_box_SECRETKEYBYTES + crypto_secretbox_MACBYTES];

    secFile.read(reinterpret_cast<char*>(salt), sizeof salt);
    secFile.read(reinterpret_cast<char*>(nonce), sizeof nonce);
    secFile.read(reinterpret_cast<char*>(encryptedSecretKey), sizeof encryptedSecretKey);
 
    std::string passphrase = readPassphraseHidden("Enter passphrase for secret key: ");

    unsigned char derivedKey[crypto_secretbox_KEYBYTES];
    if(crypto_pwhash(derivedKey, sizeof derivedKey,
          passphrase.c_str(), passphrase.size(), salt, 
          crypto_pwhash_OPSLIMIT_INTERACTIVE,
          crypto_pwhash_MEMLIMIT_INTERACTIVE,
          crypto_pwhash_ALG_DEFAULT) != 0) {
      std::cerr << "Failed to derive key from passphrase (out of memory?).\n";
      sodium_memzero(passphrase.data(), passphrase.size());
      return false;
    }
    sodium_memzero(passphrase.data(), passphrase.size());


    bool ok = crypto_secretbox_open_easy(secretKeyOut, encryptedSecretKey,
        sizeof encryptedSecretKey, nonce, derivedKey) == 0;

    sodium_memzero(derivedKey, sizeof derivedKey);

    if(!ok) {
      std::cerr << "Wrong passphrase or corrupted key file.\n";
      return false;
    }
    return true;
  }

  std::cerr << "Unknown secret key format.\n";
  return false;
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

  if(!loadSecretKey(secPath, secretKey, cfg.noKeyFormat)) return false;

  unsigned char boxNonce[crypto_box_NONCEBYTES];
  out.file.read(reinterpret_cast<char*>(boxNonce), sizeof boxNonce);

  unsigned char boxedKey[crypto_box_MACBYTES + crypto_secretstream_xchacha20poly1305_KEYBYTES];
  out.file.read(reinterpret_cast<char*>(boxedKey), sizeof boxedKey);

  if(crypto_box_open_easy(out.streamKey, boxedKey, sizeof boxedKey, boxNonce, publicKey, secretKey) != 0) {
    std::cerr << "Failed to decrypt streamKey. Maybe you used wrong keys?\n";
    sodium_memzero(secretKey, sizeof secretKey);
    return false;
  }

  sodium_memzero(secretKey, sizeof secretKey);

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
      keygen(cfg);
      findKeys(pubPath, secPath, cfg);
    } else if(answer == "n" || answer == "N") {
      return false;
    } else {
      return false;
    }
  }

  std::ifstream pubFile(pubPath, std::ios::binary);
  pubFile.read(reinterpret_cast<char*>(publicKey), crypto_box_PUBLICKEYBYTES);

  if(!loadSecretKey(secPath, secretKey, cfg.noKeyFormat)) return false;


  crypto_secretstream_xchacha20poly1305_keygen(out.streamKey);


  unsigned char boxNonce[crypto_box_NONCEBYTES];
  randombytes_buf(boxNonce, sizeof boxNonce);
  out.file.write(reinterpret_cast<char*>(boxNonce), sizeof boxNonce);

  unsigned char boxedKey[crypto_box_MACBYTES + crypto_secretstream_xchacha20poly1305_KEYBYTES];
  if(crypto_box_easy(boxedKey, out.streamKey, sizeof out.streamKey, boxNonce, publicKey, secretKey) != 0) {
    std::cerr << "Failed to encrypt.\n";
    sodium_memzero(secretKey, sizeof secretKey);
    return false;
  }

  sodium_memzero(secretKey, sizeof secretKey);

  out.file.write(reinterpret_cast<char*>(boxedKey), sizeof boxedKey);


  out.flags = writeBitFlags(cfg);
  out.file.write(reinterpret_cast<char*>(&out.flags), sizeof out.flags);

  out.file.write(reinterpret_cast<char*>(&fileCount), sizeof fileCount);

  return true;
}

