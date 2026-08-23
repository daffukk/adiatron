#include <adiatron/serialization.h>
#include <adiatron/filesystem.h>
#include <iostream>
#include <ios>





void findKeys(
    std::filesystem::path& pubPath, 
    std::filesystem::path&secPath, 
    const Config& cfg
){
namespace fs = std::filesystem;

  if(cfg.pubDir.length() > 1) {
    pubPath = cfg.pubDir;
  }

  if(cfg.secDir.length() > 1) {
    secPath = cfg.secDir;
  }

  if(cfg.pubDir.empty() || cfg.secDir.empty()) {
    for (const auto& entry : fs::recursive_directory_iterator(cfg.keysDir)) {
      const auto& path = entry.path();
      if(cfg.pubDir.length() < 1) {
        if(entry.path().extension() == ".pub") {
          pubPath = entry.path();
        }
      }

      if(cfg.secDir.length() < 1) {
        if(!path.has_extension() && entry.is_regular_file()) {
          secPath = entry.path();
        }
      }
    }
  }
}



bool openArchive(const Config& cfg, OpenedArchive &out) {
  out.file.open(cfg.file, std::ios::binary);
  if(!out.file) {
    std::cerr << "Cannot open input file\n";
    return false;
  }

  unsigned char publicKey[crypto_box_PUBLICKEYBYTES];
  unsigned char secretKey[crypto_box_SECRETKEYBYTES];

  std::filesystem::path pubPath, secPath;
  findKeys(pubPath, secPath, cfg);

  std::ifstream pubFile(pubPath, std::ios::binary);
  pubFile.read(reinterpret_cast<char*>(publicKey), crypto_box_PUBLICKEYBYTES);

  std::ifstream secFile(secPath, std::ios::binary);
  secFile.read(reinterpret_cast<char*>(secretKey), crypto_box_SECRETKEYBYTES);

  unsigned char boxNonce[crypto_box_NONCEBYTES];
  out.file.read(reinterpret_cast<char*>(boxNonce), sizeof boxNonce);

  unsigned char boxedKey[crypto_box_MACBYTES + crypto_secretstream_xchacha20poly1305_KEYBYTES];
  out.file.read(reinterpret_cast<char*>(boxedKey), sizeof boxedKey);

  if(crypto_box_open_easy(out.streamKey, boxedKey, sizeof boxedKey, boxNonce, publicKey, secretKey) != 0) {
    std::cerr << "Failed to decrypt streamKey\n";
    return false;
  }

  out.file.read(reinterpret_cast<char*>(&out.fileCount), sizeof out.fileCount);
  if(out.file.gcount() != static_cast<std::streamsize>(sizeof out.fileCount)) {
    std::cerr << "Failed to read file count, archive may be corrupted\n";
    return false;
  }

  return true;
}



bool decryptMeta(const uint8_t* data, size_t len, uint64_t entryId, const unsigned char * streamKey, FileEntry& outEntry) {
  if(len < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) return false;

  const unsigned char* nonce = data;
  const unsigned char* ciphertext = data + crypto_secretbox_NONCEBYTES;
  size_t ciphertextLen = len - crypto_secretbox_NONCEBYTES;

  unsigned char metaKey[crypto_secretbox_KEYBYTES];
  crypto_kdf_derive_from_key(metaKey, sizeof metaKey, entryId, "FILEMETA", streamKey);

  std::vector<uint8_t> plaintext(ciphertextLen - crypto_secretbox_MACBYTES);
  if(crypto_secretbox_open_easy(plaintext.data(), ciphertext, ciphertextLen, nonce, metaKey) != 0) {
    return false;
  }

  ByteReader r(plaintext.data(), plaintext.size());
  outEntry.id = entryId;
  outEntry.path = r.readString();
  outEntry.dataSize = r.readU64();
  return true;
}




