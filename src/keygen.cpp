#include <cstdlib>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>
#include <adiatron/commands.h>
#include <adiatron/terminal.h>
#include <filesystem>
#include <iostream>
#include <sodium.h>
#include <cstring>
#include <fstream>





int generateKeypair(bool noFormat) {
namespace fs = std::filesystem;
  
  std::cout << "\nGenerating new keys...\n";

  try {
    fs::create_directories("keys/publicKey");
    fs::create_directories("keys/secretKey");
  } catch (const fs::filesystem_error& e) {
    std::cerr << "Filesystem error: " << e.what() << "\n";
    std::cerr << "Path: "             << e.path1() << "\n";
    std::cerr << "Error: "            << e.code().message() << "\n";
    
    return -1;
  }

  unsigned char publicKey[crypto_box_PUBLICKEYBYTES];
  unsigned char secretKey[crypto_box_SECRETKEYBYTES];
  crypto_box_keypair(publicKey, secretKey);


  unsigned char hash[crypto_generichash_BYTES];
  crypto_generichash(hash, sizeof(hash), publicKey, sizeof publicKey, nullptr, 0);
  char hex[crypto_generichash_BYTES * 2 + 1];
  sodium_bin2hex(hex, sizeof(hex), hash, sizeof(hash));
  std::string shortHex = std::string(hex).substr(0, 6);


  std::ofstream sc(("keys/secretKey/" + shortHex).c_str(), std::ios::binary);
  
  if(!noFormat) {
    unsigned char format = 0x00;
    sc.write(reinterpret_cast<const char*>(&format), 1);
  } else {
    std::cout << "--nokeyformat flag has been used. Creating keys without format.\n";
  }
  
  sc.write(reinterpret_cast<const char*>(secretKey), sizeof secretKey);
  sc.close();

  sodium_memzero(secretKey, sizeof secretKey);

  std::ofstream pk(("keys/publicKey/" + shortHex + ".pub").c_str(), std::ios::binary);
  pk.write(reinterpret_cast<const char*>(publicKey), sizeof publicKey);
  pk.close();

  return 0;
}



int generateEncryptedKeypair(const char* passphrase) {
namespace fs = std::filesystem;
  
  try {
    fs::create_directories("keys/publicKey");
    fs::create_directories("keys/secretKey");
  } catch (const fs::filesystem_error& e) {
    std::cerr << "Filesystem error: " << e.what() << "\n";
    std::cerr << "Path: "             << e.path1() << "\n";
    std::cerr << "Error: "            << e.code().message() << "\n";
    
    return -1;
  }

  unsigned char publicKey[crypto_box_PUBLICKEYBYTES];
  unsigned char secretKey[crypto_box_SECRETKEYBYTES];
  crypto_box_keypair(publicKey, secretKey);


  unsigned char hash[crypto_generichash_BYTES];
  crypto_generichash(hash, sizeof(hash), publicKey, sizeof publicKey, nullptr, 0);
  char hex[crypto_generichash_BYTES * 2 + 1];
  sodium_bin2hex(hex, sizeof(hex), hash, sizeof(hash));
  std::string shortHex = std::string(hex).substr(0, 6);


  unsigned char salt[crypto_pwhash_SALTBYTES];
  randombytes_buf(salt, sizeof salt);

  unsigned char derivedKey[crypto_secretbox_KEYBYTES];

  if(crypto_pwhash(derivedKey, sizeof derivedKey,
        passphrase, strlen(passphrase), salt, 
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT) != 0) {
    std::cerr << "Failed to derive key from passphrase (out of memory?).\n";
    sodium_memzero(secretKey, sizeof secretKey);
    return -1;
  }

  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  randombytes_buf(nonce, sizeof nonce);

  unsigned char encryptedSecretKey[crypto_box_SECRETKEYBYTES + crypto_secretbox_MACBYTES];
  crypto_secretbox_easy(encryptedSecretKey, secretKey, sizeof secretKey, nonce, derivedKey);

  sodium_memzero(derivedKey, sizeof derivedKey);
  sodium_memzero(secretKey, sizeof secretKey);


  std::ofstream sc(("keys/secretKey/" + shortHex).c_str(), std::ios::binary);
  unsigned char format = 0x01;
  sc.write(reinterpret_cast<const char*>(&format), 1); 
  sc.write(reinterpret_cast<const char*>(salt), sizeof salt);
  sc.write(reinterpret_cast<const char*>(nonce), sizeof nonce);
  sc.write(reinterpret_cast<const char*>(encryptedSecretKey), sizeof encryptedSecretKey);
  sc.close();

  std::ofstream pk(("keys/publicKey/" + shortHex + ".pub").c_str(), std::ios::binary);
  pk.write(reinterpret_cast<const char*>(publicKey), sizeof publicKey);
  pk.close();


  return 0;
}



int keygen(const Config& cfg) {
  if(!cfg.usePassphrase) {
    return generateKeypair(cfg.noKeyFormat);
  }

  if(cfg.noKeyFormat) {
    std::cerr << "--nokeyformat cannot be used with encrypted keys.\n";
    return -1;
  }

  std::string pass1 = readPassphraseHidden("Enter passphrase: ");
  std::string pass2 = readPassphraseHidden("Confirm passphrase: ");
  if(pass1 != pass2) {
    std::cerr << "Passphrases do not match.\n";
    return -1;
  }

  int result = generateEncryptedKeypair(pass1.c_str());
  sodium_memzero(pass1.data(), pass1.size());
  sodium_memzero(pass2.data(), pass2.size());
  return result;
}
