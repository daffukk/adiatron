#pragma once
#include <filesystem>
#include <iostream>


double convertBytes(double n, std::string& sign);

// =================
//  HELP
// =================

inline void printHelp(int argc, char* argv[]) {
  std::filesystem::path adiatron = argv[0];
  std::string name = adiatron.filename().generic_string();
  std::cout
    << "Usage: " << name << " <MODE> <OPTIONS>\n"
    << "\n"
    << "Modes:\n"
    << "\tencrypt \t Encrypt a file or direcorty.\n"
    << "\tdecrypt \t Decrypt a previously encrypted archive.\n"
    << "\tkeygen \t\t Generate a new public/secret keypair.\n"
    << "\n"
    << "Examples:\n"
    << "\t" << name << " encrypt file.txt\n"
    << "\t" << name << " encrypt directory/\n"
    << "\t" << name << " decrypt file.enc\n"
    << "\t" << name << " keygen\n"
    << "\n"
    << "Options:\n"
    << "Flags can be used in both --filename cookies.png or --filename=cookies.png formats\n\n"
    << "\t-v, --verbose \t\t Display each file as it is encrypted or decrypted.\n"
    << "\t-o, --filename \t\t Specify an output filename.\n"
    << "\t--keydir \t\t Specify 'keys' directory location.\n"
    << "\t--pkey \t\t\t Specify public key directory location.\n"
    << "\t--skey \t\t\t Specify secret key directory location.\n";
}


