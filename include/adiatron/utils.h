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
    << "\tlist \t\t List encrypted archive contents without fully decrypting it. Requires keys.\n"
    << "\textract \t Extract one file from encrypted archive by fileID. You can find fileID via 'list' mode.\n"
    << "\tkeygen \t\t Generate a new public/secret keypair.\n"
    << "\t--help \t\t Display help text.\n"
    << "\n"
    << "Examples:\n"
    << "\t" << name << " encrypt file.txt\n"
    << "\t" << name << " encrypt directory/\n"
    << "\t" << name << " decrypt file.enc\n"
    << "\t" << name << " extract archive.enc 0 \t <== 0 is the first file in archive.\n"
    << "\t" << name << " list archive.enc\n"
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


