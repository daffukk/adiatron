#include <iostream>
#include "headers.h"

// General flags

Config parseArgs(int argc, char** argv) {
  Config cfg;

  if(argc < 2) exit(1);

  cfg.mode = argv[1];

  if(cfg.mode == "keygen") return cfg;
  if(argc < 3) {
    std::cerr << "File is not selected.\n";
    exit(1);
  }

  cfg.file = argv[2];

  int i=3;

  for(; i < argc; i++) {
    std::string arg = argv[i];
    
    if(arg == "--dir" || arg == "-d") {
      cfg.isDir = true;
    }

    else if(arg == "--filename" && i+1 < argc) {
      cfg.filename = argv[++i];
    }

    else if(arg == "--keydir" && i+1 < argc) {
      cfg.keysDir = argv[++i];
    }

    else if(arg.find("--filename=") == 0) {
      if(arg.substr(11).length() < 1) {
        std::cerr << "Invalid passkey.\n";
        exit(1);
      } else {
        cfg.filename = arg.substr(11);
      }
    }

    else if(arg.find("--keydir=") == 0) {
      if(arg.substr(9).length() < 1) {
        std::cerr << "Invalid keydir.\n";
        exit(1);
      } else {
        cfg.keysDir = arg.substr(11);
      }
    }

    else {
      std::cout << "Unknown argument: " << arg << "\n";
      exit(1);
    }
  }

  return cfg;
}


int main(int argc, char* argv[]) {

  if(argc < 2) {
    printHelp(argc, argv);
    return 1;
  }

  Config cfg = parseArgs(argc, argv);

  if(cfg.mode == "keygen") generateKeypair();

  if(argc < 3 && cfg.mode != "keygen") {
    printHelp(argc, argv);
    return 1;
  }


  if(cfg.mode == "encrypt") encrypt(cfg);
  else if(cfg.mode == "decrypt") decrypt(cfg);

  return 0;
}
