#include <iostream>
#include "headers.h"

// General flags


inline bool flagFinder(int argc, char* argv[], const char* flag) {
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], flag) == 0) {
      return true;
    }
  }
  return false;
}


inline double findFlagValue(int argc, char* argv[], const char* flag) {
  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
      if(arg.find(flag) == 0) {
        double flagValue = std::stof(arg.substr(strlen(flag)));

        if(flagValue < 0) {
          std::cout << "Invalid argument value: " << arg << std::endl;
          return -1;
        }

        return flagValue;
      }
  }
  return -1;
}


inline std::string findFlagValueStr(int argc, char* argv[], const char* flag) {
  for(int i=1; i < argc; i++) {
    std::string arg = argv[i];
    if(arg.find(flag) == 0) {
      std::string flagValue = arg.substr(strlen(flag));
      return flagValue;
    }
  }
  return "";
}


inline void printHelp(int argc, char* argv[]) {
  std::cout
    << "Usage: " << argv[0] << " <ENCRYPT/DECRYPT> <OPTIONS>\n"
    << "\n"
    << "Examples:\n"
    << "\t" << argv[0] << " ecnrypt file.txt\n"
    << "\t" << argv[0] << " decrypt file.enc\n"
    << "\t" << argv[0] << " keygen\n";
}





int main(int argc, char* argv[]) {

  if(argc < 3 || flagFinder(argc, argv, "--help") || flagFinder(argc, argv, "-h")) {
    printHelp(argc, argv);
    return -1;
  }

  if(argc == 2 && strcmp(argv[1], "keygen") == 0) generateKeypair();


  if(argc >= 3) {
    if(strcmp(argv[1], "encrypt") == 0) {
      encrypt(argc, argv);
    }
    else if(strcmp(argv[1], "decrypt") == 0) {
      decrypt(argc, argv);
    }
    else {
      std::cout << "Wrong argument.\n";
      return 1;
    }
  }




  return 0;
}
