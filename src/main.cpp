#include <adiatron/commands.h>
#include <adiatron/config.h>
#include <adiatron/utils.h>
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <string>

// General flags

Config parseArgs(int argc, char** argv) {
  Config cfg;
  if(argc < 2) {
    printHelp(argc, argv);
    exit(1);
  }

  cfg.mode = argv[1];


  if(std::find(modes.begin(), modes.end(), cfg.mode) == modes.end()) {
    std::cout << "Invalid mode. Type --help for more information\n";
    exit(1);
  }


  if(cfg.mode == "keygen" || cfg.mode == "--help") return cfg;
  if(argc < 3) {
    std::cerr << "File is not selected. Type --help for more information.\n";
    exit(1);
  }

  cfg.file = argv[2];

  if(cfg.mode == "extract") {
    if(argc < 4) {
      std::cerr << "FileID is not selected. Type --help for more information.\n";
      exit(1);
    }

    cfg.fileId = std::stoi(argv[3]);
  }
  

  int i;
  cfg.mode=="extract" ? i=4 : i = 3;

  for(; i < argc; i++) {
    std::string arg = argv[i];
    
    if((arg == "--filename" || arg == "-o") && i+1 < argc) {
      cfg.filename = argv[++i];
    }

    else if(arg == "--keydir" && i+1 < argc) {
      cfg.keysDir = argv[++i];
    }

    else if(arg == "--pkey" && i+1 < argc) {
      cfg.pubDir = argv[++i];
    }

    else if(arg == "--skey" && i+1 < argc) {
      cfg.secDir = argv[++i];
    }


    else if(arg.find("--filename=") == 0) {
      if(arg.substr(11).length() < 1) {
        std::cerr << "Invalid filename.\n";
        exit(1);
      } else {
        cfg.filename = arg.substr(11);
      }
    }

    else if(arg.find("-o=") == 0) {
      if(arg.substr(3).length() < 1) {
        std::cerr << "Invalid filename.\n";
        exit(1);
      } else {
        cfg.filename = arg.substr(3);
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

    else if(arg.find("--pkey=") == 0) {
      if(arg.substr(7).length() < 1) {
        std::cerr << "Invalid public key.\n";
        exit(1);
      } else {
        cfg.pubDir = arg.substr(7);
      }
    }

    else if(arg.find("--skey=") == 0) {
      if(arg.substr(7).length() < 1) {
        std::cerr << "Invalid secret key.\n";
        exit(1);
      } else {
        cfg.secDir = arg.substr(7);
      }
    }

    else if(arg == "--ftime") {
      if(cfg.mode == "encrypt") {
        cfg.recordFtime = true;
      } else {
        std::cout << "Invalid mode, you can use --ftime only when encrypting.\n";
        exit(1);
      }
    }

    else if(arg == "--verbose" || arg == "-v") {
      cfg.verbose = true;
    }

    else {
      std::cout << "Unknown argument: " << arg << "\n";
      exit(1);
    }
  }

  return cfg;
}






int main(int argc, char* argv[]) {
  Config cfg = parseArgs(argc, argv);
  if(argc < 3 && cfg.mode != "keygen") {
    printHelp(argc, argv);
    return -1;
  }


  if(cfg.mode == "keygen")       return generateKeypair();
  else if(cfg.mode == "encrypt") return encrypt(cfg);
  else if(cfg.mode == "decrypt") return decrypt(cfg);
  else if(cfg.mode == "list")    return list(cfg);
  else if(cfg.mode == "extract") return extract(cfg);
  else if(cfg.mode == "--help")  printHelp(argc, argv);

  return 0;
}
