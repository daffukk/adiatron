#include <adiatron/commands.h>
#include <adiatron/config.h>
#include <adiatron/utils.h>
#include <stdexcept>
#include <exception>
#include <iostream>
#include <cstdlib>
#include <string>
#include <vector>

Config parseArgs(int argc, char** argv) {
  Config cfg;
  std::vector<std::string> args(argv+1, argv+argc);
  std::vector<std::string> pos; 

  for(size_t i=0; i < args.size(); ++i) {
    std::string a = args[i];

    if(a == "--") { // everything after -- is positional
                    // this is used for using files with filenames like "-file.txt"
                    // see POSIX documentation about this
      pos.insert(pos.end(), args.begin() + i + 1, args.end());
      break;
    }

    if(a.size() < 2 || a[0] != '-') { // not an option
      pos.push_back(a);
      continue;
    }


    std::string val;
    bool hasVal = false;
    if(auto eq = a.find('='); eq != std::string::npos) {
      val = a.substr(eq + 1);
      a.resize(eq);
      hasVal = true;
    }

    
    auto value = [&]() -> std::string {
      if(hasVal) {
        if(val.empty()) throw std::runtime_error(a + ": empty value");
        return val;
      }
      if(i+1 >= args.size()) throw std::runtime_error(a + " requires a value");
      return args[++i];
    };

    if     (a == "-o" || a =="--filename")      cfg.filename = value();
    else if(a == "--keydir")                cfg.keysDir  = value();
    else if(a == "--pkey")                  cfg.pubPath = value();
    else if(a == "--skey")                  cfg.secPath = value();
    else if(a == "-v" || a == "--verbose")  cfg.verbose = true;
    else if(a == "-p" || a == "--passphrase") cfg.usePassphrase = true;
    else if(a == "--nokeyformat")           cfg.noKeyFormat = true;
    else if(a == "--atime")                 cfg.recordAtime = true;
    else if(a == "--ftime")                 cfg.recordFtime = true;
    else if(a == "--help")                  cfg.mode = "--help";
    else if(a == "--version")               cfg.mode = "--version";
    else throw std::runtime_error("Unknown argument: " + a);
  }

  if(cfg.mode == "--help") return cfg;
  if(cfg.mode == "--version") return cfg;
  if(pos.empty()) throw std::runtime_error("Mode is not selected");

  cfg.mode = pos[0];
  size_t need = 0; // how many positional arguments is needed with mode
  
  if     (cfg.mode == "keygen") need = 0;
  else if(cfg.mode == "extract" || cfg.mode == "add") need = 2;
  else if(cfg.mode == "encrypt" || cfg.mode == "decrypt" || cfg.mode == "list") need = 1;
  else throw std::runtime_error("Invalid mode: " + cfg.mode);

  if(pos.size() - 1 != need)
    throw std::runtime_error("Wrong number of arguments for " + cfg.mode);

  if(need >= 1) cfg.file = pos[1];
  if(cfg.mode == "extract") cfg.fileId = std::stoi(pos[2]);
  if(cfg.mode == "add")     cfg.target = pos[2];

  if((cfg.recordFtime || cfg.recordAtime) && cfg.mode != "encrypt")
    throw std::runtime_error("--atime/--ftime only work with encrypt");

  return cfg;
}





int main(int argc, char* argv[]) {
  if(argc < 2) {
    printHelp(argc, argv);
    return -1;
  }


  try {
    Config cfg = parseArgs(argc, argv);
  
    if(cfg.mode == "keygen")       return keygen(cfg);
    else if(cfg.mode == "encrypt") return encrypt(cfg);
    else if(cfg.mode == "decrypt") return decrypt(cfg);
    else if(cfg.mode == "list")    return list(cfg);
    else if(cfg.mode == "extract") return extract(cfg);
    else if(cfg.mode == "add")     return add(cfg);
    else if(cfg.mode == "--help")  printHelp(argc, argv);
    else if(cfg.mode == "--version")
      std::cout << "adiatron " << ADIATRON_VERSION << "\n";
  } catch(const std::exception& e) {
    std::cerr << "Error: " << e.what()  << "\n";
    return -1;
  } 

  return 0;
}
