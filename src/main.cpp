#include <adiatron/commands.h>
#include <adiatron/config.h>
#include <adiatron/utils.h>
#include <cstdint>
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

  size_t minArgs, maxArgs; // how many positional arguments is needed with mode
  
  if     (cfg.mode == "keygen") { minArgs = 0; maxArgs = 0; }
  else if(cfg.mode == "extract" || cfg.mode == "add") 
    { minArgs = 2; maxArgs = SIZE_MAX; }
  else if(cfg.mode == "encrypt") { minArgs = 1; maxArgs = SIZE_MAX; }
  else if(cfg.mode == "decrypt" || cfg.mode == "list") 
    { minArgs = 1; maxArgs = 1; }
  else throw std::runtime_error("Invalid mode: " + cfg.mode);


  if(pos.size() - 1 < minArgs)
    throw std::runtime_error("Not enough arguments for " + cfg.mode);

  if(pos.size() - 1 > maxArgs)
    throw std::runtime_error("Too many arguments for " + cfg.mode);

  // every mode aside those is using archive as first positional
  if(cfg.mode != "encrypt" && cfg.mode != "keygen") 
    cfg.archive = pos[1];
  
  if(cfg.mode == "encrypt")
    cfg.inputs.assign(pos.begin() + 1, pos.end()); // all files
  else if(cfg.mode == "add")
    cfg.inputs.assign(pos.begin() + 2, pos.end());


  if(cfg.mode == "extract") {
    for(size_t k=2; k < pos.size(); ++k) {
      try {
        size_t used;
        cfg.ids.push_back(std::stoull(pos[k], &used));
        if(used != pos[k].size()) throw std::invalid_argument(""); // needs because stoull("33df") will 
                                                                   // silently return 33
      } catch(...) {
        throw std::runtime_error("FileID must be a number: " + pos[k]);
      }
    }
  }

  if((cfg.recordFtime || cfg.recordAtime) && (cfg.mode != "encrypt" || cfg.mode != "add"))
    throw std::runtime_error("--atime/--ftime only work with add or encrypt modes");

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
