#include <adiatron/filesystem.h>

namespace fs = std::filesystem;

void findKeys(fs::path& pubPath, fs::path&secPath, const Config& cfg){

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

