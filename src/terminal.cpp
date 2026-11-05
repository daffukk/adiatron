#include <adiatron/utils.h>
#include <adiatron/terminal.h>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <mutex>
#include <sys/unistd.h>
#include <sys/ioctl.h>
#include <algorithm>
#include <termios.h>
#include <iostream>
#include <cstdint>
#include <string>
#include <thread>


std::mutex coutMutex;



int getTerminalWidth() {
  struct winsize w;
  if(ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0) return w.ws_col;
  return 80;
}


std::string truncateMiddle(const std::string& path, size_t maxLen) {
  if(path.size() <= maxLen) return path;

  size_t keep = maxLen - 3;
  size_t headLen = keep /2 ;
  size_t tailLen = keep - headLen;

  return path.substr(0, headLen) + "..." + path.substr(path.size() - tailLen);
}



std::string readPassphraseHidden(const std::string& prompt) {
  std::cout << prompt;
  termios oldt{};
  tcgetattr(STDIN_FILENO, &oldt);
  termios newt = oldt;
  newt.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);

  std::string passphrase;
  std::getline(std::cin, passphrase);

  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  std::cout << "\n";
  return passphrase;
}


void drawProgressBar(std::atomic<uint64_t>& processedBytes, const uint64_t totalBytes,
                     std::atomic<bool>& running) {
  const int twidth = getTerminalWidth();
  while(running) { 
    float percent = ((float)processedBytes / totalBytes) * 100;
  
    auto progressBar = [](double fraction, int width) -> std::string {
      static const char* partial[] = {" ", "▏", "▎", "▍", "▌", "▋", "▊", "▉"};
    
      fraction = std::clamp(fraction, 0.0, 1.0);
      int eights = static_cast<int>(fraction * width * 8); // 8 because there is 8 parts
      int full   = eights / 8;
      int rest   = eights % 8;
    
      std::string bar;
      for(int i=0; i < full; i++) bar += "█";
      if(full < width) {
        bar += partial[rest];
        for(int i=full + 1; i < width; i++) bar += " ";
      }
      return bar;
    };
  
    std::string sign1;
    std::string sign2;
    std::lock_guard<std::mutex> lk(coutMutex);
    std::cout << "\r\033[K"
              << std::setw(3) << int(percent) << "%|"
              << progressBar(processedBytes / double(totalBytes), twidth - 30) << "| "
              << std::fixed << std::setprecision(2)
              << convertBytes(processedBytes, sign1) << sign1
              << " / " 
              << convertBytes(totalBytes, sign2) << sign2
              << std::flush;
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(30));
}
