#include <adiatron/terminal.h>
#include <sys/unistd.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <iostream>

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
