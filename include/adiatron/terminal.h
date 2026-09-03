#pragma once
#include <string>

namespace color {  
  constexpr const char* red = "\033[31m";
  constexpr const char* green = "\033[32m";
  constexpr const char* yellow = "\033[33m";
  constexpr const char* magneta = "\033[35m";
  constexpr const char* cyan = "\033[36m";  
  constexpr const char* redbg = "\033[41m";
  constexpr const char* greenbg = "\033[42m";
  constexpr const char* yellowbg = "\033[43m";
  constexpr const char* magnetabg = "\033[45m";
  constexpr const char* cyanbg = "\033[46m";
  constexpr const char* reset = "\033[0m";
}

int getTerminalWidth();
std::string truncateMiddle(const std::string& path, size_t maxLen);
