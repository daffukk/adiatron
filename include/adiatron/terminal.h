#pragma once
#include <cstdint>
#include <string>


int getTerminalWidth();
std::string truncateMiddle(const std::string& path, size_t maxLen);
