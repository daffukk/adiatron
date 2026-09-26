#pragma once
#include "config.h"


int encrypt(const Config& cfg);
int decrypt(const Config& cfg);
int list(const Config& cfg);
int extract(const Config& cfg);
int add(const Config& cfg);
int keygen(const Config& cfg);
