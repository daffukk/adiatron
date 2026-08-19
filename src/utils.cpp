#include <adiatron/config.h>
#include <adiatron/utils.h>

double convertBytes(double n, std::string& sign) {
  if((n / TiB) >= 1) {
    sign = "TiB";
    return n / TiB;
  }

  else if((n / GiB) >= 1) {
    sign = "GiB";
    return n / GiB;
  }

  else if((n / MiB) >= 1) {
    sign = "MiB";
    return n / MiB;
  }

  else if((n / KiB) >= 1) {
    sign = "KiB";
    return n / KiB;
  }
  sign = "B";
  return n;

}

