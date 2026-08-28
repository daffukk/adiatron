#include <adiatron/serialization.h>
#include <chrono>



void writeEntry(ByteWriter& w, const FileEntry& e) {
  w.writeU64(e.id);
  w.writeU8(static_cast<uint8_t>(e.type));
  w.writeString(e.path);
  w.writeU64(e.dataSize);
  w.writeU64(e.encryptedSize);
  w.writeU64(e.dataOffset);
}

FileEntry readEntry(ByteReader &r) {
  FileEntry e;
  e.id            = r.readU64();
  e.type          = static_cast<EntryType>(r.readU8());
  e.path          = r.readString();
  e.dataSize      = r.readU64();
  e.encryptedSize = r.readU64();
  e.dataOffset    = r.readU64();
  return e;
}


// =================
// BITFLAGS
// =================

uint64_t writeBitFlags(const Config& cfg) {
  uint64_t flags=0;
  
  if(cfg.recordFtime) flags |= BitFlag::FTIME;

  return flags;
}

BitFlags readBitFlags(uint64_t flags) {
  BitFlags bf;
  if((flags & BitFlag::FTIME) != 0) bf.Ftime=true;

  return bf;
}


// =================
//  FILETIME
// =================

int64_t toUnixTime(std::filesystem::file_time_type ftime) {
  auto sctp = std::chrono::clock_cast<std::chrono::system_clock>(ftime);
  return std::chrono::duration_cast<std::chrono::seconds>(sctp.time_since_epoch()).count();
}


std::filesystem::file_time_type fromUnixTime(int64_t unixTime) {
  auto sctp = std::chrono::system_clock::time_point(std::chrono::seconds(unixTime));
  return std::chrono::clock_cast<std::filesystem::file_time_type::clock>(sctp);
}
