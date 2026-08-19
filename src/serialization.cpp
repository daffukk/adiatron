#include <adiatron/serialization.h>



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
