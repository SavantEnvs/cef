// Known-answer probe for the CEF installer archive/XZ code. Prints one line per check; test.sh
// diffs the output against mayhem/testdata/kat.expected, so a patch that breaks tar parsing,
// xz index parsing or block decompression changes the output.
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include "base/containers/span.h"
#include "base/files/file.h"
#include "cef/libcef_dll/bootstrap/installer/installer_archive.h"
#include "cef/libcef_dll/bootstrap/installer/installer_xz_index.h"

extern "C" {
#include "third_party/lzma_sdk/src/C/7zCrc.h"
#include "third_party/lzma_sdk/src/C/XzCrc64.h"
}

using namespace cef_installer;

static std::string g_data;

static std::vector<uint8_t> ReadAll(const std::string& p) {
  std::ifstream f(p, std::ios::binary);
  return std::vector<uint8_t>(std::istreambuf_iterator<char>(f), {});
}

static std::string Slurp(const std::string& p) {
  auto v = ReadAll(p);
  return std::string(v.begin(), v.end());
}

static uint64_t Fnv(const uint8_t* d, size_t n) {
  uint64_t h = 1469598103934665603ULL;
  for (size_t i = 0; i < n; i++) {
    h = (h ^ d[i]) * 1099511628211ULL;
  }
  return h;
}

static void Octal(const char* s) {
  std::vector<uint8_t> f(s, s + std::char_traits<char>::length(s));
  auto r = internal::TarReader::ReadOctalNumber(f);
  std::printf("octal \"%s\" -> %s\n", s,
              r ? std::to_string(*r).c_str() : "invalid");
}

static void ExtractReport(const char* label, const std::string& path,
                          const std::vector<std::string>& files) {
  auto tar = ReadAll(path);
  char tmpl[] = "/tmp/kat.XXXXXX";
  std::string dir = mkdtemp(tmpl);
  auto err = ExtractTarFromBuffer(tar, base::FilePath(dir));
  std::printf("%s: %s\n", label, ArchiveErrorToString(err));
  for (const auto& f : files) {
    struct stat st;
    std::string full = dir + "/" + f;
    if (stat(full.c_str(), &st) != 0) {
      std::printf("%s: %s missing\n", label, f.c_str());
    } else {
      std::string c = Slurp(full);
      std::printf("%s: %s size=%lld mtime=%lld content=[%s]\n", label, f.c_str(),
                  (long long)st.st_size, (long long)st.st_mtime,
                  c.size() > 40 ? "..." : c.c_str());
    }
  }
  std::string cmd = "rm -rf '" + dir + "'";
  if (system(cmd.c_str()) != 0) {
    std::printf("cleanup failed\n");
  }
}

static std::vector<uint8_t> TarHeader(const std::string& name, size_t size,
                                      char type) {
  std::vector<uint8_t> h(512, 0);
  std::memcpy(h.data(), name.data(), name.size());
  std::memcpy(&h[100], "0000644", 7);
  char sz[16];
  std::snprintf(sz, sizeof sz, "%011zo", size);
  std::memcpy(&h[124], sz, 11);
  std::memcpy(&h[136], "00000000000", 11);
  h[156] = type;
  std::memcpy(&h[257], "ustar", 5);
  std::memcpy(&h[148], "        ", 8);
  unsigned sum = 0;
  for (uint8_t b : h) sum += b;
  char ck[16];
  std::snprintf(ck, sizeof ck, "%06o", sum);
  std::memcpy(&h[148], ck, 6);
  h[154] = 0;
  h[155] = ' ';
  return h;
}

static void XzReport(const char* label, const std::string& path) {
  base::File f(base::FilePath(path), base::File::FLAG_OPEN | base::File::FLAG_READ);
  auto info = ParseXzIndex(f);
  if (!info) {
    std::printf("%s: index invalid\n", label);
    return;
  }
  std::printf("%s: blocks=%zu total=%llu check=%d\n", label, info->blocks.size(),
              (unsigned long long)info->total_uncompressed_size, info->check_type);
  auto file = ReadAll(path);
  for (const auto& b : info->blocks) {
    std::vector<uint8_t> out(b.uncompressed_size);
    uint16_t flags = (uint16_t(file[6]) << 8) | file[7];
    bool ok = DecompressXzBlock(
        base::span<const uint8_t>(file.data() + b.compressed_offset,
                                  b.compressed_size),
        info->check_type, flags, out);
    std::printf("%s: block off=%llu csize=%llu usize=%llu ok=%d fnv=%016llx\n",
                label, (unsigned long long)b.compressed_offset,
                (unsigned long long)b.compressed_size,
                (unsigned long long)b.uncompressed_size, ok,
                (unsigned long long)Fnv(out.data(), out.size()));
  }
}

int main(int argc, char** argv) {
  if (argc != 2) {
    std::fprintf(stderr, "usage: kat <testdata-dir>\n");
    return 2;
  }
  std::string d = argv[1];
  CrcGenerateTable();
  Crc64GenerateTable();

  Octal("00000644");
  Octal("00000000017 ");
  Octal("0000644");
  Octal("77777777777");
  Octal("89");

  ExtractReport("ustar", d + "/sample.tar", {"pkg/hello.txt", "pkg/docs/readme.txt"});

  // Hand-built archives: a control entry must extract, traversal / absolute paths must not.
  for (const char* name : {"ok.txt", "../evil", "/etc/evil", "a/../../evil"}) {
    auto h = TarHeader(name, 4, '0');
    std::vector<uint8_t> t(h);
    t.insert(t.end(), {'d', 'a', 't', 'a'});
    t.resize(t.size() + 508, 0);
    t.resize(t.size() + 1024, 0);
    char tmpl[] = "/tmp/kat.XXXXXX";
    std::string dir = mkdtemp(tmpl);
    auto err = ExtractTarFromBuffer(t, base::FilePath(dir));
    std::printf("handmade %s: %s ok.txt=[%s]\n", name, ArchiveErrorToString(err),
                Slurp(dir + "/ok.txt").c_str());
    std::string cmd = "rm -rf '" + dir + "'";
    if (system(cmd.c_str()) != 0) std::printf("cleanup failed\n");
  }
  // Corrupt checksum.
  {
    auto t = ReadAll(d + "/sample.tar");
    t[148] ^= 1;
    char tmpl[] = "/tmp/kat.XXXXXX";
    std::string dir = mkdtemp(tmpl);
    auto err = ExtractTarFromBuffer(t, base::FilePath(dir));
    std::printf("badchecksum: %s\n", ArchiveErrorToString(err));
    std::string cmd = "rm -rf '" + dir + "'";
    if (system(cmd.c_str()) != 0) std::printf("cleanup failed\n");
  }

  XzReport("xz-crc64", d + "/sample.tar.xz");
  XzReport("xz-crc32", d + "/sample_crc32.tar.xz");
  XzReport("xz-block64k", d + "/block64k_crc64.xz");

  // Full tar.xz extraction through the streaming path.
  {
    char tmpl[] = "/tmp/kat.XXXXXX";
    std::string dir = mkdtemp(tmpl);
    auto err = ExtractTarXzSingleThread(base::FilePath(d + "/sample.tar.xz"),
                                        base::FilePath(dir));
    std::printf("tar.xz: %s hello=[%s]\n", ArchiveErrorToString(err),
                Slurp(dir + "/pkg/hello.txt").c_str());
    std::string cmd = "rm -rf '" + dir + "'";
    if (system(cmd.c_str()) != 0) std::printf("cleanup failed\n");
  }
  return 0;
}
