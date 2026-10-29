// Minimal stand-in for the slice of Chromium //base that CEF's installer archive/XZ code uses, so
// that code (and its in-tree fuzz harnesses) builds without a Chromium checkout. Semantics follow
// Chromium: overflow in checked_cast/ValueOrDie is a fatal crash, span access is bounds-checked
// (via -D_GLIBCXX_ASSERTIONS), LOG() output is discarded.
#ifndef MAYHEM_SHIM_BASE_SHIM_H_
#define MAYHEM_SHIM_BASE_SHIM_H_

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
#include <limits>
#include <new>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#define BUILDFLAG(flag) (BUILDFLAG_INTERNAL_##flag())
// The fuzz and kat binaries build the POSIX branches. The upstream-gtest binary defines
// MAYHEM_SHIM_IS_WIN so the portable Windows-only logic (reserved device names, wide paths) that the
// suites assert on is compiled in too.
#ifdef MAYHEM_SHIM_IS_WIN
#define BUILDFLAG_INTERNAL_IS_WIN() (1)
#define BUILDFLAG_INTERNAL_IS_POSIX() (0)
#else
#define BUILDFLAG_INTERNAL_IS_WIN() (0)
#define BUILDFLAG_INTERNAL_IS_POSIX() (1)
#endif

namespace base {

template <typename T, size_t N = std::dynamic_extent>
using span = std::span<T, N>;

class NullStream {
 public:
  template <typename T>
  NullStream& operator<<(const T&) {
    return *this;
  }
};
#define LOG(severity) ::base::NullStream()

[[noreturn]] inline void ShimCrash(const char* what) {
  std::fprintf(stderr, "FATAL: %s\n", what);
  std::abort();
}

// --- numerics ---------------------------------------------------------------

template <typename Dst, typename Src>
constexpr Dst checked_cast(Src value) {
  if (!std::in_range<Dst>(value)) {
    ShimCrash("checked_cast out of range");
  }
  return static_cast<Dst>(value);
}

template <typename T>
class CheckedNumeric {
  static_assert(std::is_integral_v<T>);

 public:
  constexpr CheckedNumeric() = default;
  template <typename U, typename = std::enable_if_t<std::is_integral_v<U>>>
  constexpr CheckedNumeric(U v) {
    if (std::in_range<T>(v)) {
      value_ = static_cast<T>(v);
    } else {
      valid_ = false;
    }
  }

  constexpr bool IsValid() const { return valid_; }
  constexpr T ValueOrDie() const {
    if (!valid_) {
      ShimCrash("CheckedNumeric::ValueOrDie on invalid value");
    }
    return value_;
  }

  template <typename U, typename = std::enable_if_t<std::is_integral_v<U>>>
  CheckedNumeric& operator+=(U rhs) {
    return Apply(CheckedNumeric(rhs), [](T a, T b, T* o) { return __builtin_add_overflow(a, b, o); });
  }
  template <typename U, typename = std::enable_if_t<std::is_integral_v<U>>>
  CheckedNumeric& operator*=(U rhs) {
    return Apply(CheckedNumeric(rhs), [](T a, T b, T* o) { return __builtin_mul_overflow(a, b, o); });
  }
  template <typename U, typename = std::enable_if_t<std::is_integral_v<U>>>
  CheckedNumeric& operator<<=(U shift) {
    if (!valid_ || shift < 0 ||
        static_cast<uint64_t>(shift) >=
            static_cast<uint64_t>(std::numeric_limits<T>::digits)) {
      valid_ = false;
    } else {
      value_ = static_cast<T>(static_cast<std::make_unsigned_t<T>>(value_)
                              << shift);
    }
    return *this;
  }
  CheckedNumeric& operator+=(const CheckedNumeric& rhs) {
    return Apply(rhs, [](T a, T b, T* o) { return __builtin_add_overflow(a, b, o); });
  }

  template <typename U, typename = std::enable_if_t<std::is_integral_v<U>>>
  friend CheckedNumeric operator+(CheckedNumeric lhs, U rhs) {
    lhs += rhs;
    return lhs;
  }

 private:
  template <typename F>
  CheckedNumeric& Apply(const CheckedNumeric& rhs, F op) {
    if (!valid_ || !rhs.valid_) {
      valid_ = false;
    } else {
      T out;
      if (op(value_, rhs.value_, &out)) {
        valid_ = false;
      } else {
        value_ = out;
      }
    }
    return *this;
  }

  T value_ = 0;
  bool valid_ = true;
};

inline uint32_t U32FromLittleEndian(span<const uint8_t, 4u> bytes) {
  uint32_t v;
  std::memcpy(&v, bytes.data(), 4);
  return v;  // x86-64 / aarch64 little-endian hosts only
}

inline bool StringToSizeT(std::string_view s, size_t* out) {
  size_t i = 0;
  if (i < s.size() && s[i] == '+') {
    ++i;
  }
  if (i == s.size()) {
    return false;
  }
  size_t value = 0;
  for (; i < s.size(); ++i) {
    if (s[i] < '0' || s[i] > '9') {
      return false;
    }
    size_t digit = static_cast<size_t>(s[i] - '0');
    if (value > (std::numeric_limits<size_t>::max() - digit) / 10) {
      return false;
    }
    value = value * 10 + digit;
  }
  *out = value;
  return true;
}

// --- time / functional / misc ----------------------------------------------

class Time {
 public:
  static Time FromTimeT(time_t t) {
    Time r;
    r.t_ = t;
    r.null_ = false;
    return r;
  }
  bool is_null() const { return null_; }
  time_t ToTimeT() const { return t_; }
  friend bool operator==(const Time& a, const Time& b) { return a.null_ == b.null_ && a.t_ == b.t_; }

 private:
  time_t t_ = 0;
  bool null_ = true;
};

template <typename Sig>
class RepeatingCallback;
template <typename R, typename... Args>
class RepeatingCallback<R(Args...)> {
 public:
  RepeatingCallback() = default;
  template <typename F>
  RepeatingCallback(F f) : fn_(std::move(f)) {}
  explicit operator bool() const { return static_cast<bool>(fn_); }
  R Run(Args... args) const { return fn_(std::forward<Args>(args)...); }

 private:
  std::function<R(Args...)> fn_;
};

template <typename T>
class NoDestructor {
 public:
  template <typename... A>
  explicit NoDestructor(A&&... args) : ptr_(new T(std::forward<A>(args)...)) {}
  T* get() { return ptr_; }
  T* operator->() { return ptr_; }
  T& operator*() { return *ptr_; }

 private:
  T* ptr_;
};

// --- files ------------------------------------------------------------------

// UTF-8 path text that also compares equal to wide literals: CEF's installer is Windows code whose
// tests write `EXPECT_EQ(L"x", path.value())`; this shim's FilePath is narrow on POSIX.
class PathString : public std::string {
 public:
  PathString() = default;
  PathString(std::string s) : std::string(std::move(s)) {}
  friend bool operator==(const wchar_t* lhs, const PathString& rhs) {
    return rhs == lhs;
  }
  friend bool operator==(const PathString& lhs, const wchar_t* rhs) {
    size_t n = 0;
    while (rhs[n] != 0) {
      ++n;
    }
    if (n != lhs.size()) {
      return false;
    }
    for (size_t i = 0; i < n; ++i) {
      if (static_cast<uint32_t>(rhs[i]) != static_cast<unsigned char>(lhs[i])) {
        return false;
      }
    }
    return true;
  }
  friend bool operator==(const PathString& lhs, const PathString& rhs) {
    return static_cast<const std::string&>(lhs) == static_cast<const std::string&>(rhs);
  }
};

inline std::string WideToUTF8(std::wstring_view w) {
  std::string out;
  for (wchar_t wc : w) {
    uint32_t c = static_cast<uint32_t>(wc);
    if (c < 0x80) {
      out.push_back(static_cast<char>(c));
    } else if (c < 0x800) {
      out.push_back(static_cast<char>(0xC0 | (c >> 6)));
      out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
    } else if (c < 0x10000) {
      out.push_back(static_cast<char>(0xE0 | (c >> 12)));
      out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
    } else {
      out.push_back(static_cast<char>(0xF0 | (c >> 18)));
      out.push_back(static_cast<char>(0x80 | ((c >> 12) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
    }
  }
  return out;
}

inline std::wstring UTF8ToWide(std::string_view s) {
  std::wstring out;
  for (size_t i = 0; i < s.size();) {
    unsigned char b = static_cast<unsigned char>(s[i]);
    size_t len = b < 0x80 ? 1 : (b >> 5) == 6 ? 2 : (b >> 4) == 14 ? 3 : (b >> 3) == 30 ? 4 : 0;
    if (len == 0 || i + len > s.size()) {
      out.push_back(0xFFFD);
      ++i;
      continue;
    }
    uint32_t c = len == 1 ? b : (b & (0xFF >> (len + 1)));
    for (size_t k = 1; k < len; ++k) {
      c = (c << 6) | (static_cast<unsigned char>(s[i + k]) & 0x3F);
    }
    out.push_back(static_cast<wchar_t>(c));
    i += len;
  }
  return out;
}

class FilePath {
 public:
  FilePath() = default;
  explicit FilePath(std::string s) : path_(std::move(s)) {}
  explicit FilePath(std::wstring_view s) : path_(WideToUTF8(s)) {}
  const PathString& value() const { return path_; }
  bool empty() const { return path_.empty(); }

  FilePath Append(std::string_view component) const { return Append(FilePath(std::string(component))); }
  FilePath Append(std::wstring_view component) const { return Append(FilePath(component)); }
  FilePath AppendASCII(std::string_view component) const { return Append(FilePath(std::string(component))); }

  FilePath Append(const FilePath& component) const {
    if (path_.empty()) {
      return component;
    }
    if (component.path_.empty()) {
      return *this;
    }
    std::string out = path_;
    if (out.back() != '/') {
      out.push_back('/');
    }
    out += component.path_;
    return FilePath(std::move(out));
  }

  FilePath DirName() const {
    std::string s = path_;
    while (s.size() > 1 && s.back() == '/') {
      s.pop_back();
    }
    size_t slash = s.rfind('/');
    if (slash == std::string::npos) {
      return FilePath(".");
    }
    s.erase(slash);
    while (s.size() > 1 && s.back() == '/') {
      s.pop_back();
    }
    return FilePath(s.empty() ? "/" : s);
  }

 private:
  PathString path_;
};

class File {
 public:
  enum Flags : uint32_t {
    FLAG_OPEN = 1 << 0,
    FLAG_CREATE = 1 << 1,
    FLAG_OPEN_ALWAYS = 1 << 2,
    FLAG_CREATE_ALWAYS = 1 << 3,
    FLAG_READ = 1 << 4,
    FLAG_WRITE = 1 << 5,
    FLAG_WIN_TEMPORARY = 1 << 6,
    FLAG_DELETE_ON_CLOSE = 1 << 7,
    FLAG_WIN_SHARE_DELETE = 1 << 8,
  };
  enum Whence { FROM_BEGIN = SEEK_SET, FROM_CURRENT = SEEK_CUR, FROM_END = SEEK_END };

  struct Info {
    int64_t size = 0;
    bool is_directory = false;
    Time last_modified;
  };

  File() = default;
  File(const FilePath& path, uint32_t flags) { Initialize(path, flags); }
  File(File&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
  File& operator=(File&& o) noexcept {
    if (this != &o) {
      Close();
      fd_ = o.fd_;
      o.fd_ = -1;
    }
    return *this;
  }
  File(const File&) = delete;
  File& operator=(const File&) = delete;
  ~File() { Close(); }

  void Initialize(const FilePath& path, uint32_t flags) {
    Close();
    int oflags = O_CLOEXEC;
    if ((flags & FLAG_READ) && (flags & FLAG_WRITE)) {
      oflags |= O_RDWR;
    } else if (flags & FLAG_WRITE) {
      oflags |= O_WRONLY;
    } else {
      oflags |= O_RDONLY;
    }
    if (flags & FLAG_CREATE) {
      oflags |= O_CREAT | O_EXCL;
    } else if (flags & FLAG_CREATE_ALWAYS) {
      oflags |= O_CREAT | O_TRUNC;
    } else if (flags & FLAG_OPEN_ALWAYS) {
      oflags |= O_CREAT;
    }
    fd_ = ::open(path.value().c_str(), oflags, 0600);
    if (fd_ >= 0 && (flags & FLAG_DELETE_ON_CLOSE)) {
      ::unlink(path.value().c_str());
    }
  }

  bool IsValid() const { return fd_ >= 0; }
  void Close() {
    if (fd_ >= 0) {
      ::close(fd_);
      fd_ = -1;
    }
  }
  int64_t GetLength() {
    struct stat st;
    if (fd_ < 0 || ::fstat(fd_, &st) != 0) {
      return -1;
    }
    return st.st_size;
  }
  bool SetLength(int64_t length) { return fd_ >= 0 && ::ftruncate(fd_, length) == 0; }
  int64_t Seek(Whence whence, int64_t offset) {
    return fd_ < 0 ? -1 : ::lseek(fd_, offset, whence);
  }

  std::optional<size_t> ReadAtCurrentPos(span<uint8_t> buf) {
    if (fd_ < 0) {
      return std::nullopt;
    }
    ssize_t n = ::read(fd_, buf.data(), buf.size());
    if (n < 0) {
      return std::nullopt;
    }
    return static_cast<size_t>(n);
  }
  bool ReadAtCurrentPosAndCheck(span<uint8_t> buf) {
    size_t done = 0;
    while (done < buf.size()) {
      ssize_t n = ::read(fd_, buf.data() + done, buf.size() - done);
      if (n <= 0) {
        return false;
      }
      done += static_cast<size_t>(n);
    }
    return true;
  }
  bool WriteAtCurrentPosAndCheck(span<const uint8_t> buf) {
    size_t done = 0;
    while (done < buf.size()) {
      ssize_t n = ::write(fd_, buf.data() + done, buf.size() - done);
      if (n <= 0) {
        return false;
      }
      done += static_cast<size_t>(n);
    }
    return true;
  }
  std::optional<size_t> Write(int64_t offset, span<const uint8_t> buf) {
    if (fd_ < 0) {
      return std::nullopt;
    }
    size_t done = 0;
    while (done < buf.size()) {
      ssize_t n = ::pwrite(fd_, buf.data() + done, buf.size() - done,
                           offset + static_cast<int64_t>(done));
      if (n <= 0) {
        return std::nullopt;
      }
      done += static_cast<size_t>(n);
    }
    return done;
  }

 private:
  int fd_ = -1;
};

inline std::string ShimTempRoot() {
  const char* t = std::getenv("TMPDIR");
  return (t && *t) ? t : "/tmp";
}

inline bool CreateDirectory(const FilePath& path) {
  std::error_code ec;
  if (std::filesystem::is_directory(path.value().c_str(), ec)) {
    return true;
  }
  std::filesystem::create_directories(path.value().c_str(), ec);
  return !ec && std::filesystem::is_directory(path.value().c_str(), ec);
}

inline bool TouchFile(const FilePath& path, const Time& accessed, const Time& modified) {
  struct timespec ts[2] = {{accessed.ToTimeT(), 0}, {modified.ToTimeT(), 0}};
  return ::utimensat(AT_FDCWD, path.value().c_str(), ts, 0) == 0;
}

inline bool CreateTemporaryFile(FilePath* path) {
  std::string tmpl = ShimTempRoot() + "/shim-tmp-XXXXXX";
  int fd = ::mkstemp(tmpl.data());
  if (fd < 0) {
    return false;
  }
  ::close(fd);
  *path = FilePath(tmpl);
  return true;
}

class ScopedTempDir {
 public:
  ScopedTempDir() = default;
  ScopedTempDir(const ScopedTempDir&) = delete;
  ScopedTempDir& operator=(const ScopedTempDir&) = delete;
  ~ScopedTempDir() { Remove(); }

  bool CreateUniqueTempDir() { return CreateUnder(FilePath(ShimTempRoot())); }
  bool CreateUniqueTempDirUnderPath(const FilePath& parent) { return CreateUnder(parent); }
  bool IsValid() const { return !path_.empty(); }
  const FilePath& GetPath() const { return path_; }

 private:
  bool CreateUnder(const FilePath& parent) {
    Remove();
    std::string tmpl = parent.value() + "/scoped_dir_XXXXXX";
    if (::mkdtemp(tmpl.data()) == nullptr) {
      return false;
    }
    path_ = FilePath(tmpl);
    return true;
  }
  void Remove() {
    if (!path_.empty()) {
      std::error_code ec;
      std::filesystem::remove_all(path_.value().c_str(), ec);
      path_ = FilePath();
    }
  }
  FilePath path_;
};

// --- test-support slice (used only by the upstream gtest suites built in mayhem/build.sh) -------

inline bool PathExists(const FilePath& p) {
  std::error_code ec;
  return std::filesystem::exists(p.value().c_str(), ec);
}
inline bool GetFileInfo(const FilePath& p, File::Info* info) {
  struct stat st;
  if (::stat(p.value().c_str(), &st) != 0) {
    return false;
  }
  info->size = st.st_size;
  info->is_directory = S_ISDIR(st.st_mode);
  info->last_modified = Time::FromTimeT(st.st_mtime);
  return true;
}
inline bool DirectoryExists(const FilePath& p) {
  std::error_code ec;
  return std::filesystem::is_directory(p.value().c_str(), ec);
}
inline std::optional<int64_t> GetFileSize(const FilePath& p) {
  struct stat st;
  if (::stat(p.value().c_str(), &st) != 0) {
    return std::nullopt;
  }
  return static_cast<int64_t>(st.st_size);
}
inline bool ReadFileToString(const FilePath& p, std::string* out) {
  FILE* f = std::fopen(p.value().c_str(), "rb");
  if (!f) {
    return false;
  }
  out->clear();
  char buf[65536];
  size_t n;
  while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) {
    out->append(buf, n);
  }
  bool ok = !std::ferror(f);
  std::fclose(f);
  return ok;
}
inline bool WriteFile(const FilePath& p, std::string_view data) {
  FILE* f = std::fopen(p.value().c_str(), "wb");
  if (!f) {
    return false;
  }
  bool ok = std::fwrite(data.data(), 1, data.size(), f) == data.size();
  return std::fclose(f) == 0 && ok;
}
inline bool WriteFile(const FilePath& p, span<const uint8_t> data) {
  return WriteFile(p, std::string_view(reinterpret_cast<const char*>(data.data()), data.size()));
}
inline std::string_view as_string_view(span<const uint8_t> s) {
  return std::string_view(reinterpret_cast<const char*>(s.data()), s.size());
}

template <typename F, typename... Bound>
auto BindRepeating(F f, Bound... bound) {
  return [f, bound...](auto&&... rest) { return f(bound..., std::forward<decltype(rest)>(rest)...); };
}

enum TrimPositions { TRIM_NONE = 0, TRIM_LEADING = 1, TRIM_TRAILING = 2, TRIM_ALL = 3 };
inline TrimPositions TrimWhitespaceASCII(std::string_view in, TrimPositions where, std::string* out) {
  size_t b = 0, e = in.size();
  auto ws = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
  if (where & TRIM_LEADING) {
    while (b < e && ws(in[b])) {
      ++b;
    }
  }
  if (where & TRIM_TRAILING) {
    while (e > b && ws(in[e - 1])) {
      --e;
    }
  }
  *out = std::string(in.substr(b, e - b));
  return where;
}

enum BasePathKey { DIR_SRC_TEST_DATA_ROOT = 1 };
class PathService {
 public:
  // The directory that contains `cef/` (the build links $SRC there); set by mayhem/test.sh.
  static bool Get(int key, FilePath* out) {
    const char* root = std::getenv("MAYHEM_SRC_TEST_DATA_ROOT");
    if (key != DIR_SRC_TEST_DATA_ROOT || !root || !*root) {
      return false;
    }
    *out = FilePath(root);
    return true;
  }
};

namespace test {
// Only ExtractTarXzIntegrationTest holds one; ExtractTarXz runs on the calling thread in this shim.
class TaskEnvironment {};
}  // namespace test

}  // namespace base

#endif  // MAYHEM_SHIM_BASE_SHIM_H_
