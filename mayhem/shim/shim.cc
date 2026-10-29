#include "cef/libcef_dll/bootstrap/installer/installer_parallel_xz.h"

// The parallel (thread-pool) extraction path is not part of any fuzz target; route it to the
// single-threaded streaming extractor so installer_archive.cc links without Chromium's ThreadPool.
namespace cef_installer {
ArchiveError ExtractTarXzParallel(const base::FilePath& archive_path,
                                  const base::FilePath& dest_dir,
                                  const ExtractionConfig&,
                                  ExtractionProgressCallback progress) {
  return ExtractTarXzSingleThread(archive_path, dest_dir, std::move(progress));
}
}  // namespace cef_installer
