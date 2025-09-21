#include "portable.h"
#include <chrono>
#include <cstring>
#ifdef _WIN32
  #define NOMINMAX
  #include <windows.h>
  #include <bcrypt.h>
#else
  #include <unistd.h>
  #include <sys/mman.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #include <sys/syscall.h>
  #include <errno.h>
#endif

bool rng_bytes(void* dst, size_t len) {
#ifdef _WIN32
  NTSTATUS st = BCryptGenRandom(nullptr, (PUCHAR)dst, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  return st == 0;
#else
  #ifdef SYS_getrandom
  ssize_t n = syscall(SYS_getrandom, dst, len, 0);
  if (n == (ssize_t)len) return true;
  #endif
  int fd = ::open("/dev/urandom", O_RDONLY);
  if (fd < 0) return false;
  size_t off=0; while (off<len) {
    ssize_t r = ::read(fd, (char*)dst+off, len-off);
    if (r<=0) { ::close(fd); return false; }
    off += (size_t)r;
  }
  ::close(fd); return true;
#endif
}

int cpu_count() {
#ifdef _WIN32
  SYSTEM_INFO si; GetSystemInfo(&si); return (int)si.dwNumberOfProcessors;
#else
  long n = sysconf(_SC_NPROCESSORS_ONLN); return (int)(n>0?n:1);
#endif
}

uint64_t monotonic_us() {
#ifdef _WIN32
  LARGE_INTEGER f,c; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c);
  return (uint64_t)(c.QuadPart * 1000000.0 / f.QuadPart);
#else
  using namespace std::chrono;
  return (uint64_t)duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
#endif
}

bool map_file(const std::string& path, MappedFile& out, bool write) {
#ifdef _WIN32
  DWORD acc = write? GENERIC_READ|GENERIC_WRITE : GENERIC_READ;
  HANDLE h = CreateFileA(path.c_str(), acc, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, write? OPEN_ALWAYS:OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h==INVALID_HANDLE_VALUE) return false;
  LARGE_INTEGER sz; if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); return false; }
  HANDLE mh = CreateFileMapping(h, NULL, write? PAGE_READWRITE:PAGE_READONLY, 0, 0, NULL);
  if (!mh) { CloseHandle(h); return false; }
  void* p = MapViewOfFile(mh, write? FILE_MAP_WRITE|FILE_MAP_READ:FILE_MAP_READ, 0,0,0);
  if (!p) { CloseHandle(mh); CloseHandle(h); return false; }
  out.data=p; out.size=(size_t)sz.QuadPart; out.h1=mh; out.h2=h; return true;
#else
  int fd = ::open(path.c_str(), write? O_RDWR|O_CREAT : O_RDONLY, 0644);
  if (fd<0) return false;
  struct stat st; if (fstat(fd,&st)<0) { ::close(fd); return false; }
  size_t len = (size_t)st.st_size;
  int prot = write? (PROT_READ|PROT_WRITE) : PROT_READ;
  void* p = mmap(nullptr, len, prot, MAP_SHARED, fd, 0);
  if (p==MAP_FAILED) { ::close(fd); return false; }
  out.data=p; out.size=len; out.h1=(void*)(intptr_t)fd; return true;
#endif
}

void unmap_file(MappedFile& m) {
#ifdef _WIN32
  if (m.data) UnmapViewOfFile(m.data);
  if (m.h1) CloseHandle((HANDLE)m.h1);
  if (m.h2) CloseHandle((HANDLE)m.h2);
#else
  if (m.data && m.size) munmap(m.data, m.size);
  if (m.h1) ::close((int)(intptr_t)m.h1);
#endif
  m = {};
}
