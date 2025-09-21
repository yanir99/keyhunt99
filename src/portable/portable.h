#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

bool rng_bytes(void* dst, size_t len);
int  cpu_count();
uint64_t monotonic_us();

struct MappedFile { void* data=nullptr; size_t size=0; void* h1=nullptr; void* h2=nullptr; };
bool map_file(const std::string& path, MappedFile& out, bool write=false);
void unmap_file(MappedFile& m);
