#pragma once
#include <cstdint>
#include <vector>
#include <array>

struct TagPrefilter {
  struct Bucket { uint32_t off=0, len=0; };
  std::array<Bucket, 1u<<16> idx{}; // 65,536 buckets
  std::vector<uint8_t> tags;        // concatenated 1-byte tags

  void build(const uint8_t* pub33, uint64_t n);
  bool maybe(const uint8_t key33[33]) const;
};
