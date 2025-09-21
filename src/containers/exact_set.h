#pragma once
#include <cstdint>
#include <vector>

struct ExactSet {
  struct Entry { uint64_t fp=0; uint32_t off=0; uint32_t pad=0; };
  std::vector<Entry>   table; // power-of-two sized
  std::vector<uint8_t> blob;  // N*33 packed pubkeys
  uint32_t mask=0;

  void build(const uint8_t* pub33, uint64_t n, double load=0.80);
  bool contains(const uint8_t key33[33]) const;
};
