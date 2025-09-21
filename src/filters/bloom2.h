#pragma once
#include <cstdint>

struct Bloom2 {
  uint64_t m_bits=0; int k=0; uint64_t n_items=0;
  std::vector<uint8_t> bits; // vector keeps it portable everywhere
};

bool bloom2_init(Bloom2& b, uint64_t n_items, double fpp);
void bloom2_add(Bloom2& b, const uint8_t key33[33]);
bool bloom2_maybe(const Bloom2& b, const uint8_t key33[33]);
