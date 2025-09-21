#include "bloom2.h"
#include <cmath>
#include <cstring>
#include <algorithm>

static inline uint64_t mix64(uint64_t x){
  x ^= x >> 33; x *= 0xff51afd7ed558ccdULL;
  x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ULL;
  x ^= x >> 33; return x;
}
static inline void params(uint64_t n, double fpp, uint64_t& m_bits, int& k){
  double bpe = -std::log(fpp) / (std::log(2.0)*std::log(2.0));
  m_bits = (uint64_t)std::ceil(bpe * (double)n);
  k = std::max(1, (int)std::round((m_bits/(double)n) * std::log(2.0)));
  const uint64_t blk = 2048ull*8ull; // 2KB blocks
  m_bits = ((m_bits + blk - 1) / blk) * blk;
}
static inline void hash12(const uint8_t k33[33], uint64_t& h1, uint64_t& h2){
  uint64_t h=0x9e3779b97f4a7c15ULL;
  for(int i=0;i<33;i++){ h ^= (uint64_t)k33[i] << ((i&7)*8); h = mix64(h); }
  h1 = mix64(h ^ 0xa5a5a5a55a5a5a5aULL);
  h2 = (mix64(h ^ 0x5a5a5a5aa5a5a5a5ULL) | 1ULL);
}
static inline void setbit(std::vector<uint8_t>& bits, uint64_t bit){ bits[bit>>3] |= (uint8_t)(1u << (bit&7)); }
static inline bool getbit(const std::vector<uint8_t>& bits, uint64_t bit){ return (bits[bit>>3] >> (bit&7)) & 1u; }

bool bloom2_init(Bloom2& b, uint64_t n_items, double fpp){
  b.n_items = n_items; params(n_items, fpp, b.m_bits, b.k);
  size_t bytes = (size_t)((b.m_bits + 7) / 8);
  b.bits.assign(bytes, 0);
  return true;
}
void bloom2_add(Bloom2& b, const uint8_t key33[33]){
  uint64_t h1,h2; hash12(key33, h1,h2);
  const uint64_t blk = 2048ull*8ull;
  uint64_t blocks = b.m_bits / blk;
  uint64_t blk_idx = (h1 >> 32) % blocks;
  uint64_t base = blk_idx * blk;
  for(int i=0;i<b.k;i++){
    uint64_t bit = base + ((h1 + i*h2) % blk);
    setbit(b.bits, bit);
  }
}
bool bloom2_maybe(const Bloom2& b, const uint8_t key33[33]){
  uint64_t h1,h2; hash12(key33, h1,h2);
  const uint64_t blk = 2048ull*8ull;
  uint64_t blocks = b.m_bits / blk;
  uint64_t blk_idx = (h1 >> 32) % blocks;
  uint64_t base = blk_idx * blk;
  for(int i=0;i<b.k;i++){
    uint64_t bit = base + ((h1 + i*h2) % blk);
    if (!getbit(b.bits, bit)) return false;
  }
  return true;
}
