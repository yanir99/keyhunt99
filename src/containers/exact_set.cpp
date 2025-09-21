#include "exact_set.h"
#include <cstring>
#include <cmath>

static inline uint64_t mix64(uint64_t x){
  x ^= x >> 33; x *= 0xff51afd7ed558ccdULL;
  x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ULL;
  x ^= x >> 33; return x;
}
static inline uint64_t hash33(const uint8_t k[33]){
  uint64_t h=0x9e3779b97f4a7c15ULL;
  for(int i=0;i<33;i++){ h ^= (uint64_t)k[i] << ((i&7)*8); h = mix64(h); }
  return (mix64(h) | 1ULL); // never zero (marks empty)
}
static inline uint32_t next_pow2(uint32_t v){ v--; v|=v>>1; v|=v>>2; v|=v>>4; v|=v>>8; v|=v>>16; return v+1; }

void ExactSet::build(const uint8_t* pub33, uint64_t n, double load){
  blob.assign(pub33, pub33 + n*33);
  uint32_t need = (uint32_t)std::ceil(n / load);
  uint32_t sz = next_pow2(need < (1u<<10) ? (1u<<10) : need);
  table.assign(sz, {}); mask = sz - 1;
  for(uint64_t i=0;i<n;i++){
    const uint8_t* p = pub33 + i*33;
    uint64_t fp = hash33(p);
    uint32_t pos = (uint32_t)(fp & mask);
    while(true){
      if (table[pos].fp == 0){ table[pos].fp = fp; table[pos].off = (uint32_t)(i*33); break; }
      pos = (pos + 1) & mask;
    }
  }
}
bool ExactSet::contains(const uint8_t key33[33]) const{
  uint64_t fp = hash33(key33);
  uint32_t pos = (uint32_t)(fp & mask);
  while(true){
    const Entry& e = table[pos];
    if (e.fp == 0) return false;
    if (e.fp == fp){
      const uint8_t* p = blob.data() + e.off;
      if (std::memcmp(p, key33, 33)==0) return true;
    }
    pos = (pos + 1) & mask;
  }
}
