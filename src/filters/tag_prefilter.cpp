#include "tag_prefilter.h"
#include <algorithm>
#include <cstring>

static inline uint64_t mix64(uint64_t x){
  x ^= x >> 33; x *= 0xff51afd7ed558ccdULL;
  x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ULL;
  x ^= x >> 33; return x;
}
static inline uint64_t hash33(const uint8_t k[33]){
  uint64_t h=0x9e3779b97f4a7c15ULL;
  for(int i=0;i<33;i++){ h ^= (uint64_t)k[i] << ((i&7)*8); h = mix64(h); }
  return mix64(h);
}

void TagPrefilter::build(const uint8_t* pub33, uint64_t n){
  std::vector<uint32_t> cnt(1u<<16, 0);
  for(uint64_t i=0;i<n;i++){
    const uint8_t* p = pub33 + i*33;
    uint64_t h = hash33(p);
    cnt[(uint32_t)(h & 0xFFFFu)]++;
  }
  uint32_t off=0; for(size_t b=0;b<idx.size();++b){ idx[b].off = off; idx[b].len = cnt[b]; off += cnt[b]; }
  tags.assign(off, 0);
  std::vector<uint32_t> cur(idx.size()); for(size_t b=0;b<idx.size();++b) cur[b]=idx[b].off;
  for(uint64_t i=0;i<n;i++){
    const uint8_t* p = pub33 + i*33;
    uint64_t h = hash33(p);
    uint32_t b = (uint32_t)(h & 0xFFFFu);
    uint8_t  t = (uint8_t)((h >> 16) & 0xFFu);
    tags[cur[b]++] = t;
  }
  for(size_t b=0;b<idx.size();++b){
    auto s = tags.begin()+idx[b].off, e = s + idx[b].len;
    std::sort(s,e);
  }
}

bool TagPrefilter::maybe(const uint8_t key33[33]) const{
  uint64_t h = hash33(key33);
  uint32_t b = (uint32_t)(h & 0xFFFFu);
  uint8_t  t = (uint8_t)((h >> 16) & 0xFFu);
  const Bucket& bk = idx[b];
  const uint8_t* base = tags.data() + bk.off;
  return std::binary_search(base, base+bk.len, t);
}
