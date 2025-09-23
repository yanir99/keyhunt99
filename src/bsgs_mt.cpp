#include <thread>
#include <atomic>
#include <vector>
#include <string>
#include <cstdio>
#include <cstdint>
#include <algorithm>
#include <cstring>

#include "portable/portable.h"
#include "portable/numa_linux.h"
#include "filters/tag_prefilter.h"
#include "filters/bloom2.h"
#include "containers/exact_set.h"

// Your ECC headers:
#include "../secp256k1/SECP256k1.h"
#include "../secp256k1/Point.h"
#include "../secp256k1/Int.h"

// ---------------- CLI options struct ----------------
struct BsgsMtOptions {
  std::string targets_path;
  std::string range_hex;     // "-r <start:end>" already parsed by your CLI; pass start and end as hex strings or set below fields
  std::string range_start_hex;
  std::string range_end_hex;

  uint64_t    baby_size = (1ull<<26); // m
  int         block_size=8192;
  int         threads=0;

  std::string filter_kind="tag+exact";  // or "bloom"
  double      bloom_fpp=1e-9;

  // NUMA (Linux)
  std::string numa_mode="auto";         // off|auto|nodes=0,1
  std::string numa_policy="local";      // local|interleave
  bool        hugepages=false;
};

// --------- Helpers to parse hex -> Int ---------
static bool parse_hex_u256(const std::string& hex, Int &out) {
  // Accept hex with or without 0x, big-endian
  std::string s = hex;
  if (s.size()>2 && s[0]=='0' && (s[1]=='x'||s[1]=='X')) s = s.substr(2);
  // Build 32 bytes
  std::vector<uint8_t> buf(32,0);
  int bi = 31;
  int i = (int)s.size()-1;
  int nybble = 0; uint8_t byte = 0;
  auto hv=[&](char c)->int{
    if(c>='0'&&c<='9') return c-'0';
    if(c>='a'&&c<='f') return c-'a'+10;
    if(c>='A'&&c<='F') return c-'A'+10;
    return -1;
  };
  while (i>=0 && bi>=0) {
    int v = hv(s[i--]); if (v<0) return false;
    if (nybble==0) { byte = (uint8_t)v; nybble=1; }
    else { byte |= (uint8_t)(v<<4); buf[bi--] = byte; nybble=0; byte=0; }
  }
  if (nybble==1) { buf[bi--] = byte; }
  // Set Int from bytes (big-endian)
  out.SetInt32(0);
  for (int k=0;k<32;k++) out.SetByte(31-k, buf[k]); // Int has SetByte(index, value)
  return true;
}

static void read_targets_as_compressed33(const std::string& path, std::vector<uint8_t>& out33, Secp256K1& secp) {
  FILE* f = fopen(path.c_str(), "rb");
  if(!f){ fprintf(stderr,"[bsgs-mt] cannot open targets file\n"); return; }
  char line[256];
  while (fgets(line, sizeof(line), f)) {
    char* p=line; while(*p==' '||*p=='\t') ++p;
    int L=0; while(p[L] && p[L]!='\r' && p[L]!='\n') ++L; p[L]=0;
    if (L<2) continue;
    // Accept 33B or 65B hex
    auto hexv=[&](char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return 0; };
    if ((L==66 && (p[0]=='0'?(p[1]=='2'||p[1]=='3'):(p[0]=='2'||p[0]=='3'))) ||
        (L==130 && (p[0]=='0'?p[1]=='4':p[0]=='4'))) {
      std::vector<uint8_t> tmp(L/2);
      for (int i=0;i<L;i+=2) tmp[i/2] = (uint8_t)((hexv(p[i])<<4)|hexv(p[i+1]));
      if (tmp.size()==33) out33.insert(out33.end(), tmp.begin(), tmp.end());
      else if (tmp.size()==65 && tmp[0]==0x04) {
        // compress: 02/03 || X
        uint8_t out[33]; out[0] = (tmp[64] & 1) ? 0x03 : 0x02; std::memcpy(out+1, &tmp[1], 32);
        out33.insert(out33.end(), out, out+33);
      }
    }
  }
  fclose(f);
}

// ---------------- NUMA resources per node ----------------
struct NodeResources {
  int node=0;
  Point* baby=nullptr;     // baby table
  size_t baby_bytes=0;
  uint64_t m=0;
  TagPrefilter pre;
  ExactSet exact;
  Bloom2 bloom;
  bool use_exact=true, use_bloom=false;
};

// Build baby table with NextKey (fast G additions inside your lib)
static void build_baby_table(Point* B, uint64_t m, Secp256K1& secp){
  // B[0] = Infinity (identity)
  B[0].Clear();
  if (m==1) return;
  B[1] = secp.G;
  Point p = B[1];
  for (uint64_t j=2;j<m;j++){
    p = secp.NextKey(p);   // p = p + G
    B[j] = p;
  }
}

// Serialize compressed (33B) using your lib (handles affine normalization internally)
static inline void serialize_pub33(const Point& P, uint8_t out[33], Secp256K1& secp){
  // Unfortunately GetPublicKeyRaw wants non-const, so const_cast is used.
  Point &ref = const_cast<Point&>(P);
  secp.GetPublicKeyRaw(true, ref, (char*)out);
}

// Worker job per thread
struct WorkerJob {
  const NodeResources* R=nullptr;
  uint64_t i_begin=0, i_end=0; // giant index range [i_begin, i_end)
  int block=8192;
  Secp256K1* secp=nullptr;
};

// main inner loop (no batch inversion; we rely on Point::Add being projective)
static void worker_bsgs(const WorkerJob& job){
  const auto& R = *job.R; const uint64_t m = R.m; const int block = job.block;
  Secp256K1& secp = *job.secp;

  // Precompute stride M = m*G
  Int mInt((uint64_t)m);
  Point M = secp.ScalarMultiplication(secp.G, &mInt);

  // base = i_begin * M  (compute with scalar-mult to start)
  Int iInt((uint64_t)job.i_begin);
  Point base = secp.ScalarMultiplication(M, &iInt);

  std::vector<uint8_t> buf(33);
  for(uint64_t i = job.i_begin; i < job.i_end; ++i){

    // j in blocks
    uint64_t j = 0;
    while (j < m) {
      int n = (int)std::min<uint64_t>(block, m - j);

      for (int t=0; t<n; ++t) {
        // P = base + B[j+t]
        Point P = secp.Add(base, R.baby[j+t]);

        // serialize compressed
        serialize_pub33(P, buf.data(), secp);

        // membership
        bool ok = true;
        if (R.pre.idx[0].len) ok = R.pre.maybe(buf.data());
        if (!ok) continue;
        if (R.use_bloom && !bloom2_maybe(R.bloom, buf.data())) continue;
        if (R.use_exact && !R.exact.contains(buf.data())) continue;

        // If you want: emit scalar k = i*m + (j+t)
        unsigned long long k_low = i * m + (j+t);
        // NOTE: this is the low 64 bits; if you need full 256-bit key, add start offset.
        printf("HIT: k_low=%llu  pub[0]=%02x\n", k_low, buf[0]);
        fflush(stdout);
      }
      j += n;
    }

    // base += M
    base = secp.Add(base, M);
  }
}

// Public entry (call from your CLI)
int run_bsgs_mt(const BsgsMtOptions& opt){
  // --- Init ECC ---
  Secp256K1 secp; secp.Init();

  // --- Load targets -> compressed 33B ---
  std::vector<uint8_t> targets33; targets33.reserve(1<<20);
  read_targets_as_compressed33(opt.targets_path, targets33, secp);
  if (targets33.empty()){ fprintf(stderr,"[bsgs-mt] no targets loaded\n"); return 1; }

  // --- NUMA topo ---
  NumaTopo topo = numa_discover();
  NumaConfig ncfg; ncfg.enabled = (opt.numa_mode!="off" && topo.available);
  ncfg.policy = (opt.numa_policy=="interleave"? NumaPolicy::INTERLEAVE : NumaPolicy::LOCAL);
  ncfg.hugepages = opt.hugepages;
  std::vector<int> nodes_filter;
  if (opt.numa_mode.rfind("nodes=",0)==0) nodes_filter = parse_nodes_list(opt.numa_mode.substr(6));

  std::vector<NumaCpuSet> nodes;
  if (ncfg.enabled){
    if (!nodes_filter.empty()){
      for(int n: nodes_filter) for(auto& g: topo.groups) if (g.node==n) nodes.push_back(g);
    } else nodes = topo.groups;
  } else {
    NumaCpuSet all; all.node=0; int ncpu=cpu_count(); for(int i=0;i<ncpu;i++) all.cpus.push_back(i); nodes.push_back(all);
  }

  // --- Parse range start/end ---
  Int K0, K1; 
  if (!opt.range_start_hex.empty() && !opt.range_end_hex.empty()) {
    if (!parse_hex_u256(opt.range_start_hex, K0) || !parse_hex_u256(opt.range_end_hex, K1)) {
      fprintf(stderr,"[bsgs-mt] invalid -r range hex\n"); return 1;
    }
  } else {
    // If your CLI passes "-r <start:end>" as a single string, split it here.
    fprintf(stderr,"[bsgs-mt] range not set\n"); return 1;
  }

  // Compute i0,r0 and i1,r1 using your Int::Div (quotient in this, remainder out)
  Int mInt((uint64_t)opt.baby_size);

  Int q0(K0); Int r0; q0.Div(&mInt, &r0); // q0 = floor(K0/m), r0 = K0 % m
  Int q1(K1); Int r1; q1.Div(&mInt, &r1); // q1 = floor(K1/m), r1 = K1 % m

  // For practicality we assume q1-q0 fits in uint64_t for one run. Chunk if needed.
  // Extract low 64-bit of q0 and q1 (your Int exposes Get32Bytes; do a quick extraction)
  auto u64_from_Int = [](const Int& x)->uint64_t {
    // Little helper using Get32Bytes as used in SECP256K1.cpp
    uint8_t b[32]; const_cast<Int&>(x).Get32Bytes(b);
    uint64_t v=0; for(int i=24;i<32;i++) v = (v<<8) | b[i];
    return v;
  };
  uint64_t i0 = u64_from_Int(q0);
  uint64_t i1 = u64_from_Int(q1);
  if (i1 < i0) { fprintf(stderr,"[bsgs-mt] empty range\n"); return 0; }

  // --- Build per-node resources (replicate baby & sets) ---
  std::vector<NodeResources> res(nodes.size());
  for(size_t ni=0; ni<nodes.size(); ++ni){
    numa_set_thread_mem_policy_portable(ncfg, topo, nodes[ni].node);
    res[ni].node = nodes[ni].node; res[ni].m = opt.baby_size;

    // Baby table
    size_t bytes = opt.baby_size * sizeof(Point);
    res[ni].baby = (Point*)numa_alloc_portable(bytes, ncfg, topo, nodes[ni].node);
    res[ni].baby_bytes = bytes;
    build_baby_table(res[ni].baby, opt.baby_size, secp);

    // Membership
    if (opt.filter_kind=="bloom") {
      res[ni].use_bloom=true; res[ni].use_exact=false;
      bloom2_init(res[ni].bloom, targets33.size()/33, opt.bloom_fpp);
      for(size_t i=0;i<targets33.size(); i+=33) bloom2_add(res[ni].bloom, &targets33[i]);
    } else {
      res[ni].use_exact=true; res[ni].use_bloom=false;
      res[ni].pre.build(targets33.data(), targets33.size()/33);
      res[ni].exact.build(targets33.data(), targets33.size()/33, 0.80);
    }
  }

  // --- Dispatch threads across nodes ---
  std::vector<std::thread> pool;
  for(size_t ni=0; ni<nodes.size(); ++ni){
    auto& g = nodes[ni]; auto& R = res[ni];
    int nthr = (int)g.cpus.size(); if (opt.threads>0) nthr = std::min(nthr, opt.threads/(int)nodes.size());
    if (nthr<=0) nthr = 1;
    uint64_t span = (i1 - i0 + 1);
    for(int t=0;t<nthr;t++){
      uint64_t tb = i0 + (span * t)/nthr;
      uint64_t te = i0 + (span * (t+1))/nthr;
      pool.emplace_back([&, ni, t, tb, te]{
        pin_thread_to_node_cpu(nodes[ni], t);
        WorkerJob job; job.R=&R; job.i_begin=tb; job.i_end=te; job.block=opt.block_size; job.secp=&secp;
        worker_bsgs(job);
      });
    }
  }
  for(auto& th: pool) th.join();

  // Cleanup
  for(auto& R: res){ if (R.baby) numa_free_portable(R.baby, R.baby_bytes); }
  return 0;
}