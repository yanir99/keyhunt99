#include <thread>
#include <atomic>
#include <vector>
#include <string>
#include <cstdio>
#include <cstdint>
#include <algorithm>
#include <cstring>
#include <cctype>
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

// --- 64-bit extraction helpers for Int ---

// Return the low 64 bits of an Int (no fit check).
static inline uint64_t u64_lo_from_Int(const Int& x) {
  uint8_t b[32];
  const_cast<Int&>(x).Get32Bytes(b);   // Int::Get32Bytes isn't const, so cast
  uint64_t v = 0;
  for (int i = 24; i < 32; ++i) v = (v << 8) | b[i];
  return v;
}

// If x fits fully in 64 bits (upper 192 bits are zero), write it to 'out' and return true.
static inline bool int_to_u64_exact(const Int& x, uint64_t& out) {
  uint8_t b[32];
  const_cast<Int&>(x).Get32Bytes(b);
  for (int i = 0; i < 24; ++i) if (b[i] != 0) return false;  // any high byte non-zero → doesn't fit
  uint64_t v = 0;
  for (int i = 24; i < 32; ++i) v = (v << 8) | b[i];
  out = v;
  return true;
}

static void read_targets_as_compressed33(const std::string& path,
                                         std::vector<uint8_t>& out33,
                                         Secp256K1& secp) {
  (void)secp; // not needed; keep to silence -Wunused-parameter
  FILE* f = fopen(path.c_str(), "rb");
  if(!f){
    fprintf(stderr,"[bsgs-mt] cannot open targets file: %s\n", path.c_str());
    return;
  }
  char line[512];
  while (fgets(line, sizeof(line), f)) {
    // 1) chop comment starting at '#'
    char* hash = std::strchr(line, '#');
    if (hash) *hash = '\0';

    // 2) trim trailing whitespace/newlines
    size_t L = std::strlen(line);
    while (L && std::isspace((unsigned char)line[L-1])) line[--L] = '\0';

    // 3) skip leading whitespace
    char* p = line;
    while (*p && std::isspace((unsigned char)*p)) ++p;

    // 4) empty after trimming => skip
    if (*p == '\0') continue;

    // 5) now p should be the hex pubkey token; measure its length to first space (if any)
    char* ws = p;
    while (*ws && !std::isspace((unsigned char)*ws)) ++ws;
    *ws = '\0';
    L = std::strlen(p);

    // 6) accept only 66 (compressed 02/03) or 130 (uncompressed 04) hex chars
    if (!(L == 66 || L == 130)) continue;

    auto ishex = [](char c)->bool {
      return (c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F');
    };
    bool allhex = true; for (size_t i=0;i<L;i++) if (!ishex(p[i])) { allhex=false; break; }
    if (!allhex) continue;

    auto hexv = [](char c)->uint8_t {
      if (c>='0'&&c<='9') return (uint8_t)(c-'0');
      if (c>='a'&&c<='f') return (uint8_t)(c-'a'+10);
      return (uint8_t)(c-'A'+10);
    };

    if (L == 66) {
      // compressed must start with 02 or 03
      if (!(p[0]=='0' && (p[1]=='2'||p[1]=='3')) &&
          !(p[0]=='2' || p[0]=='3')) continue;

      uint8_t out[33];
      for (size_t i=0;i<66;i+=2)
        out[i/2] = (uint8_t)((hexv(p[i])<<4)|hexv(p[i+1]));
      out33.insert(out33.end(), out, out+33);
    } else {
      // uncompressed must start with 04
      if (!((p[0]=='0'&&p[1]=='4') || p[0]=='4')) continue;

      uint8_t tmp[65];
      for (size_t i=0;i<130;i+=2)
        tmp[i/2] = (uint8_t)((hexv(p[i])<<4)|hexv(p[i+1]));

      // compress: 02/03 || X[32]
      uint8_t out[33];
      out[0] = (tmp[64] & 1) ? 0x03 : 0x02;  // parity(Y)
      std::memcpy(out+1, &tmp[1], 32);       // copy X
      out33.insert(out33.end(), out, out+33);
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

// Multithreaded baby-table build:
// Split [0..m) into T chunks. Each thread t:
//   j0 = t * chunk; P0 = j0*G (scalar mult once), then fill chunk via NextKey.
// Prints periodic progress so it doesn't look "hung".
static void build_baby_table_mt(Point* B, uint64_t m, int threads) {
  if (m == 0) return;
  if (threads < 1) threads = 1;

  // Progress
  std::atomic<uint64_t> done{0};
  const uint64_t report_every = (m >= (1u<<26)) ? (1u<<22) : (1u<<20); // every ~4M or 1M

  auto worker = [&](uint64_t j0, uint64_t len){
    Secp256K1 secp_local; secp_local.Init();

    // P0 = j0 * G
    Int j0Int((uint64_t)j0);
    Point P0 = secp_local.ScalarMultiplication(secp_local.G, &j0Int);

    // fill B[j] = P0; P0 += G
    for (uint64_t k=0; k<len; ++k) {
      B[j0+k] = P0;
      P0  = secp_local.NextKey(P0);
      uint64_t d = ++done;
      if ((d % report_every) == 0) {
        double pct = (100.0 * d) / (double)m;
        fprintf(stderr, "[bsgs-mt] baby build: %.1f%% (%llu/%llu)\r",
                pct, (unsigned long long)d, (unsigned long long)m);
        fflush(stderr);
      }
    }
  };

  // Partition
  uint64_t chunk = (m + (uint64_t)threads - 1) / (uint64_t)threads;
  if (chunk == 0) chunk = m;

  // Launch
  std::vector<std::thread> th;
  th.reserve(threads);
  for (int t=0; t<threads; ++t) {
    uint64_t j0 = (uint64_t)t * chunk;
    if (j0 >= m) break;
    uint64_t len = std::min<uint64_t>(chunk, m - j0);
    th.emplace_back(worker, j0, len);
  }
  for (auto& x : th) x.join();

  fprintf(stderr, "\n[bsgs-mt] baby build: 100%% (%llu/%llu)\n",
          (unsigned long long)m, (unsigned long long)m);
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

// Big-range worker: i_begin is full-precision (Int), we iterate "count" times.
// base = (i_begin)*M, then for each step: check block of baby[j], base += M.
static void worker_bsgs_big(const NodeResources& R,
                            const Int& i_begin,
                            uint64_t count,
                            int block,
                            Secp256K1& secp) {
  const uint64_t m = R.m;

  // Precompute stride M = m*G once here (cheap compared to the loop).
  Int mInt((uint64_t)m);
  Point M = secp.ScalarMultiplication(secp.G, &mInt);

  // base = i_begin * M
  Point base = secp.ScalarMultiplication(M, const_cast<Int*>(&i_begin));

  std::vector<uint8_t> buf(33);
  for (uint64_t step = 0; step < count; ++step) {
    uint64_t j = 0;
    while (j < m) {
      int n = (int)std::min<uint64_t>(block, m - j);

      for (int t=0; t<n; ++t) {
        Point P = secp.Add(base, R.baby[j+t]);

        // serialize compressed
        serialize_pub33(P, buf.data(), secp);

        // membership
        bool ok = true;
        if (R.pre.idx[0].len) ok = R.pre.maybe(buf.data());
        if (!ok) continue;
        if (R.use_bloom && !bloom2_maybe(R.bloom, buf.data())) continue;
        if (R.use_exact && !R.exact.contains(buf.data())) continue;

        // Optional: low 64-bit report remains illustrative only.
        printf("HIT: (big) pub[0]=%02x\n", buf[0]);
        fflush(stdout);
      }
      j += n;
    }

    // Next giant step
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
  fprintf(stderr, "[bsgs-mt] loaded %zu targets (compressed 33B)\n", targets33.size()/33);

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

  // --- Build per-node resources (replicate baby & sets) ---
  std::vector<NodeResources> res(nodes.size());
  size_t bytes_all = opt.baby_size * sizeof(Point);
  fprintf(stderr, "[bsgs-mt] sizeof(Point)=%zu, baby m=%llu, per-node bytes=%.2f GiB\n",
          sizeof(Point), (unsigned long long)opt.baby_size, bytes_all / (1024.0*1024.0*1024.0));

  Point* first_baby = nullptr;
  for(size_t ni=0; ni<nodes.size(); ++ni){
    numa_set_thread_mem_policy_portable(ncfg, topo, nodes[ni].node);
    res[ni].node = nodes[ni].node; res[ni].m = opt.baby_size;

    res[ni].baby = (Point*)numa_alloc_portable(bytes_all, ncfg, topo, nodes[ni].node);
    res[ni].baby_bytes = bytes_all;

    if (ni == 0) {
      int build_threads = std::max(1, (opt.threads>0 ? opt.threads : cpu_count()) / (int)nodes.size());
      fprintf(stderr, "[bsgs-mt] building baby table on node %d with %d threads...\n",
              nodes[ni].node, build_threads);
      build_baby_table_mt(res[ni].baby, opt.baby_size, build_threads);
      first_baby = res[ni].baby;
    } else {
      fprintf(stderr, "[bsgs-mt] replicating baby table to node %d (%.2f GiB memcpy)...\n",
              nodes[ni].node, bytes_all / (1024.0*1024.0*1024.0));
      std::memcpy(res[ni].baby, first_baby, bytes_all);
    }

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

  // --- Decide scheduling path: 64-bit fast path vs. big-range chunking ---
  uint64_t i0_64, i1_64;
  bool q0_fit = int_to_u64_exact(q0, i0_64);
  bool q1_fit = int_to_u64_exact(q1, i1_64);

  int total_threads = (opt.threads > 0) ? opt.threads : cpu_count();

  if (q0_fit && q1_fit && i1_64 >= i0_64) {
    // ===== Fast path: whole span fits in uint64_t =====
    fprintf(stderr, "[bsgs-mt] starting giant steps (u64): i in [%llu, %llu), block=%d, threads=%d\n",
            (unsigned long long)i0_64, (unsigned long long)i1_64 + 1ULL, opt.block_size, total_threads);

    std::vector<std::thread> pool;
    for(size_t ni=0; ni<nodes.size(); ++ni){
      const auto& R = res[ni];
      uint64_t span = (i1_64 - i0_64 + 1ULL); // guaranteed non-zero here

      for (int t=0; t<total_threads; ++t) {
        uint64_t tb = i0_64 + (span * (uint64_t)t)/ (uint64_t)total_threads;
        uint64_t te = i0_64 + (span * (uint64_t)(t+1))/ (uint64_t)total_threads;
        pool.emplace_back([&, ni, tb, te]{
          pin_thread_to_node_cpu(nodes[ni], t);
          WorkerJob job; job.R=&R; job.i_begin=tb; job.i_end=te; job.block=opt.block_size; job.secp=&secp;
          worker_bsgs(job);
        });
      }
    }
    for (auto& th: pool) th.join();
  } else {
    // ===== Big path: stream the span in 64-bit CHUNKS =====
    const uint64_t CHUNK = (1ULL<<32);  // ~4 billion giant steps per outer iteration
    Int cur(q0);

    // Compute remaining = q1 - cur + 1 as Int
    auto remaining_Int = [&](Int& out){
      out.Sub(&q1, &cur);     // out = q1 - cur
      out.Add((uint64_t)1);   // out += 1
    };

    while (true) {
      Int rem; remaining_Int(rem);
      // if rem == 0 => done
      if (rem.IsZero()) break;

      // this_chunk = min(rem, CHUNK)
      uint64_t rem64 = u64_lo_from_Int(rem);
      uint64_t this_chunk = rem64 ? std::min<uint64_t>(rem64, CHUNK) : CHUNK;

      fprintf(stderr, "[bsgs-mt] chunk start (big): i = cur, count = %llu\n", 
              (unsigned long long)this_chunk);

      std::vector<std::thread> pool;
      for(size_t ni=0; ni<nodes.size(); ++ni){
        const auto& R = res[ni];
        for (int t=0; t<total_threads; ++t) {
          uint64_t tb = (this_chunk * (uint64_t)t)    / (uint64_t)total_threads;
          uint64_t te = (this_chunk * (uint64_t)(t+1))/ (uint64_t)total_threads;
          uint64_t cnt = (te > tb) ? (te - tb) : 0;
          if (!cnt) continue;

          // i_begin_big = cur + tb
          Int i_begin_big(cur);
          i_begin_big.Add(tb);

          pool.emplace_back([&, ni, i_begin_big, cnt, t]{
            pin_thread_to_node_cpu(nodes[ni], t);
            worker_bsgs_big(res[ni], i_begin_big, cnt, opt.block_size, secp);
          });
        }
      }
      for (auto& th: pool) th.join();

      // advance cur += this_chunk
      cur.Add(this_chunk);
    }
  }

  // Cleanup
  for(auto& R: res){ if (R.baby) numa_free_portable(R.baby, R.baby_bytes); }
  return 0;
}