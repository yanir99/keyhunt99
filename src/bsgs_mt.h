#pragma once
#include <string>

struct BsgsMtOptions {
  std::string targets_path;
  std::string range_hex;
  std::string range_start_hex;
  std::string range_end_hex;
  unsigned long long baby_size; // m
  int   block_size;
  int   threads;
  std::string filter_kind;      // "tag+exact" or "bloom"
  double bloom_fpp;
  std::string numa_mode;        // "auto" | "off" | "nodes=0,1"
  std::string numa_policy;      // "local" | "interleave"
  bool hugepages;
};

int run_bsgs_mt(const BsgsMtOptions& opt);
