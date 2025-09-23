#include "numa_linux.h"
#include <cstdlib>
#include <cstring>
#include <thread>
#ifdef __linux__
  #include <sched.h>
  #include <pthread.h>
  #include <sys/mman.h>
  #include <unistd.h>
  #include <errno.h>
  #ifdef HAVE_LIBNUMA
    #include <numa.h>
    #include <numaif.h>
  #endif
#endif

static bool g_have_numa = false;

std::vector<int> parse_nodes_list(const std::string& s) {
  std::vector<int> out; if (s.empty()) return out;
  size_t i=0; while (i<s.size()) {
    while (i<s.size() && (s[i]==','||s[i]==' ')) ++i;
    size_t j=i; while (j<s.size() && s[j]>='0'&&s[j]<='9') ++j;
    if (j>i) out.push_back(std::atoi(s.substr(i,j-i).c_str()));
    i=j;
  }
  return out;
}

NumaTopo numa_discover() {
  NumaTopo t;
#ifdef __linux__
  #ifdef HAVE_LIBNUMA
    t.available = (numa_available() != -1);
    g_have_numa = t.available;
    if (!t.available) return t;
    int maxn = numa_max_node(); t.max_node = maxn;
    for (int node=0; node<=maxn; ++node) {
      if (!numa_bitmask_isbitset(numa_all_nodes_ptr, node)) continue;
      NumaCpuSet cs; cs.node = node;
      struct bitmask* mask = numa_allocate_cpumask();
      if (numa_node_to_cpus(node, mask) == 0) {
        for (unsigned long cpu = 0; cpu < mask->size; ++cpu) {
          if (numa_bitmask_isbitset(mask, cpu)) cs.cpus.push_back((int)cpu);
        }
      }
      numa_free_cpumask(mask);
      if (!cs.cpus.empty()) t.groups.push_back(std::move(cs));
    }
  #else
    g_have_numa = false;
  #endif
#endif
  return t;
}

static void set_hugepage_advise(void* p, size_t bytes, bool on) {
#ifdef __linux__
  if (!p || !bytes) return;
  #ifdef MADV_HUGEPAGE
  if (on) madvise(p, bytes, MADV_HUGEPAGE);
  #endif
  #ifdef MADV_NOHUGEPAGE
  if (!on) madvise(p, bytes, MADV_NOHUGEPAGE);
  #endif
#endif
}

void numa_set_thread_mem_policy_portable(const NumaConfig& cfg, const NumaTopo& topo, int node_index) {
#ifdef __linux__
  #ifdef HAVE_LIBNUMA
    if (!g_have_numa || !cfg.enabled) return;
    std::vector<unsigned long> nodemask;
    int nbits = topo.max_node + 1;
    int nlongs = (nbits + (int)(8*sizeof(unsigned long)) - 1) / (int)(8*sizeof(unsigned long));
    nodemask.assign(nlongs, 0);
    auto allow_node = [&](int n){
      int idx = n / (int)(8*sizeof(unsigned long));
      int bit = n % (int)(8*sizeof(unsigned long));
      nodemask[idx] |= (1UL << bit);
    };
    if (!cfg.restrict_nodes.empty()) {
      for (int n : cfg.restrict_nodes) {
        if (n >= 0 && n <= topo.max_node) allow_node(n);
      }
    } else {
      for (const auto& g : topo.groups) allow_node(g.node);
    }
    int mode = (cfg.policy == NumaPolicy::INTERLEAVE) ? MPOL_INTERLEAVE : MPOL_PREFERRED;
    if (mode == MPOL_PREFERRED) {
      int chosen = node_index;
      if (chosen < 0 || chosen > topo.max_node)
        chosen = !cfg.restrict_nodes.empty()? cfg.restrict_nodes.front() : topo.groups.front().node;
      for (auto& v: nodemask) v = 0;
      allow_node(chosen);
    }
    set_mempolicy(mode, nodemask.data(), nbits);
  #endif
#else
  (void)cfg; (void)topo; (void)node_index;
#endif
}

void* numa_alloc_portable(size_t bytes, const NumaConfig& cfg, const NumaTopo& topo, int node_index) {
#ifdef __linux__
  #ifdef HAVE_LIBNUMA
    if (g_have_numa && cfg.enabled && cfg.policy == NumaPolicy::LOCAL) {
      int node = node_index;
      if (node < 0 || node > topo.max_node)
        node = !cfg.restrict_nodes.empty()? cfg.restrict_nodes.front() : topo.groups.front().node;
      void* p = numa_alloc_onnode(bytes, node);
      set_hugepage_advise(p, bytes, cfg.hugepages);
      return p;
    }
    if (g_have_numa && cfg.enabled && cfg.policy == NumaPolicy::INTERLEAVE) {
      void* p = numa_alloc_interleaved(bytes);
      set_hugepage_advise(p, bytes, cfg.hugepages);
      return p;
    }
  #endif
#endif
  // portable fallback
  void* p = std::malloc(bytes ? bytes : 1);
#ifdef __linux__
  set_hugepage_advise(p, bytes, cfg.hugepages);
#endif
  return p;
}

void  numa_free_portable(void* p, size_t bytes) {
#ifdef __linux__
  #ifdef HAVE_LIBNUMA
    if (g_have_numa && p) { ::numa_free(p, bytes); return; }
  #endif
#endif
  std::free(p);
}

bool pin_thread_to_cpu(int cpu) {
#ifdef __linux__
  cpu_set_t set; CPU_ZERO(&set); CPU_SET(cpu, &set);
  int rc = pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
  return rc == 0;
#else
  (void)cpu; return true;
#endif
}

bool pin_thread_to_node_cpu(const NumaCpuSet& cs, int thread_index) {
  if (cs.cpus.empty()) return true;
  int cpu = cs.cpus[thread_index % (int)cs.cpus.size()];
  return pin_thread_to_cpu(cpu);
}
