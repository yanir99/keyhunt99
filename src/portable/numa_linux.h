#pragma once
#include <vector>
#include <string>
#include <cstddef>

enum class NumaPolicy { LOCAL, INTERLEAVE };

struct NumaCpuSet { int node=-1; std::vector<int> cpus; };
struct NumaTopo { bool available=false; int max_node=0; std::vector<NumaCpuSet> groups; };
struct NumaConfig { bool enabled=false; NumaPolicy policy=NumaPolicy::LOCAL; std::vector<int> restrict_nodes; bool hugepages=false; };

NumaTopo numa_discover();
void numa_set_thread_mem_policy(const NumaConfig& cfg, const NumaTopo& topo, int node_index);
void* numa_alloc(size_t bytes, const NumaConfig& cfg, const NumaTopo& topo, int node_index);
void  numa_free(void* p, size_t bytes);
bool  pin_thread_to_cpu(int cpu);
bool  pin_thread_to_node_cpu(const NumaCpuSet& cs, int thread_index);
std::vector<int> parse_nodes_list(const std::string& s);
