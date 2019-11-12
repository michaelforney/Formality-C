#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fm-net.h"
#include "nodes.h"

int main(void) {
  Net net;
  net.nodes = malloc(sizeof(uint64_t) * 200000000);
  net.redex = malloc(sizeof(uint64_t) * 10000000);
  net.freed = 0;

  net.nodes_len = 0;
  net.redex_len = 0;

  memcpy(net.nodes, nodes, sizeof(nodes));
  net.nodes_len = sizeof(nodes) / sizeof(nodes[0]);

  net_find_redexes(&net);
  Stats stats = net_reduce_strict(&net);

  // Must output 51325139
  printf("rewrites: %d\n", stats.rewrites);
  printf("loops: %d\n", stats.loops);
}
