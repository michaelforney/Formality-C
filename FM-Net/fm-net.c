#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "nodes.h"

enum {
  PTR,
  NUM,
  ERA,
};

enum {
  NOD,
  OP1,
  OP2,
  ITE,
};

enum {
  ADD,
  SUB,
  MUL,
  DIV,
  MOD,
  POW,
  AND,
  BOR,
  XOR,
  NOT,
  SHR,
  SHL,
  GTR,
  LES,
  EQL,
  FADD,
  FSUB,
  FMUL,
  FDIV,
  FMOD,
  FPOW,
  ITOF,
  FTOI,
};

static uint64_t Pointer(uint32_t addr, uint32_t port) {
  return (uint64_t)((addr << 2) + (port & 3));
}

static uint32_t addr_of(uint64_t ptrn) {
  return (uint32_t)(ptrn >> 2);
}

static uint32_t slot_of(uint64_t ptrn) {
  return (uint32_t)(ptrn & 3);
}

static uint64_t Numeric(uint32_t numb) {
  return numb | (uint64_t)NUM << 32;
}

static uint64_t Erase(void) {
  return (uint64_t)ERA << 32;
}

static uint32_t numb_of(uint64_t ptrn) {
  return (uint32_t)ptrn;
}

static uint32_t type_of(uint64_t ptrn) {
  return ptrn >> 32;
}

typedef struct Node {
  uint32_t port[3];
  uint32_t info;
} Node;

typedef struct Net {
  uint32_t *nodes;
  uint32_t nodes_len;
  uint32_t *redex;
  uint32_t redex_len;
  uint32_t *freed;
  uint32_t freed_len;
} Net;

typedef struct Stats {
  uint32_t rewrites;
  uint32_t loops;
} Stats;

static uint32_t alloc_node(Net *net, uint32_t type, uint32_t kind) {
  uint32_t addr;
  if (net->freed_len > 0) {
    addr = net->freed[--net->freed_len];
  } else {
    addr = net->nodes_len / 4;
    net->nodes_len += 4;
  }
  net->nodes[addr * 4 + 3] = (kind << 8) + ((type & 0x3) << 6);
  return addr;
}

static void free_node(Net *net, uint32_t addr) {
  net->nodes[addr * 4 + 0] = addr * 4 + 0;
  net->nodes[addr * 4 + 1] = addr * 4 + 1;
  net->nodes[addr * 4 + 2] = addr * 4 + 2;
  net->nodes[addr * 4 + 3] = 0;
  net->freed[net->freed_len++] = addr;
}

static uint32_t is_free(Net *net, uint32_t addr) {
  return net->nodes[addr * 4 + 0] == addr * 4 + 0 &&
         net->nodes[addr * 4 + 1] == addr * 4 + 1 &&
         net->nodes[addr * 4 + 2] == addr * 4 + 2 &&
         net->nodes[addr * 4 + 3] == 0;
}

static uint32_t port_type(Net *net, uint32_t addr, uint32_t slot) {
  return (net->nodes[addr * 4 + 3] >> slot * 2) & 3;
}

static void set_port(Net *net, uint32_t addr, uint32_t slot, uint64_t ptrn) {
  net->nodes[addr * 4 + slot] = ptrn;
  net->nodes[addr * 4 + 3] =
      (net->nodes[addr * 4 + 3] & ~(3 << slot * 2)) | type_of(ptrn) << slot * 2;
}

static uint64_t get_port(Net *net, uint32_t addr, uint32_t slot) {
  return net->nodes[addr * 4 + slot] | (uint64_t)port_type(net, addr, slot)
                                           << 32;
}

static void set_type(Net *net, uint32_t addr, uint32_t type) {
  net->nodes[addr * 4 + 3] =
      (net->nodes[addr * 4 + 3] & ~(3 << 6)) | (type << 6);
}

static uint32_t get_type(Net *net, uint32_t addr) {
  return (net->nodes[addr * 4 + 3] >> 6) & 0x3;
}

static uint32_t get_kind(Net *net, uint32_t addr) {
  return net->nodes[addr * 4 + 3] >> 8;
}

// Given a pointer to a port, returns a pointer to the opposing port
static uint64_t enter_port(Net *net, uint64_t ptrn) {
  if (type_of(ptrn) != PTR) {
    printf("[ERROR]\nCan't enter a numeric/erase pointer.");
    return 0;
  } else {
    return get_port(net, addr_of(ptrn), slot_of(ptrn));
  }
}

static uint32_t is_redex(Net *net, uint32_t addr) {
  uint64_t a_ptrn = Pointer(addr, 0);
  uint64_t b_ptrn = enter_port(net, a_ptrn);
  return type_of(b_ptrn) == NUM ||
         (slot_of(b_ptrn) == 0 && !is_free(net, addr));
}

// Connects two ports
static void link_ports(Net *net, uint64_t a_ptrn, uint64_t b_ptrn) {
  uint32_t a_type = type_of(a_ptrn);
  uint32_t b_type = type_of(b_ptrn);

  // Point ports to each-other
  if (a_type == PTR)
    set_port(net, addr_of(a_ptrn), slot_of(a_ptrn), b_ptrn);
  if (b_type == PTR)
    set_port(net, addr_of(b_ptrn), slot_of(b_ptrn), a_ptrn);

  // If both are main ports, add this to the list of active pairs
  if (a_type == PTR && slot_of(a_ptrn) == 0 &&
      (b_type != PTR || slot_of(b_ptrn) == 0))
    net->redex[net->redex_len++] = addr_of(a_ptrn);
  else if (b_type == PTR && slot_of(b_ptrn) == 0 && a_type != PTR)
    net->redex[net->redex_len++] = addr_of(b_ptrn);
}

static uint32_t powi(uint32_t fst, uint32_t snd) {
  uint32_t res;

  for (res = 1; snd; snd >>= 1, fst *= fst) {
    if (snd & 1)
      res *= fst;
  }
  return res;
}

// Rewrites an active pair
static void rewrite(Net *net, uint32_t a_addr) {
  uint64_t b_ptrn = get_port(net, a_addr, 0);
  uint32_t a_type = get_type(net, a_addr);
  uint32_t a_kind = get_kind(net, a_addr);
  uint32_t b_addr, b_type, b_kind;

  switch (type_of(b_ptrn)) {
  case NUM:
    // UnaryOperation
    if (a_type == OP1) {
      union {
        uint32_t i;
        float f;
      } fst, snd, res;
      uint64_t dst;

      dst = enter_port(net, Pointer(a_addr, 2));
      fst.i = numb_of(b_ptrn);
      snd.i = numb_of(enter_port(net, Pointer(a_addr, 1)));
      switch (a_kind) {
      case ADD: res.i = fst.i + snd.i; break;
      case SUB: res.i = fst.i - snd.i; break;
      case MUL: res.i = fst.i * snd.i; break;
      case DIV: res.i = fst.i / snd.i; break;
      case MOD: res.i = fst.i % snd.i; break;
      case POW: res.i = powi(fst.i, snd.i); break;
      case AND: res.i = fst.i & snd.i; break;
      case BOR: res.i = fst.i | snd.i; break;
      case XOR: res.i = fst.i ^ snd.i; break;
      case NOT: res.i = ~snd.i; break;
      case SHR: res.i = fst.i >> snd.i; break;
      case SHL: res.i = fst.i << snd.i; break;
      case GTR: res.i = fst.i > snd.i; break;
      case LES: res.i = fst.i < snd.i; break;
      case EQL: res.i = fst.i == snd.i; break;
      case FADD: res.f = fst.f + snd.f; break;
      case FSUB: res.f = fst.f - snd.f; break;
      case FMUL: res.f = fst.f * snd.f; break;
      case FDIV: res.f = fst.f / snd.f; break;
      case FMOD: res.f = fmodf(fst.f, snd.f); break;
      case FPOW: res.f = powf(fst.f, snd.f); break;
      case ITOF: res.f = snd.i; break;
      case FTOI: res.i = snd.f; break;
      default:
        res.i = 0;
        printf("[ERROR]\nInvalid interaction.");
        break;
      }
      link_ports(net, dst, Numeric(res.i));
      free_node(net, a_addr);

      // BinaryOperation
    } else if (a_type == OP2) {
      set_type(net, a_addr, OP1);
      link_ports(net, Pointer(a_addr, 0), enter_port(net, Pointer(a_addr, 1)));
      link_ports(net, Pointer(a_addr, 1), b_ptrn);

      // NumberDuplication
    } else if (a_type == NOD) {
      link_ports(net, b_ptrn, enter_port(net, Pointer(a_addr, 1)));
      link_ports(net, b_ptrn, enter_port(net, Pointer(a_addr, 2)));
      free_node(net, a_addr);

      // IfThenElse
    } else if (a_type == ITE) {
      uint32_t cond_val = numb_of(b_ptrn) == 0;
      uint64_t pair_ptr = enter_port(net, Pointer(a_addr, 1));
      set_type(net, a_addr, NOD);
      link_ports(net, Pointer(a_addr, 0), pair_ptr);
      uint64_t dest_ptr = enter_port(net, Pointer(a_addr, 2));
      link_ports(net, Pointer(a_addr, cond_val ? 2 : 1), dest_ptr);
      link_ports(net, Pointer(a_addr, cond_val ? 1 : 2), Erase());

    } else {
      printf("[ERROR]\nInvalid interaction.");
    }
    break;
  case ERA:
    link_ports(net, enter_port(net, Pointer(a_addr, 1)), Erase());
    link_ports(net, enter_port(net, Pointer(a_addr, 2)), Erase());
    break;
  case PTR:
    b_addr = addr_of(b_ptrn);
    b_type = get_type(net, b_addr);
    b_kind = get_kind(net, b_addr);

    // NodeAnnihilation, UnaryAnnihilation, BinaryAnnihilation
    if ((a_type == NOD && b_type == NOD && a_kind == b_kind) ||
        (a_type == OP1 && b_type == OP1) || (a_type == OP2 && b_type == OP2) ||
        (a_type == ITE && b_type == ITE)) {
      uint64_t a_aux1_dest = enter_port(net, Pointer(a_addr, 1));
      uint64_t b_aux1_dest = enter_port(net, Pointer(b_addr, 1));
      link_ports(net, a_aux1_dest, b_aux1_dest);
      uint64_t a_aux2_dest = enter_port(net, Pointer(a_addr, 2));
      uint64_t b_aux2_dest = enter_port(net, Pointer(b_addr, 2));
      link_ports(net, a_aux2_dest, b_aux2_dest);
      free_node(net, a_addr);
      if (a_addr != b_addr) {
        free_node(net, b_addr);
      }

      // NodeDuplication, BinaryDuplication
    } else if ((a_type == NOD && b_type == NOD && a_kind != b_kind) ||
               (a_type == NOD && b_type == OP2) ||
               (a_type == NOD && b_type == ITE)) {
      uint32_t p_addr = alloc_node(net, b_type, b_kind);
      uint32_t q_addr = alloc_node(net, b_type, b_kind);
      uint32_t r_addr = alloc_node(net, a_type, a_kind);
      uint32_t s_addr = alloc_node(net, a_type, a_kind);
      link_ports(net, Pointer(r_addr, 1), Pointer(p_addr, 1));
      link_ports(net, Pointer(s_addr, 1), Pointer(p_addr, 2));
      link_ports(net, Pointer(r_addr, 2), Pointer(q_addr, 1));
      link_ports(net, Pointer(s_addr, 2), Pointer(q_addr, 2));
      link_ports(net, Pointer(p_addr, 0), enter_port(net, Pointer(a_addr, 1)));
      link_ports(net, Pointer(q_addr, 0), enter_port(net, Pointer(a_addr, 2)));
      link_ports(net, Pointer(r_addr, 0), enter_port(net, Pointer(b_addr, 1)));
      link_ports(net, Pointer(s_addr, 0), enter_port(net, Pointer(b_addr, 2)));
      free_node(net, a_addr);
      if (a_addr != b_addr) {
        free_node(net, b_addr);
      }

      // UnaryDuplication
    } else if ((a_type == NOD && b_type == OP1) ||
               (a_type == ITE && b_type == OP1)) {
      uint32_t p_addr = alloc_node(net, b_type, b_kind);
      uint32_t q_addr = alloc_node(net, b_type, b_kind);
      uint32_t s_addr = alloc_node(net, a_type, a_kind);
      link_ports(net, Pointer(p_addr, 1), enter_port(net, Pointer(b_addr, 1)));
      link_ports(net, Pointer(q_addr, 1), enter_port(net, Pointer(b_addr, 1)));
      link_ports(net, Pointer(s_addr, 1), Pointer(p_addr, 2));
      link_ports(net, Pointer(s_addr, 2), Pointer(q_addr, 2));
      link_ports(net, Pointer(p_addr, 0), enter_port(net, Pointer(a_addr, 1)));
      link_ports(net, Pointer(q_addr, 0), enter_port(net, Pointer(a_addr, 2)));
      link_ports(net, Pointer(s_addr, 0), enter_port(net, Pointer(b_addr, 2)));
      free_node(net, a_addr);
      if (a_addr != b_addr) {
        free_node(net, b_addr);
      }

      // Permutations
    } else if (a_type == OP1 && b_type == NOD) {
      rewrite(net, b_addr);
    } else if (a_type == OP2 && b_type == NOD) {
      rewrite(net, b_addr);
    } else if (a_type == ITE && b_type == NOD) {
      rewrite(net, b_addr);

      // InvalidInteraction
    } else {
      printf("[ERROR]\nInvalid interaction.");
    }
    break;
  }
}

// Rewrites active pairs until none is left, reducing the graph to normal form
// This could be performed in parallel. Unreachable data is freed automatically.
static Stats reduce(Net *net) {
  Stats stats;
  stats.rewrites = 0;
  stats.loops = 0;
  while (net->redex_len > 0) {
    for (uint32_t i = 0, l = net->redex_len; i < l; ++i) {
      rewrite(net, net->redex[--net->redex_len]);
      ++stats.rewrites;
    }
    ++stats.loops;
  }
  return stats;
}

static void find_redexes(Net *net) {
  net->redex_len = 0;
  for (uint32_t i = 0; i < net->nodes_len / 4; ++i) {
    uint64_t b_ptrn = enter_port(net, Pointer(i, 0));
    if ((type_of(b_ptrn) == NUM || addr_of(b_ptrn) >= i) && is_redex(net, i)) {
      net->redex[net->redex_len++] = i;
    }
  }
}

static void print_pointer(uint64_t ptrn) {
  switch (type_of(ptrn)) {
  case NUM: printf("#%u", numb_of(ptrn)); break;
  case ERA: printf("-"); break;
  case PTR:
    printf("%u", addr_of(ptrn));
    switch (slot_of(ptrn)) {
    case 0: printf("a"); break;
    case 1: printf("b"); break;
    case 2: printf("c"); break;
    }
    break;
  }
}

static void print_net(Net *net) {
  for (uint32_t i = 0; i < net->nodes_len / 4; i++) {
    if (is_free(net, i)) {
      printf("%u: ~\n", i);
    } else {
      uint32_t type = get_type(net, i);
      uint32_t kind = get_kind(net, i);
      printf("%u: ", i);
      printf("[%u:%u| ", type, kind);
      print_pointer(get_port(net, i, 0));
      printf(" ");
      print_pointer(get_port(net, i, 1));
      printf(" ");
      print_pointer(get_port(net, i, 2));
      printf("]");
      printf("...");
      printf("%d ", port_type(net, i, 0));
      printf("%d ", port_type(net, i, 1));
      printf("%d ", port_type(net, i, 2));
      printf("\n");
    }
  }
}

int main(void) {
  Net net;
  net.nodes = malloc(sizeof(uint32_t) * 200000000);
  net.redex = malloc(sizeof(uint32_t) * 10000000);
  net.freed = malloc(sizeof(uint32_t) * 10000000);

  net.nodes_len = 0;
  net.redex_len = 0;
  net.freed_len = 0;

  for (uint32_t i = 0; i < sizeof(nodes) / sizeof(uint32_t); ++i) {
    net.nodes[i] = nodes[i];
    net.nodes_len += 1;
  }

  find_redexes(&net);
  Stats stats = reduce(&net);

  // Must output 51325139
  printf("rewrites: %d\n", stats.rewrites);
  printf("loops: %d\n", stats.loops);
}
