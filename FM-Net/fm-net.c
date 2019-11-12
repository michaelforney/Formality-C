#include <assert.h>
#include <math.h>
#include <stdint.h>

#include "fm-net.h"

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

static uint64_t alloc_node(Net *net) {
  uint64_t addr;
  if (net->freed) {
    addr = net->freed - 1;
    net->freed = net->nodes[addr];
  } else {
    addr = net->nodes_len;
    net->nodes_len += 4;
  }
  return addr;
}

static void free_node(Net *net, uint64_t addr) {
  net->nodes[addr] = net->freed;
  net->freed = addr + 1;
}

static void queue(Net *net, uint64_t addr) {
  net->redex[net->redex_len++] = addr;
  assert(addr % 4 == 0);
}

static uint64_t powi(uint64_t fst, uint64_t snd) {
  uint64_t res;

  for (res = 1; snd; snd >>= 1, fst *= fst) {
    if (snd & 1)
      res *= fst;
  }
  return res;
}

static void rewrite(Net *net, uint64_t a_addr) {
  uint64_t *nodes = net->nodes;
  union {
    uint64_t i;
    double f;
  } res, fst, snd;
  uint64_t b_addr, c_addr, d_addr;
  uint64_t *a, *b, *c, *d;
  int a_info, a_kind, b_info, b_kind;

  a = &nodes[a_addr];
  a_info = a[3];
  a_kind = a_info >> 6 & 3;

  switch (a_info & 3) {
  case NUM:
    fst.i = a[0];
    switch (a_kind) {
    case OP1:
      snd.i = a[1];
      switch (a[3] >> 8) {
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
      case FMOD: res.f = fmod(fst.f, snd.f); break;
      case FPOW: res.f = pow(fst.f, snd.f); break;
      case ITOF: res.f = snd.i; break;
      case FTOI: res.i = snd.f; break;
      /* unreachable */
      default: res.i = 0; break;
      }
      if ((a[3] >> 4 & 3) == PTR) {
        nodes[a[2]] = res.i;
        nodes[a[2] | 3] |= NUM << (a[2] & 3) * 2;
        if ((a[2] & 3) == 0)
          queue(net, a[2]);
      }
      free_node(net, a_addr);
      break;
    case OP2:
      a[0] = a[1];
      a[1] = fst.i;
      a[3] = OP1 << 6 | NUM << 2 | (a[3] >> 2 & 3) |
             (a[3] & ~(3 << 6 | 3 << 0 | 3 << 2));
      if ((a[3] & 3) == PTR)
        nodes[a[0]] = a_addr;
      if ((a[3] & 3) != PTR || (a[0] & 3) == 0)
        queue(net, a_addr);
      break;
    case NOD:
      if ((a[3] >> 2 & 3) == PTR) {
        nodes[a[1]] = fst.i;
        nodes[a[1] | 3] |= NUM << (a[1] & 3) * 2;
        if ((a[1] & 3) == 0)
          queue(net, a[1]);
      }
      if ((a[3] >> 4 & 3) == PTR) {
        nodes[a[2]] = fst.i;
        nodes[a[2] | 3] |= NUM << (a[2] & 3) * 2;
        if ((a[2] & 3) == 0)
          queue(net, a[2]);
      }
      free_node(net, a_addr);
      break;
    case ITE:
      assert((a[3] >> 2 & 3) == PTR);
      a[0] = a[1];
      a[3] = NOD << 6 | (a[3] >> 2 & 3) | (a[3] & ~0xff);
      nodes[a[0]] &= ~3;
      if (fst.i) {
        a[1] = a[2];
        a[3] |= (a_info >> 2 & 3 << 2) | ERA << 4;
        nodes[a[1]] ^= 3;
      } else {
        a[3] |= (a_info & 3 << 4) | ERA << 2;
      }
      if ((a[0] & 3) == 0)
        queue(net, a_addr);
      break;
    }
    break;
  case PTR:
    b_addr = a[0];
    assert(a_addr != b_addr);
    b = &nodes[b_addr];
    b_info = b[3];
    b_kind = b_info >> 6 & 3;
    if (a_kind == b_kind && (a_kind != NOD || a[3] >> 8 == b[3] >> 8)) {
      /* annihilation */
      if ((a[3] >> 2 & 3) == PTR) {
        nodes[a[1]] = b[1];
        nodes[a[1] | 3] |= (b[3] >> 2 & 3) << (a[1] & 3) * 2;
        if ((a[1] & 3) == 0 && ((b[3] >> 2 & 3) != PTR || (b[1] & 3) == 0))
          queue(net, a[1]);
      }
      if ((b[3] >> 2 & 3) == PTR) {
        nodes[b[1]] = a[1];
        nodes[b[1] | 3] |= (a[3] >> 2 & 3) << (b[1] & 3) * 2;
        if ((b[1] & 3) == 0 && (a[3] >> 2 & 3) != PTR)
          queue(net, b[1]);
      }
      if ((a[3] >> 4 & 3) == PTR) {
        nodes[a[2]] = b[2];
        nodes[a[2] | 3] |= (b[3] >> 4 & 3) << (a[2] & 3) * 2;
        if ((a[2] & 3) == 0 && ((b[3] >> 4 & 3) != PTR || (b[2] & 3) == 0))
          queue(net, a[2]);
      }
      if ((b[3] >> 4 & 3) == PTR) {
        nodes[b[2]] = a[2];
        nodes[b[2] | 3] |= (a[3] >> 4 & 3) << (b[2] & 3) * 2;
        if ((b[2] & 3) == 0 && (a[3] >> 4 & 3) != PTR)
          queue(net, b[2]);
      }
      free_node(net, a_addr);
      free_node(net, b_addr);
    } else if (a_kind == NOD && b_kind != OP1) {
      /* nodes/binary duplication */
      c_addr = alloc_node(net);
      d_addr = alloc_node(net);
      c = &nodes[c_addr];
      d = &nodes[d_addr];
      a[0] = b[1];
      a[3] = (a_info & ~0x3f) | (b_info >> 2 & 3);
      if ((a[3] & 3) == PTR)
        nodes[a[0]] = a_addr;
      if ((a[3] & 3) != PTR || (a[0] & 3) == 0)
        queue(net, a_addr);
      b[0] = a[2];
      b[3] = (b_info & ~0x3f) | (a_info >> 4 & 3);
      if ((b[3] & 3) == PTR)
        nodes[b[0]] = b_addr;
      if ((b[3] & 3) != PTR || (b[0] & 3) == 0)
        queue(net, b_addr);
      c[0] = b[2];
      c[3] = (a_info & ~0x3f) | (b_info >> 4 & 3);
      if ((c[3] & 3) == PTR)
        nodes[c[0]] = c_addr;
      if ((c[3] & 3) != PTR || (c[0] & 3) == 0)
        queue(net, c_addr);
      d[0] = a[1];
      d[3] = (b_info & ~0x3f) | (a_info >> 2 & 3);
      if ((d[3] & 3) == PTR)
        nodes[d[0]] = d_addr;
      if ((d[3] & 3) != PTR || (d[0] & 3) == 0)
        queue(net, d_addr);
      a[1] = d_addr | 1;
      b[1] = a_addr | 2;
      c[1] = d_addr | 2;
      d[1] = a_addr | 1;
      a[2] = b_addr | 1;
      b[2] = c_addr | 2;
      c[2] = b_addr | 2;
      d[2] = c_addr | 1;
    } else if (a_kind != OP2 && b_kind == OP1) {
      /* unary duplication */
      c_addr = alloc_node(net);
      c = &nodes[c_addr];
      a[0] = b[2];
      a[3] = (a_info & ~0x3f) | (b_info >> 4 & 3);
      if ((a[3] & 3) == PTR)
        nodes[a[0]] = a_addr;
      if ((a[3] & 3) != PTR || (a[0] & 3) == 0)
        queue(net, a_addr);
      b[0] = a[1];
      b[3] = (b_info & ~0x33) | (a_info >> 2 & 3);
      if ((b[3] & 3) == PTR)
        nodes[b[0]] = b_addr;
      if ((b[3] & 3) != PTR || (b[0] & 3) == 0)
        queue(net, b_addr);
      c[0] = a[2];
      c[3] = (b_info & ~0x33) | (a_info >> 4 & 3);
      if ((c[3] & 3) == PTR)
        nodes[c[0]] = c_addr;
      if ((c[3] & 3) != PTR || (c[0] & 3) == 0)
        queue(net, c_addr);
      a[1] = b_addr | 2;
      /* b[1] already set */
      c[1] = b[1];
      a[2] = c_addr | 2;
      b[2] = a_addr | 1;
      c[2] = a_addr | 2;
    } else if (b_kind == NOD) {
      /* permutations */
      rewrite(net, b_addr);
    }
    break;
  case ERA:
    if ((a[3] >> 2 & 3) == PTR) {
      nodes[a[1] | 3] |= ERA << (a[1] & 3) * 2;
      if ((a[1] & 3) == 0)
        queue(net, a[1]);
    }
    if ((a[3] >> 4 & 3) == PTR) {
      nodes[a[2] | 3] |= ERA << (a[2] & 3) * 2;
      if ((a[2] & 3) == 0)
        queue(net, a[2]);
    }
    free_node(net, a_addr);
    break;
  }
}

// Rewrites active pairs until none is left, reducing the graph to normal form
// This could be performed in parallel. Unreachable data is freed automatically.
Stats net_reduce_strict(Net *net) {
  Stats stats;
  stats.rewrites = 0;
  stats.loops = 0;
  while (net->redex_len > 0) {
    for (size_t i = 0, l = net->redex_len; i < l; ++i) {
      rewrite(net, net->redex[--net->redex_len]);
      ++stats.rewrites;
    }
    ++stats.loops;
  }
  return stats;
}

void net_find_redexes(Net *net) {
  size_t i;

  for (i = 0; i < net->nodes_len; i += 4) {
    if (net->nodes[i | 3] & 1 ||
        ((net->nodes[i] & 3) == 0 && net->nodes[i] >= i))
      queue(net, i);
  }
}
