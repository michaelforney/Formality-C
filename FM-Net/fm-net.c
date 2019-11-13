#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <limits.h>

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
  EQ,      // equality
  NE,      // not-equal
  LT_S,    // signed less-than
  LT_U,    // unsigned less-than
  GT_S,    // signed greater-than
  GT_U,    // unsigned greater-than
  LE_S,    // signed less-than-or-equal
  LE_U,    // unsigned less-than-or-equal
  GE_S,    // signed greater-than-or-equal
  GE_U,    // unsigned greater-than-or-equal
  CLZ,     // count leading zeros, unary
  CTZ,     // count trailing zeros, unary
  POPCNT,  // count number of 1 bits, unary
  SHL,     // shift left
  SHR,     // unsigned shift right
  SHR_S,   // signed shift right
  ROTL,    // rotate left
  ROTR,    // rotate right
  AND,     // bitwise and
  OR,      // bitwise or
  XOR,     // bitwise xor
  ADD,     // addition
  SUB,     // subtraction
  MUL,     // multiplication
  DIV_S,   // signed division
  DIV_U,   // unsigned division
  REM_S,   // signed remainder
  REM_U,   // unsigned remainder
  FABS,    // absolute value, unary
  FNEG,    // negation, unary
  FCEIL,   // round upward, unary
  FFLOOR,  // round downward, unary
  FTRUNC,  // truncate, unary
  FNRST,   // round to nearest, unary
  FSQRT,   // square-root, unary
  FADD,    // addition
  FSUB,    // subtraction
  FMUL,    // multiplication
  FDIV,    // division
  FMIN,    // minimum
  FMAX,    // maximum
  FCPYSGN, // copy sign value of first arg and sign of second arg
  FEQ,     // equality
  FNE,     // not-equal
  FLT,     // less-than
  FGT,     // greater-than
  FLE,     // less-than-or-equal
  FGE,     // greater-than-or-equal
  EXT32_S, // signed extension of 32 bit numbers to 64 bit
  FTOS,    // f64 to signed i64
  FTOU,    // f64 to unsigned i64
  STOF,    // signed i64 to f64
  UTOF     // UNSIGNED I64 TO F64
};

uint64_t rotl(uint64_t a, uint64_t b) {
  const uint64_t mask = CHAR_BIT*sizeof(b) - 1;
  b &= mask;
  return (a << b) | (a >> ((-b) & mask));
}

uint64_t rotr(uint64_t a, uint64_t b) {
  const uint64_t mask = CHAR_BIT*sizeof(b) - 1;
  b &= mask;
  return (a >> b) | (a << ((-b) & 63));
}

//static uint64_t powi(uint64_t fst, uint64_t snd) {
//  uint64_t res;
//
//  for (res = 1; snd; snd >>= 1, fst *= fst) {
//    if (snd & 1)
//      res *= fst;
//  }
//  return res;
//}

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

static void rewrite(Net *net, uint64_t a_addr) {
  uint64_t *nodes = net->nodes;
  union {
    uint64_t u;
    int64_t  s;
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
    fst.u = a[0];
    switch (a_kind) {
    case OP1:
      snd.u = a[1];
    switch (a[3] >> 8) {
      case EQ:      res.u = fst.u == snd.u; break;
      case NE:      res.u = fst.u != snd.u; break;
      case LT_S:    res.s = fst.s < snd.s; break;
      case LT_U:    res.u = fst.u < snd.u; break;
      case GT_S:    res.s = fst.s > snd.s; break;
      case GT_U:    res.u = fst.u > snd.u; break;
      case LE_S:    res.u = fst.s <= snd.s; break;
      case LE_U:    res.u = fst.u <= snd.u; break;
      case GE_S:    res.u = fst.u >= snd.u; break;
      case GE_U:    res.u = fst.u >= snd.u; break;
      case CLZ:     res.u = __builtin_clz(snd.u); break;
      case CTZ:     res.u = __builtin_ctz(snd.u); break;
      case POPCNT:  res.u = __builtin_popcount(snd.u); break;
      case SHL:     res.u = fst.u << snd.u; break;
      case SHR:     res.u = fst.u >> snd.u; break;
      case SHR_S:   res.s = fst.s >> snd.u; break;
      case ROTL:    res.u = rotl(fst.u, snd.u); break;
      case ROTR:    res.u = rotr(fst.u, snd.u); break;
      case AND:     res.u = fst.u & snd.u; break;
      case  OR:     res.u = fst.u | snd.u; break;
      case XOR:     res.u = fst.u ^ snd.u; break;
      case ADD:     res.u = fst.u + snd.u; break;
      case SUB:     res.u = fst.u - snd.u; break;
      case MUL:     res.u = fst.u * snd.u; break;
      case DIV_S:   res.s = fst.s / snd.s; break;
      case DIV_U:   res.u = fst.u / snd.u; break;
      case REM_S:   res.s = fst.s % snd.s; break;
      case REM_U:   res.u = fst.u % snd.u; break;
      case FABS:    res.f = fabs(snd.f); break;
      case FNEG:    res.f = -1 * snd.f; break;
      case FCEIL:   res.f = ceil(snd.f); break;
      case FFLOOR:  res.f = floor(snd.f); break;
      case FTRUNC:  res.f = trunc(snd.f); break;
      case FNRST:   res.f = round(snd.f); break;
      case FSQRT:   res.f = sqrt(snd.f); break;
      case FADD:    res.f = fst.f + snd.f; break;
      case FSUB:    res.f = fst.f - snd.f; break;
      case FMUL:    res.f = fst.f * snd.f; break;
      case FDIV:    res.f = fst.f / snd.f; break;
      case FMIN:    res.f = fmin(fst.f, snd.f); break;
      case FMAX:    res.f = fmax(fst.f, snd.f); break;
      case FCPYSGN: res.f = copysign(fst.f, snd.f); break;
      case FEQ:     res.u = fst.f == snd.f; break;
      case FNE:     res.u = isunordered(fst.f,snd.f) ? 1 :
                              islessgreater(fst.f, snd.f); break;
      case FLT:     res.u = isless(fst.f, snd.f); break;
      case FGT:     res.u = isgreater(fst.f, snd.f); break;
      case FLE:     res.u = islessequal(fst.f, snd.f); break;
      case FGE:     res.u = isgreaterequal(fst.f, snd.f); break;
      //case EXT32_S:
      case FTOS:   res.s = snd.f; break;
      case FTOU:   res.u = snd.f; break;
      case STOF:   res.f = snd.s; break;
      case UTOF:   res.f = snd.u; break;
      /* unreachable */
      default: res.u = 0; break;
      }
      if ((a[3] >> 4 & 3) == PTR) {
        nodes[a[2]] = res.u;
        nodes[a[2] | 3] |= NUM << (a[2] & 3) * 2;
        if ((a[2] & 3) == 0)
          queue(net, a[2]);
      }
      free_node(net, a_addr);
      break;
    case OP2:
      a[0] = a[1];
      a[1] = fst.u;
      a[3] = OP1 << 6 | NUM << 2 | (a[3] >> 2 & 3) |
             (a[3] & ~(3 << 6 | 3 << 0 | 3 << 2));
      if ((a[3] & 3) == PTR)
        nodes[a[0]] = a_addr;
      if ((a[3] & 3) != PTR || (a[0] & 3) == 0)
        queue(net, a_addr);
      break;
    case NOD:
      if ((a[3] >> 2 & 3) == PTR) {
        nodes[a[1]] = fst.u;
        nodes[a[1] | 3] |= NUM << (a[1] & 3) * 2;
        if ((a[1] & 3) == 0)
          queue(net, a[1]);
      }
      if ((a[3] >> 4 & 3) == PTR) {
        nodes[a[2]] = fst.u;
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
      if (fst.u) {
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
