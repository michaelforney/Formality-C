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
  UTOF     // unsigned i64 to f64
};

uint64_t op_eq(uint64_t a, uint64_t b) { return a == b; }
uint64_t op_ne(uint64_t a, uint64_t b) { return a != b; }
uint64_t op_lt_s(int64_t a, int64_t b) { return a < b; }
uint64_t op_gt_s(int64_t a, int64_t b) { return a > b; }
uint64_t op_le_s(int64_t a, int64_t b) { return a <= b; }
uint64_t op_ge_s(int64_t a, int64_t b) { return a >= b; }
uint64_t op_lt_u(uint64_t a, uint64_t b) { return a < b; }
uint64_t op_gt_u(uint64_t a, uint64_t b) { return a > b; }
uint64_t op_le_u(uint64_t a, uint64_t b) { return a <= b; }
uint64_t op_ge_u(uint64_t a, uint64_t b) { return a >= b; }
uint64_t op_clz(uint64_t a, uint64_t b) { return __builtin_clzll(b); }
uint64_t op_ctz(uint64_t a, uint64_t b) { return __builtin_ctzll(b); }
uint64_t op_popcnt(uint64_t a, uint64_t b) { return __builtin_popcountll(b); }
uint64_t op_shl(uint64_t a, uint64_t b) { return a << b; }
uint64_t op_shr(uint64_t a, uint64_t b) { return a >> b; }
int64_t op_shr_s(int64_t a, uint64_t b) { return a >> b; }
uint64_t op_rotl(uint64_t a, uint64_t b) { return a << (b & 63) | a >> (-b & 63); }
uint64_t op_rotr(uint64_t a, uint64_t b) { return a >> (b & 63) | a << (-b & 63); }
uint64_t op_and(uint64_t a, uint64_t b) { return a & b; }
uint64_t op_or(uint64_t a, uint64_t b) { return a | b; }
uint64_t op_xor(uint64_t a, uint64_t b) { return a ^ b; }
uint64_t op_add(uint64_t a, uint64_t b) { return a + b; }
uint64_t op_sub(uint64_t a, uint64_t b) { return a - b; }
uint64_t op_mul(uint64_t a, uint64_t b) { return a * b; }
int64_t op_div_s(int64_t a, int64_t b) { return a / b; }
uint64_t op_div_u(uint64_t a, uint64_t b) { return a / b; }
int64_t op_rem_s(int64_t a, int64_t b) { return a % b; }
uint64_t op_rem_u(uint64_t a, uint64_t b) { return a % b; }
double op_fabs(double a, double b) { return fabs(b); }
double op_fneg(double a, double b) { return -1 * b; }
double op_fceil(double a, double b) { return ceil(b); }
double op_ffloor(double a, double b) { return floor(b); }
double op_ftrunc(double a, double b) { return trunc(b); }
double op_fnrst(double a, double b) { return round(b); }
double op_fsqrt(double a, double b) { return sqrt(b); }
double op_fadd(double a, double b) { return a + b; }
double op_fsub(double a, double b) { return a - b; }
double op_fmul(double a, double b) { return a * b; }
double op_fdiv(double a, double b) { return a / b; }
double op_fmin(double a, double b) { return fmin(a, b); }
double op_fmax(double a, double b) { return fmax(a, b); }
double op_fcpysgn(double a, double b) { return copysign(a, b); }
uint64_t op_feq(double a, double b) { return a == b; }
uint64_t op_fne(double a, double b) { return a != b; }
uint64_t op_flt(double a, double b) { return isless(a, b); }
uint64_t op_fgt(double a, double b) { return isgreater(a, b); }
uint64_t op_fle(double a, double b) { return islessequal(a, b); }
uint64_t op_fge(double a, double b) { return isgreaterequal(a, b); }
int64_t op_ftos(double a, double b) { return (int64_t)b; }
uint64_t op_ftou(double a, double b) { return (uint64_t)b; }
double op_stof(int64_t a, int64_t b) { return (double)b; }
double op_utof(uint64_t a, uint64_t b) { return (double)b; }

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
      case EQ:      res.u = op_eq(fst.u, snd.u); break;
      case NE:      res.u = op_ne(fst.u, snd.u); break;
      case LT_S:    res.s = op_lt_s(fst.s, snd.s); break;
      case LT_U:    res.u = op_lt_u(fst.u, snd.u); break;
      case GT_S:    res.s = op_gt_s(fst.s, snd.s); break;
      case GT_U:    res.u = op_gt_u(fst.u, snd.u); break;
      case LE_S:    res.u = op_le_s(fst.s, snd.s); break;
      case LE_U:    res.u = op_le_u(fst.u, snd.u); break;
      case GE_S:    res.u = op_ge_s(fst.u, snd.u); break;
      case GE_U:    res.u = op_ge_u(fst.u, snd.u); break;
      case CLZ:     res.u = op_clz(fst.u, snd.u); break;
      case CTZ:     res.u = op_ctz(fst.u, snd.u); break;
      case POPCNT:  res.u = op_popcnt(fst.u, snd.u); break;
      case SHL:     res.u = op_shl(fst.u, snd.u); break;
      case SHR:     res.u = op_shr(fst.u, snd.u); break;
      case SHR_S:   res.s = op_shr_s(fst.s, snd.u); break;
      case ROTL:    res.u = op_rotl(fst.u, snd.u); break;
      case ROTR:    res.u = op_rotr(fst.u, snd.u); break;
      case AND:     res.u = op_and(fst.u, snd.u); break;
      case  OR:     res.u = op_or(fst.u, snd.u); break;
      case XOR:     res.u = op_xor(fst.u, snd.u); break;
      case ADD:     res.u = op_add(fst.u, snd.u); break;
      case SUB:     res.u = op_sub(fst.u, snd.u); break;
      case MUL:     res.u = op_mul(fst.u, snd.u); break;
      case DIV_S:   res.s = op_div_s(fst.s, snd.s); break;
      case DIV_U:   res.u = op_div_u(fst.u, snd.u); break;
      case REM_S:   res.s = op_rem_s(fst.s, snd.s); break;
      case REM_U:   res.u = op_rem_u(fst.u, snd.u); break;
      case FABS:    res.f = op_fabs(fst.f, snd.f); break;
      case FNEG:    res.f = op_fneg(fst.f, snd.f); break;
      case FCEIL:   res.f = op_fceil(fst.f, snd.f); break;
      case FFLOOR:  res.f = op_ffloor(fst.f, snd.f); break;
      case FTRUNC:  res.f = op_ftrunc(fst.f, snd.f); break;
      case FNRST:   res.f = op_fnrst(fst.f, snd.f); break;
      case FSQRT:   res.f = op_fsqrt(fst.f, snd.f); break;
      case FADD:    res.f = op_fadd(fst.f, snd.f); break;
      case FSUB:    res.f = op_fsub(fst.f, snd.f); break;
      case FMUL:    res.f = op_fmul(fst.f, snd.f); break;
      case FDIV:    res.f = op_fdiv(fst.f, snd.f); break;
      case FMIN:    res.f = op_fmin(fst.f, snd.f); break;
      case FMAX:    res.f = op_fmax(fst.f, snd.f); break;
      case FCPYSGN: res.f = op_fcpysgn(fst.f, snd.f); break;
      case FEQ:     res.u = op_fne(fst.f, snd.f); break;
      case FNE:     res.u = op_fne(fst.f, snd.f); break;
      case FLT:     res.u = op_flt(fst.f, snd.f); break;
      case FGT:     res.u = op_fgt(fst.f, snd.f); break;
      case FLE:     res.u = op_fle(fst.f, snd.f); break;
      case FGE:     res.u = op_fge(fst.f, snd.f); break;
      //case EXT32_S:
      case FTOS:    res.s = op_ftos(fst.f, snd.f); break;
      case FTOU:    res.u = op_ftou(fst.f, snd.f); break;
      case STOF:    res.f = op_stof(fst.s, snd.s); break;
      case UTOF:    res.f = op_utof(fst.u, snd.u); break;
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
