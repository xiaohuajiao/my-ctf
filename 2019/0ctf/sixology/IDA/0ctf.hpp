#ifndef _0CTF_HPP
#define _0CTF_HPP

#include "idaidp.hpp"
#include "ins.hpp"
#include <typeinf.hpp>
#include <stdint.h>

#define LOOP_TAG  'L'

#define PROC_MAXOP 4  // max number of operands
CASSERT(PROC_MAXOP <= UA_MAXOP);

//------------------------------------------------------------------
enum RegNo
{
    R0,   R1,   R2,   R3,   R4,   R5,   R6,   R7,
    R8,   R9,   R10,  R11,  R12,  R13,  R14,  R15,
    R16,  R17,  R18,  R19,  R20,  R21,  R22,  R23,
    R24,  R25,  R26,  R27,  R28,  R29,  R30,  R31,
    P0, P1, P2, P3,
    SA, LC,
  rVcs, rVds,      // virtual registers for code and data segments
  SP = R31,
  FP = R30,
  LR = R29,
};

#define GPR_NUM 32

enum cond_t
{
    cLT = 0,
    cEQ = 1,
    cGT = 2,
};

int idaapi ana(insn_t *_insn);
int idaapi emu(const insn_t &_insn);
bool idaapi oops_is_basic_block_end(const insn_t &insn);
bool idaapi create_func_frame(func_t * pfn);
bool idaapi oops_is_call_insn(const insn_t &insn);
int idaapi oops_get_frame_retsize(const func_t * /*pfn */ );

#endif
