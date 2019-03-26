#ifndef __INS_HPP
#define __INS_HPP

extern instruc_t Instructions[];

enum nameNum
{
    MEMEDA_null = 0,

    MEMEDA_allocframe = 2,
    MEMEDA_deallocframe = 5,

    MEMEDA_store = 3,
    MEMEDA_load = 31,

    MEMEDA_loop = 7,
    MEMEDA_endloop = 23,

    MEMEDA_jmp = 19,
    MEMEDA_call = 17,
    MEMEDA_jmpcond = 30,
    MEMEDA_ret = 29,
    MEMEDA_switch = 26,

    MEMEDA_add = 8,
    MEMEDA_sub = 14,
    MEMEDA_div = 24,
    MEMEDA_nor = 12,

    MEMEDA_cmp = 20,

    MEMEDA_exchange = 4,
    MEMEDA_mov = 16,
    MEMEDA_li = 11,

    MEMEDA_lexcmp = 27,

    MEMEDA_last = 32,
};

#endif
