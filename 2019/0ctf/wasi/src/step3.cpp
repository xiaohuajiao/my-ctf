
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "step3.h"
#include "zerology.h"

uint16_t g_regs[NUM_OF_GPR] = {0};
uint8_t g_memory[MEMORY_SIZE] = {0};

// FIXME: is this function signature ok??
void step3()
{
    Zerology *vm = new Zerology(g_regs, NUM_OF_GPR, g_memory, MEMORY_SIZE);
    if (!vm) _exit(0);

    OlogyOpcode operators[14];
    uint32_t operands[14][3];

    operators[0] = OP_li;
    operators[1] = OP_mov;
    operators[2] = OP_add;
    operators[3] = OP_mov;
    operators[4] = OP_add;
    operators[5] = OP_mul;
    operators[6] = OP_li;
    operators[7] = OP_exchange;
    operators[8] = OP__write;
    operators[9] = OP_exchange;
    operators[10] = OP_add;
    operators[11] = OP_cmp;
    operators[12] = OP_jmpcond;
    operators[13] = OP_quit;

    operands[0][0] = 0;
    operands[0][1] = 1;
    operands[0][2] = 2;
    
    operands[1][0] = 1;
    operands[1][1] = 0;
    operands[1][2] = 3;
    
    operands[2][0] = 2;
    operands[2][1] = 1;
    operands[2][2] = 0;
    
    operands[3][0] = 3;
    operands[3][1] = 2;
    operands[3][2] = 0;
    
    operands[4][0] = 4;
    operands[4][1] = 2;
    operands[4][2] = 3;
    
    operands[5][0] = 5;
    operands[5][1] = 4;
    operands[5][2] = 4;
    
    operands[6][0] = 7;
    operands[6][1] = 1;
    operands[6][2] = 4;
    
    operands[7][0] = 6;
    operands[7][1] = 1;
    operands[7][2] = 0;
    
    operands[8][0] = 7;
    operands[8][1] = 6;
    operands[8][2] = 3;
    
    operands[9][0] = 1;
    operands[9][1] = 6;
    operands[9][2] = 0;
    
    operands[10][0] = 1;
    operands[10][1] = 1;
    operands[10][2] = 0;
    
    operands[11][0] = 5;
    operands[11][1] = 1;
    operands[11][2] = CMP_GT;
    
    operands[12][0] = (uint32_t)-5;
    operands[12][1] = 0;
    operands[12][2] = 0;
    
    operands[13][0] = 8;
    operands[13][1] = 8;
    operands[13][2] = 6;
    
    uint32_t num_of_ins = 14;
    

    uint32_t cur_pc = 0;

    while (cur_pc < num_of_ins)
    {
        int32_t ins_result = vm->run_ins(operators[cur_pc],
                                         operands[cur_pc][0],
                                         operands[cur_pc][1],
                                         operands[cur_pc][2]);

        if (ins_result == INS_RESULT_FAIL)
            break;

        cur_pc += ins_result;
    }

    delete vm;
    _exit(0);
}
    