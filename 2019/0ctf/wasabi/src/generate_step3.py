#!/usr/bin/env python
# encoding: utf-8

instructions = """
li 0, 0x3231, 0
li 1, 0, 0
store 0, 1, 2
li 0, 0x3433, 0
li 1, 2, 0
store 0, 1, 2

li 0, 0, 0
li 1, 0, 0
_open 2, 0, 1

li 3, 0x10, 0
li 4, 1, 0
li 5, 0x20, 0

_read 2, 3, 0
add 3, 3, 4
cmp 3, 5, CMP_LT
jmpcond (uint32_t)-3, 0, 0

quit 0, 0, 0
"""

instructions = """
li 0, 1, 2
mov 1, 0, 3
add 2, 1, 0
mov 3, 2, 0
add 4, 2, 3
mul 5, 4, 4

li 7, 1, 4

exchange 6, 1, 0
_write 7, 6, 3
exchange 1, 6, 0
add 1, 1, 0
cmp 5, 1, CMP_GT
jmpcond (uint32_t)-5, 0, 0

quit 8, 8, 6
"""

def parser(instructions):
    operators = []
    operands = []

    for ins in instructions.split("\n"):
        if len(ins) == 0:
            continue
        operator, tmp = ins.strip().split(" ", 1)
        operand = map(lambda x: x.strip(), tmp.split(","))

        operators.append(operator)
        operands.append(operand)

    print operators
    print operands
    return operators, operands

def generator(operators, operands):
    assert len(operators) == len(operands)

    c_code = """
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
"""
    c_code += """
    OlogyOpcode operators[{num}];
    uint32_t operands[{num}][3];

""".format(num=len(operators))

    for i in xrange(len(operators)):
        c_code += "    operators[{}] = OP_{};\n".format(i, operators[i])

    for i in xrange(len(operands)):
        assert len(operands[i]) == 3
        c_code += """
    operands[{index}][0] = {op0};
    operands[{index}][1] = {op1};
    operands[{index}][2] = {op2};
    """.format(index=i, op0=operands[i][0], op1=operands[i][1], op2=operands[i][2])

    c_code += """
    uint32_t num_of_ins = {};
    """.format(len(operators))

    c_code += """

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
    """

    return c_code


if __name__ == "__main__":
    operators, operands = parser(instructions)
    c_code = generator(operators, operands)
    print c_code

    open("step3.cpp", 'w').write(c_code)

