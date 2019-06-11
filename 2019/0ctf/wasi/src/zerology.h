#ifndef ZEROLOGY_H
#define ZEROLOGY_H

#include <stdint.h>

#define VM_DEBUG

#define NUM_OF_GPR      (0x20U)
#define MEMORY_SIZE     (0x10000)

#define CHECK_GPR(reg)  (((uint32_t)reg >= 0U) && ((uint32_t)reg < NUM_OF_GPR))

#define INS_RESULT_FAIL (-0x10000)
#define INS_RESULT_NEXT (1)

enum OlogyOpcode {
    OP_nop = 0,

    OP_add,
    OP_sub,
    OP_mul,
    OP_div,
    OP_mod,
    OP_nor,

    OP_mov,
    OP_exchange,
    OP_li,

    OP_load,
    OP_store,

    OP_jmp,
    OP_jmpcond,

    OP_cmp,

    OP__open,
    OP__read,
    OP__write,
    OP__close,

    OP_quit,
};

enum CMP_OP {
    CMP_LT = 0,
    CMP_EQ,
    CMP_GT,
};

class Ology
{
public:
    Ology();
    Ology(uint16_t *_regs, uint32_t reg_num, uint8_t *memory, uint32_t memory_size);
    virtual ~Ology() {};

protected:
    virtual int32_t add(uint32_t rd, uint32_t rs, uint32_t rt) = 0;
    virtual int32_t sub(uint32_t rd, uint32_t rs, uint32_t rt) = 0;
    virtual int32_t mul(uint32_t rd, uint32_t rs, uint32_t rt) = 0;
    virtual int32_t div(uint32_t rd, uint32_t rs, uint32_t rt) = 0;
    virtual int32_t mod(uint32_t rd, uint32_t rs, uint32_t rt) = 0;
    virtual int32_t nor(uint32_t rd, uint32_t rs, uint32_t rt) = 0;

    virtual int32_t mov(uint32_t rd, uint32_t rs, uint32_t reserved) = 0;
    virtual int32_t exchange(uint32_t rd, uint32_t rs, uint32_t reserved) = 0;
    virtual int32_t li(uint32_t rd, uint16_t imm, uint32_t reserved) = 0;

    virtual int32_t load(uint32_t rd, uint32_t rs, uint32_t type) = 0;
    virtual int32_t store(uint32_t rd, uint32_t rs, uint32_t type) = 0;

    virtual int32_t jmp(uint32_t offset, uint32_t, uint32_t) = 0;
    virtual int32_t jmpcond(uint32_t offset, uint32_t, uint32_t) = 0;

    virtual int32_t cmp(uint32_t rd, uint32_t rs, uint32_t) = 0;

    virtual int32_t _open(uint32_t fd, uint32_t filename, uint32_t mode) = 0;
    virtual int32_t _read(uint32_t fd, uint32_t buf, uint32_t) = 0;
    virtual int32_t _write(uint32_t fd, uint32_t buf, uint32_t) = 0;
    virtual int32_t _close(uint32_t fd, uint32_t, uint32_t) = 0;

    virtual int32_t nop(uint32_t, uint32_t, uint32_t) = 0;
    virtual int32_t quit(uint32_t, uint32_t, uint32_t) = 0;

    virtual int32_t run_ins(uint32_t opcode, uint32_t op1, uint32_t op2, uint32_t op3) = 0;

protected:
    uint16_t regs[NUM_OF_GPR];
    uint8_t memory[MEMORY_SIZE];
    uint16_t preg;
};

class Zerology : Ology
{
public:
    Zerology(uint16_t *_regs, uint32_t reg_num, uint8_t *memory, uint32_t memory_size);
    ~Zerology();

public:

    int32_t add(uint32_t rd, uint32_t rs, uint32_t rt);
    int32_t sub(uint32_t rd, uint32_t rs, uint32_t rt);
    int32_t mul(uint32_t rd, uint32_t rs, uint32_t rt);
    int32_t div(uint32_t rd, uint32_t rs, uint32_t rt);
    int32_t mod(uint32_t rd, uint32_t rs, uint32_t rt);
    int32_t nor(uint32_t rd, uint32_t rs, uint32_t rt);

    int32_t mov(uint32_t rd, uint32_t rs, uint32_t reserved);
    int32_t exchange(uint32_t rd, uint32_t rs, uint32_t reserved);
    int32_t li(uint32_t rd, uint16_t imm, uint32_t reserved);

    int32_t load(uint32_t rd, uint32_t rs, uint32_t type);
    int32_t store(uint32_t rd, uint32_t rs, uint32_t type);

    int32_t jmp(uint32_t offset, uint32_t, uint32_t);
    int32_t jmpcond(uint32_t offset, uint32_t , uint32_t);

    int32_t cmp(uint32_t rd, uint32_t rs, uint32_t);

    int32_t _open(uint32_t fd, uint32_t filename, uint32_t mode);
    int32_t _read(uint32_t fd, uint32_t buf, uint32_t);
    int32_t _write(uint32_t fd, uint32_t buf, uint32_t);
    int32_t _close(uint32_t fd, uint32_t, uint32_t);

    int32_t nop(uint32_t, uint32_t, uint32_t);
    int32_t quit(uint32_t, uint32_t, uint32_t);

    int32_t run_ins(uint32_t opcode, uint32_t op1, uint32_t op2, uint32_t op3);
};

#endif
