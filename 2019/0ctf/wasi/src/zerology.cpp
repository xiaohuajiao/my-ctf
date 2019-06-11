#include <cstdio>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "zerology.h"
#include "step3.h"
#include "utils.h"

Ology::Ology()
{
    memset(this->regs, 0, sizeof(this->regs));
    memset(this->memory, 0, sizeof(this->memory));

    memcpy(this->memory+1, "Amazing,gogogo", 14);

    this->preg = 0;
}

Ology::Ology(uint16_t *_regs, uint32_t reg_num, uint8_t *_memory, uint32_t memory_size)
{
    memset(this->regs, 0, sizeof(this->regs));
    memset(this->memory, 0, sizeof(this->memory));

    memcpy(this->regs, _regs, reg_num*sizeof(uint16_t));
    memcpy(this->memory, _memory, memory_size*sizeof(uint8_t));
    this->preg = 0;
}

Zerology::Zerology(uint16_t *_regs, uint32_t reg_num, uint8_t *_memory, uint32_t memory_size)
    : Ology(_regs, reg_num, _memory, memory_size)
{
}
Zerology::~Zerology()
{

}

int32_t Zerology::add(uint32_t rd, uint32_t rs, uint32_t rt)
{
    if (!CHECK_GPR(rd) || !CHECK_GPR(rs) || !CHECK_GPR(rs))
    {
        return INS_RESULT_FAIL;
    }

    this->regs[rd] = this->regs[rs] + this->regs[rt];

    LOG("r%d(%#x) = r%d(%#x) + r%d(%#x)\n",
            rd, this->regs[rd],
            rs, this->regs[rs],
            rt, this->regs[rt]
            );
    return INS_RESULT_NEXT;
}

int32_t Zerology::sub(uint32_t rd, uint32_t rs, uint32_t rt)
{
    if (!CHECK_GPR(rd) || !CHECK_GPR(rs) || !CHECK_GPR(rs))
    {
        return INS_RESULT_FAIL;
    }

    this->regs[rd] = this->regs[rs] - this->regs[rt];

    LOG("r%d(%#x) = r%d(%#x) - r%d(%#x)\n",
            rd, this->regs[rd],
            rs, this->regs[rs],
            rt, this->regs[rt]
            );
    return INS_RESULT_NEXT;
}

int32_t Zerology::mul(uint32_t rd, uint32_t rs, uint32_t rt)
{
    if (!CHECK_GPR(rd) || !CHECK_GPR(rs) || !CHECK_GPR(rs))
    {
        return INS_RESULT_FAIL;
    }

    uint32_t result = this->regs[rs] * this->regs[rt];
    uint16_t low= (result >> 0) & 0xffff;

    this->regs[rd] = low;

    LOG("r%d(%#x) = r%d(%#x) * r%d(%#x)\n",
            rd, low,
            rs, this->regs[rs],
            rt, this->regs[rt]
            );
    return INS_RESULT_NEXT;
}

int32_t Zerology::div(uint32_t rd, uint32_t rs, uint32_t rt)
{
    if (!CHECK_GPR(rd) || !CHECK_GPR(rs) || !CHECK_GPR(rs))
    {
        return INS_RESULT_FAIL;
    }

    if (this->regs[rt] == 0)
        return INS_RESULT_FAIL;

    this->regs[rd] = this->regs[rs] / this->regs[rt];

    LOG("r%d(%#x) = r%d(%#x) / r%d(%#x)\n",
            rd, this->regs[rd],
            rs, this->regs[rs],
            rt, this->regs[rt]
            );
    return INS_RESULT_NEXT;
}

int32_t Zerology::mod(uint32_t rd, uint32_t rs, uint32_t rt)
{
    if (!CHECK_GPR(rd) || !CHECK_GPR(rs) || !CHECK_GPR(rs))
    {
        return INS_RESULT_FAIL;
    }

    if (this->regs[rt] == 0)
        return INS_RESULT_FAIL;

    this->regs[rd] = this->regs[rs] % this->regs[rt];

    LOG("r%d(%#x) = r%d(%#x) %% r%d(%#x)\n",
            rd, this->regs[rd],
            rs, this->regs[rs],
            rt, this->regs[rt]
            );
    return INS_RESULT_NEXT;
}

int32_t Zerology::nor(uint32_t rd, uint32_t rs, uint32_t rt)
{
    if (!CHECK_GPR(rd) || !CHECK_GPR(rs) || !CHECK_GPR(rs))
    {
        return INS_RESULT_FAIL;
    }

    this->regs[rd] = ~(this->regs[rs] | this->regs[rt]);

    LOG("r%d(%#x) = ~(r%d(%#x) | r%d(%#x))\n",
            rd, ~(this->regs[rs] | this->regs[rt]),
            rs, this->regs[rs],
            rt, this->regs[rt]
            );
    return INS_RESULT_NEXT;
}


int32_t Zerology::mov(uint32_t rd, uint32_t rs, uint32_t _)
{
    if (!CHECK_GPR(rd) || !CHECK_GPR(rs))
    {
        return INS_RESULT_FAIL;
    }

    this->regs[rd] = this->regs[rs];

    LOG("r%d(%#x) = r%d(%#x)\n",
            rd, this->regs[rd],
            rs, this->regs[rs]);

    return INS_RESULT_NEXT;
}

int32_t Zerology::exchange(uint32_t rd, uint32_t rs, uint32_t _)
{
    if (!CHECK_GPR(rd) || !CHECK_GPR(rs))
    {
        return INS_RESULT_FAIL;
    }

    uint16_t tmp = this->regs[rs];
    this->regs[rs] = this->regs[rd];
    this->regs[rd] = tmp;

    LOG("r%d(%#x) <=> r%d(%#x)\n",
            rd, this->regs[rd],
            rs, this->regs[rs]);
    return INS_RESULT_NEXT;
}

int32_t Zerology::li(uint32_t rd, uint16_t imm, uint32_t _)
{
    if (!CHECK_GPR(rd))
    {
        return INS_RESULT_FAIL;
    }

    this->regs[rd] = (uint16_t)imm;

    LOG("r%d(%#x) = %#x\n",
            rd, this->regs[rd],
            imm
            );

    return INS_RESULT_NEXT;
}

int32_t Zerology::load(uint32_t rd, uint32_t rs, uint32_t type)
{
    if (!CHECK_GPR(rd) || !CHECK_GPR(rs))
    {
        return INS_RESULT_FAIL;
    }

    uint16_t mem = 0;
    switch (type)
    {
        case 1:
            {
                mem = this->regs[rs];
                this->regs[rd] = this->memory[mem];

                LOG("r%d(%#x) = byte ptr [r%d(%#x)] (%#02x)\n",
                        rd, this->regs[rd],
                        rs, this->regs[rs],
                        this->regs[rd]
                        );
            }
            break;
        case 2:
            {
                mem = this->regs[rs];
                if (mem > MEMORY_SIZE-2)
                    return INS_RESULT_FAIL;

                this->regs[rd] = *(uint16_t *)(this->memory + mem);

                LOG("r%d(%#x) = word ptr [r%d(%#x)] (%#02x)\n",
                        rd, this->regs[rd],
                        rs, this->regs[rs],
                        this->regs[rd]
                        );
            }
            break;
    }
    return INS_RESULT_NEXT;
}

int32_t Zerology::store(uint32_t rd, uint32_t rs, uint32_t type)
{
    if (!CHECK_GPR(rd) || !CHECK_GPR(rs))
    {
        return INS_RESULT_FAIL;
    }

    uint16_t mem = 0;
    switch (type)
    {
        case 1:
            {
                mem = this->regs[rs];
                this->memory[mem] = this->regs[rd] & 0xff;

                LOG("byte ptr [r%d(%#x)] (%#02x) = r%d(%#x)\n",
                        rs, this->regs[rs],
                        this->regs[rd],
                        rd, this->regs[rd]
                        );
            }
            break;
        case 2:
            {
                mem = this->regs[rs];
                if (mem > MEMORY_SIZE-2)
                    return INS_RESULT_FAIL;

                *(uint16_t *)(this->memory + mem) = this->regs[rd];

                LOG("word ptr [r%d(%#x)] (%#02x) = r%d(%#x)\n",
                        rs, this->regs[rs],
                        this->regs[rd],
                        rd, this->regs[rd]
                        );
            }
            break;
    }
    return INS_RESULT_NEXT;
}


int32_t Zerology::jmp(uint32_t offset, uint32_t _, uint32_t __)
{
    LOG("jmp %#x\n", offset);

    return (int32_t)offset;
}

int32_t Zerology::jmpcond(uint32_t offset, uint32_t _, uint32_t __)
{
    LOG("jmpcond (%d) %#x (%s)\n",
            this->preg,
            offset,
            (this->preg) ? "Taken": "Not taken"
            );

    if (this->preg)
        return (int32_t)offset;
    else
        return INS_RESULT_NEXT;
}


int32_t Zerology::cmp(uint32_t rd, uint32_t rs, uint32_t cond)
{
    if (!CHECK_GPR(rd) || !CHECK_GPR(rs))
    {
        return INS_RESULT_FAIL;
    }

    switch (cond)
    {
        case CMP_LT:
            {
                this->preg = (this->regs[rd] < this->regs[rs]);

                LOG("r%d(%#x) < r%d(%#x)\n",
                        rd, this->regs[rd],
                        rs, this->regs[rs]
                        );
            }
            break;
        case CMP_EQ:
            {
                this->preg = (this->regs[rd] == this->regs[rs]);

                LOG("r%d(%#x) == r%d(%#x)\n",
                        rd, this->regs[rd],
                        rs, this->regs[rs]
                        );
            }
            break;
        case CMP_GT:
            {
                this->preg = (this->regs[rd] > this->regs[rs]);

                LOG("r%d(%#x) > r%d(%#x)\n",
                        rd, this->regs[rd],
                        rs, this->regs[rs]
                        );
            }
            break;
        default:
            {
                return INS_RESULT_FAIL;
            }
    }
    return INS_RESULT_NEXT;
}


int32_t Zerology::_open(uint32_t reg_fd, uint32_t reg_filename, uint32_t reg_mode)
{
    if (!CHECK_GPR(reg_fd) || !CHECK_GPR(reg_filename) || !CHECK_GPR(reg_mode))
    {
        return INS_RESULT_FAIL;
    }

    char *filename = (char *)(this->memory + this->regs[reg_filename]);
    int mode = this->regs[reg_mode];

#ifdef WASI
    mode <<= 16;
#endif

    int fd = open(filename, mode);
    this->regs[reg_fd] = fd;

    LOG("r%d(%d) = open([%#x]\"%s\", %#x)\n", reg_fd, fd, this->regs[reg_filename], filename, mode);

    return INS_RESULT_NEXT;
}

int32_t Zerology::_read(uint32_t reg_fd, uint32_t reg_buf, uint32_t _)
{
    if (!CHECK_GPR(reg_fd) || !CHECK_GPR(reg_buf))
    {
        return INS_RESULT_FAIL;
    }

    int fd = this->regs[reg_fd];
    char *buf = (char *)(this->memory+this->regs[reg_buf]);

    read(fd, buf, 1);

    LOG("read(%d, [r%d(%#x)] => '%c' (%02x), %#x)\n",
            fd,
            reg_buf, this->regs[reg_buf],
            *buf, *buf,
            1);

    return INS_RESULT_NEXT;
}

int32_t Zerology::_write(uint32_t reg_fd, uint32_t reg_buf, uint32_t _)
{
    if (!CHECK_GPR(reg_fd) || !CHECK_GPR(reg_buf))
    {
        return INS_RESULT_FAIL;
    }

    int fd = this->regs[reg_fd];
    char *buf = (char *)(this->memory+this->regs[reg_buf]);

    write(fd, buf, 1);

    LOG("write(%d, [r%d(%#x)] => '%c' (%02x), %#x)\n",
            fd,
            reg_buf, this->regs[reg_buf],
            *buf, *buf,
            1);

    return INS_RESULT_NEXT;
}

int32_t Zerology::_close(uint32_t reg_fd, uint32_t _, uint32_t __)
{
    if (!CHECK_GPR(reg_fd))
    {
        return INS_RESULT_FAIL;
    }

    int fd = this->regs[reg_fd];

    close(fd);

    LOG("close(%d)\n", fd);

    return INS_RESULT_NEXT;
}

int32_t Zerology::nop(uint32_t, uint32_t, uint32_t)
{
    LOG("nop\n");
    return INS_RESULT_NEXT;
}

int32_t Zerology::quit(uint32_t, uint32_t, uint32_t)
{
    LOG("quit\n");
    return INS_RESULT_FAIL;
}

int32_t Zerology::run_ins(uint32_t opcode, uint32_t op1, uint32_t op2, uint32_t op3)
{
#define CASE_OP(op) case OP_ ##op : return this->op(op1, op2, op3)

    switch (opcode)
    {
        CASE_OP(nop);

        CASE_OP(add);
        CASE_OP(sub);
        CASE_OP(mul);
        CASE_OP(div);
        CASE_OP(mod);
        CASE_OP(nor);

        CASE_OP(mov);
        CASE_OP(exchange);
        CASE_OP(li);

        CASE_OP(load);
        CASE_OP(store);

        CASE_OP(jmp);
        CASE_OP(jmpcond);

        CASE_OP(cmp);

        CASE_OP(_open);
        CASE_OP(_read);
        CASE_OP(_write);
        CASE_OP(_close);

        CASE_OP(quit);
    }

    return INS_RESULT_FAIL;
}



#ifdef STEP3_DEBUG
int main()
{
    Zerology * six = new Zerology();

    /*
    six->li(0, 1, 0);
    six->li(1, 2, 0);
    six->li(2, 3, 0);
    six->li(3, 4, 0);
    six->li(4, 5, 0);
    six->li(5, 6, 0);
    six->add(7, 0, 1);
    six->div(8, 4, 2);
    six->mod(9, 4, 2);
    six->mul(10, 4, 3);
    six->sub(11, 4, 1);
    six->mov(12, 11, 0);
    six->exchange(10, 12, 0);

    six->li(0, 0x3231, 0);
    six->li(1, 0, 0);
    six->store(0, 1, 2);
    six->li(0, 0x3433, 0);
    six->li(1, 2, 0);
    six->store(0, 1, 2);

    six->li(0, 0, 0);
    six->li(1, 0, 0);
    six->_open(2, 0, 1);

    uint32_t base;
    for (base = 0x10; base < 0x20; base++)
    {
        six->li(3, base, 0);
        six->_read(2, 3, 0);
    }

    six->li(4, 1, 0);
    for (base = 0x10; base < 0x20; base++)
    {
        six->li(3, base, 0);
        six->_write(4, 3, 0);
    }
    */


    /*

    six->li(0, 0x3231, 0);
    six->li(1, 0, 0);
    six->store(0, 1, 2);
    six->li(0, 0x3433, 0);
    six->li(1, 2, 0);
    six->store(0, 1, 2);

    six->li(0, 0, 0);
    six->li(1, 0, 0);
    six->_open(2, 0, 1);

    six->li(4, 1, 0);
    six->li(5, 0x20, 0);

    six->li(3, 0x10, 0);
    six->_read(2, 3, 0);
    six->add(3, 3, 4);
    six->cmp(3, 5, CMP_LT);
    six->jmpcond(-4, 0, 0);

    six->quit(0, 0, 0);
    */

    step3(six);

    //six->li(0, 0x2019, 2);
    //six->li(10, 0x30, 4);
    //six->li(0, 0x2019, 2);

    delete six;
}

#endif
