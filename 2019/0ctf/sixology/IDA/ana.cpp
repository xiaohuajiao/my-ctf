#include "0ctf.hpp"
#include <frame.hpp>

#define BITS(val, low, bits) ( ((val)>>low) & ( (1<<bits)-1) )

#define RD(val) ( BITS(val, 27, 5) )
#define RS(val) ( BITS(val, 22, 5) )
#define RT(val) ( BITS(val, 17, 5) )
#define RM(val) ( BITS(val, 2, 5) )


//----------------------------------------------------------------------
// analyze an instruction
int idaapi ana(insn_t *_insn)
{
    uint32_t bytes = 0;
    insn_t &insn = *_insn;

    ssize_t ret = get_bytes(&bytes, 4, insn.ea);
    if (ret != 4)
        return 0;

    uint32_t opcode = BITS(bytes, 12, 5);

    insn.itype = opcode;
    insn.size = 4;

    // msg(" [ana]: %#x %s\n", insn.ea, Instructions[opcode].name);

    switch (insn.itype)
    {
        case MEMEDA_allocframe:
        {
            uint32_t delta = 0;
            delta |= BITS(bytes, 20, 12);
            delta |= BITS(bytes, 0, 12) << 12;

            insn.Op1.type = o_imm;
            insn.Op1.dtype = dt_dword;
            insn.Op1.value = delta;
            break;
        }
        case MEMEDA_ret:
        case MEMEDA_deallocframe:
        {
            insn.Op1.type = o_void;
            break;
        }
        case MEMEDA_store:
        case MEMEDA_load:
        {
            uint32_t memop_type = BITS(bytes, 17, 2);
            uint32_t width = BITS(bytes, 19, 2);

            insn.Op1.type = o_reg;
            insn.Op1.dtype = width;
            insn.Op1.reg = RD(bytes);

            // msg("[%#x] memop_type: %d width: %d\n", memop_type, width);

            switch (memop_type)
            {
                case 1:
                {
                    // load/store Rd, [Rs]
                    insn.Op2.type = o_phrase;
                    insn.Op2.reg = RS(bytes);
                    insn.Op2.dtype = width;
                    break;
                }
                case 2:
                {
                    // load/store Rd, [Rs+Imm]
                    uint32_t displacement = BITS(bytes, 0, 12);

                    insn.Op2.type = o_displ;
                    insn.Op2.reg = RS(bytes);
                    insn.Op2.addr = displacement;
                    insn.Op2.dtype = width;
                    break;
                }
                case 3:
                {
                    // load/store Rd, [Imm]
                    uint32_t addr = BITS(bytes, 0, 12);
                    insn.Op2.type = o_mem;
                    insn.Op2.addr = addr;
                    insn.Op2.dtype = width;
                    break;
                }
                default:
                {
                    // qeprintf("[X] Unknow memop type at %#x\n", insn.ea);
                    break;
                }
            }
            break;
        }
        case MEMEDA_li:
        {
            uint32_t imm = 0;
            ret = get_bytes(&imm, 4, insn.ea+4);
            if (ret != 4)
                return 0;

            imm ^= 0x46544330;

            insn.Op1.type = o_reg;
            insn.Op1.dtype = dt_dword;
            insn.Op1.reg = RD(bytes);

            insn.Op2.type = o_imm;
            insn.Op2.dtype = dt_dword;
            insn.Op2.value = imm;

            insn.size += 4;
            break;
        }
        case MEMEDA_exchange:
        case MEMEDA_mov:
        {
            insn.Op1.type = o_reg;
            insn.Op1.dtype = dt_dword;
            insn.Op1.reg = RD(bytes);

            insn.Op2.type = o_reg;
            insn.Op2.dtype = dt_dword;
            insn.Op2.reg = RS(bytes);
            break;
        }
        case MEMEDA_add:
        case MEMEDA_nor:
        case MEMEDA_sub:
        {
            insn.Op1.type = o_reg;
            insn.Op1.dtype = dt_dword;
            insn.Op1.reg = RD(bytes);

            insn.Op2.type = o_reg;
            insn.Op2.dtype = dt_dword;
            insn.Op2.reg = RS(bytes);

            insn.Op3.type = o_reg;
            insn.Op3.dtype = dt_dword;
            insn.Op3.reg = RT(bytes);
            break;
        }
        case MEMEDA_div:
        {
            insn.Op1.type = o_reg;
            insn.Op1.dtype = dt_dword;
            insn.Op1.reg = RD(bytes);

            insn.Op2.type = o_reg;
            insn.Op2.dtype = dt_dword;
            insn.Op2.reg = RM(bytes);

            insn.Op3.type = o_reg;
            insn.Op3.dtype = dt_dword;
            insn.Op3.reg = RS(bytes);

            insn.Op4.type = o_reg;
            insn.Op4.dtype = dt_dword;
            insn.Op4.reg = RT(bytes);
            break;
        }
        case MEMEDA_lexcmp:
        case MEMEDA_cmp:
        {
            insn.Op1.type = o_idpspec0;
            insn.Op1.dtype = dt_dword;
            insn.Op1.reg = BITS(bytes, 30, 2)+GPR_NUM;
            insn.Op1.specflag1 = BITS(bytes, 27, 2);

            insn.Op2.type = o_reg;
            insn.Op2.dtype = dt_dword;
            insn.Op2.reg = RS(bytes);

            insn.Op3.type = o_reg;
            insn.Op3.dtype = dt_dword;
            insn.Op3.reg = RT(bytes);
            break;
        }
        case MEMEDA_loop:
        {
            int16_t offset = 0;
            offset |= BITS(bytes, 0, 12);
            offset |= BITS(bytes, 17, 2) << 12;
            offset <<= 2;

            // msg("[%#x] loop: %#x\n", insn.ea, offset);
            insn.Op1.type = o_near;
            insn.Op1.dtype = dt_dword;
            insn.Op1.addr = insn.ea+4+offset;

            insn.Op2.type = o_reg;
            insn.Op2.dtype = dt_dword;
            insn.Op2.reg = RS(bytes);
            break;
        }
        case MEMEDA_endloop:
        {
            int16_t offset = 0;
            offset |= BITS(bytes, 17, 14);
            offset <<= 2;

            uint32_t count = BITS(bytes, 0, 10);

            insn.Op1.type = o_near;
            insn.Op1.dtype = dt_dword;
            insn.Op1.addr = insn.ea+4+offset;
            break;
        }
        case MEMEDA_switch:
        {
            int16_t default_off = 0;
            default_off |= BITS(bytes, 0, 12);
            default_off <<= 2;

            int16_t jtable_off = 0;
            jtable_off |= BITS(bytes, 17, 12);
            jtable_off <<= 2;

            insn.Op1.type = o_reg;
            insn.Op1.dtype = dt_dword;
            insn.Op1.reg = BITS(bytes, 29, 3);

            insn.Op2.type = o_near;
            insn.Op2.dtype = dt_dword;
            insn.Op2.addr = insn.ea+4+default_off;

            insn.Op3.type = o_idpspec1;
            insn.Op3.dtype = dt_dword;
            insn.Op3.addr = insn.ea+4+jtable_off;
            break;
        }
        case MEMEDA_call:
        case MEMEDA_jmp:
        {
            int16_t offset = 0;
            offset |= BITS(bytes, 0, 12);
            offset |= BITS(bytes, 17, 2) << 12;
            offset <<= 2;

            insn.Op1.type = o_near;
            insn.Op1.dtype = dt_dword;
            insn.Op1.addr = insn.ea+4+offset;
            break;
        }
        case MEMEDA_jmpcond:
        {
            int16_t offset = 0;
            offset |= BITS(bytes, 0, 12);
            offset |= BITS(bytes, 17, 2) << 12;
            offset <<= 2;

            insn.Op1.type = o_reg;
            insn.Op1.dtype = dt_dword;
            insn.Op1.reg = BITS(bytes, 30, 2) + GPR_NUM;

            insn.Op2.type = o_near;
            insn.Op2.dtype = dt_dword;
            insn.Op2.addr = insn.ea+4+offset;
            break;
        }
        default:
        {
            // qeprintf("[%#x] error opcode %#x\n", insn.ea, opcode);
            break;
        }
    }
    return insn.size;
}
