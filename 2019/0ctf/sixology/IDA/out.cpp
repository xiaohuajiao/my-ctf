#include "0ctf.hpp"


//----------------------------------------------------------------------
class out_0ctf_t : public outctx_t
{
    out_0ctf_t(void) : outctx_t(BADADDR) {} // not used
    public:
    void outreg(int rn);

    bool out_operand(const op_t &x);
    void out_insn(void);
    void out_proc_mnem(void);
    void out_memop_prefix(const op_t & op);
};
CASSERT(sizeof(out_0ctf_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS(out_0ctf_t)


void out_0ctf_t::outreg(int rn)
{
  const char *regname = (rn < ph.regs_num) ? ph.reg_names[rn] : "42";
  out_register(regname);
}
    //----------------------------------------------------------------------
    /* outputs an operand 'x' */
#ifndef RELEASE
void out_0ctf_t::out_memop_prefix(const op_t & op)
{
    switch (op.dtype)
    {
        case dt_byte:
            out_line("byte ptr ", 0);
            break;
        case dt_word:
            out_line("word ptr ", 0);
            break;
        case dt_dword:
            out_line("dword ptr ", 0);
            break;
    }
}

bool out_0ctf_t::out_operand(const op_t & op)
{
    switch ( op.type )
    {
        case o_imm:
            out_value(op, OOFW_IMM | OOFW_32 | OOF_SIGNED);
            break;

        case o_idpspec1:
        {
            bool r = out_name_expr(op, op.addr+4, BADADDR);
            if (!r)
            {
                out_tagon(COLOR_ERROR);
                out_long(op.addr+4, 16);
                out_tagoff(COLOR_ERROR);
                remember_problem(PR_NONAME, insn.ea);
            }
            break;
        }
        case o_near:
        {
            // msg("%#x: o_near %#x\n", insn.ea, op.addr);
            bool r = out_name_expr(op, op.addr, BADADDR);
            if (!r)
            {
                out_tagon(COLOR_ERROR);
                out_long(op.addr, 16);
                out_tagoff(COLOR_ERROR);
                remember_problem(PR_NONAME, insn.ea);
            }
            break;
        }
        case o_reg:
        {
            outreg(op.reg);
            break;
        }
        case o_mem:
        {
            out_memop_prefix(op);

            out_symbol('[');
            if ( !out_name_expr(op, op.addr, op.addr) )
            {
                out_tagon(COLOR_ERROR);
                out_btoa(uint32(op.addr), 16);
                out_tagoff(COLOR_ERROR);
                remember_problem(PR_NONAME, insn.ea);
            }
            out_symbol(']');
            break;
        }
        case o_phrase:
        {
            out_memop_prefix(op);

            out_symbol('[');
            outreg(op.reg);
            out_symbol(']');
            break;
        }
        case o_displ:
        {
            out_memop_prefix(op);

            out_symbol('[');
            outreg(op.reg);
            out_symbol('+');
            out_value(op, OOF_ADDR | OOFW_IMM);
            out_symbol(']');
            break;
        }
        case o_idpspec0:
        {
            outreg(op.reg);
            out_symbol('=');
            switch (op.specflag1)
            {
                case cLT:
                    out_line("lt");
                    break;
                case cEQ:
                    out_line("eq");
                    break;
                case cGT:
                    out_line("gt");
                    break;
            }
            break;
        }

        default:
            //out_symbol('?');
            break;
    }
    return 1;
}

#else
bool out_0ctf_t::out_operand(const op_t & op)
{
    switch ( op.type )
    {
        case o_imm:
            op_t new_op;
            new_op.type = op.type;
            new_op.dtype = op.dtype;
            new_op.value = op.value ^ 0x66546330;
            out_value(new_op, OOFW_IMM | OOFW_32 | OOF_SIGNED);
            break;
        case o_reg:
            outreg(op.reg);
            break;
        case o_idpspec1:
        {
            // msg("%#x: o_near %#x\n", insn.ea, op.addr);
            bool r = out_name_expr(op, op.addr+4, BADADDR);
            if (!r)
            {
                out_tagon(COLOR_ERROR);
                out_long(op.addr+4, 16);
                out_tagoff(COLOR_ERROR);
                remember_problem(PR_NONAME, insn.ea);
            }
            break;
        }
        case o_near:
        {
            // msg("%#x: o_near %#x\n", insn.ea, op.addr);
            bool r = out_name_expr(op, op.addr, BADADDR);
            if (!r)
            {
                out_tagon(COLOR_ERROR);
                out_long(op.addr, 16);
                out_tagoff(COLOR_ERROR);
                remember_problem(PR_NONAME, insn.ea);
            }
            break;
        }
        default:
        {
            out_printf("op%d", op.n);
        }
    }
    return 1;
}

#endif

//----------------------------------------------------------------------
void out_0ctf_t::out_proc_mnem(void)
{
    out_mnem();
}

//----------------------------------------------------------------------
void out_0ctf_t::out_insn(void)
{
    // msg(" [out]: %#x %s\n", insn.ea, Instructions[insn.itype].name);
    out_mnemonic();
    if ( insn.Op1.type != o_void )
        out_one_operand(0);   // output the first operand

    if ( insn.Op2.type != o_void )
    {
        out_symbol(',');
        out_char(' ');
        out_one_operand(1);   // output the second operand
    }

    if ( insn.Op3.type != o_void )
    {
        out_symbol(',');
        out_char(' ');
        out_one_operand(2);   // output the third operand
    }

    if ( insn.Op4.type != o_void )
    {
        out_symbol(',');
        out_char(' ');
        out_one_operand(3);   // output the 4th operand
    }

    // output a character representation of the immediate values
    // embedded in the instruction as comments
    out_immchar_cmts();
    set_gen_cmt();

    flush_outbuf();
}
