#include "0ctf.hpp"
#include <map>

#include <frame.hpp>
#include <xref.hpp>

//#include <jumptable.hpp>

extern netnode helper;

bool idaapi oops_is_basic_block_end(const insn_t &insn)
{
    // msg("[%#x] is bbl end\n", insn.ea);

    if ( !is_flow(get_flags(insn.ea+insn.size)) )
        return true;

    xrefblk_t xb;
    for ( bool ok=xb.first_from(insn.ea, XREF_FAR); ok && xb.iscode; ok=xb.next_from() )
    {
        if ( xb.type == fl_JF || xb.type == fl_JN )
        {
            return true;
        }
    }
    return false;
}

bool idaapi create_func_frame(func_t * pfn)
{
    ea_t ea = pfn->start_ea;

    insn_t insn;
    for ( int i = 0; i < 10 && ea < pfn->end_ea; i++ )
    {
        if ( !decode_insn(&insn, ea) )
            break;
        // HINT: allocframe #imm
        if ( insn.itype == MEMEDA_allocframe
                && insn.Op1.type == o_imm)
        {
            pfn->flags |= FUNC_FRAME;
            update_func(pfn);
            // for save LR FP
            return add_frame(pfn, insn.Op1.value, 8, 0);
        }
        ea += insn.size;
    }
    return 0;
}

//----------------------------------------------------------------------
int idaapi oops_get_frame_retsize(const func_t * /*pfn */ )
{
  return 0;
}

// info about a single register
struct ldr_value_info_t
{
    uint32_t value;         // value loaded into the register
    ea_t val_ea;          // where the value comes from (for constant pool or immediate loads)
    eavec_t insn_eas;     // insns that were involved in calculating the value
    char n;               // operand number
    char state;
#define LVI_STATE    0x03 // state mask
#define LVI_UNKNOWN  0x00 // unknown state
#define LVI_VALID    0x01 // value known to be valid
#define LVI_INVALID  0x02 // value known to be invalid
#define LVI_CONST    0x04 // is the value constant? (e.g. immediate or const pool)

    ldr_value_info_t(void)
        : value(0), val_ea(BADADDR), n(0), state(LVI_UNKNOWN)
    {}
    bool is_const(void) const { return (state & LVI_CONST) != 0; }
    bool is_valid(void) const { return (state & LVI_STATE) == LVI_VALID; }
    bool is_known(void) const { return (state & LVI_STATE) != LVI_UNKNOWN; }
    void set_valid(bool valid)
    {
        state &= ~LVI_STATE;
        state |= valid ? LVI_VALID : LVI_INVALID;
    }
    void set_const(void) { state |= LVI_CONST; }
};

//----------------------------------------------------------------------
// helper class for find_op_value/find_ldr_value
// we keep a cache of discovered register values to avoid unnecessary recursion
struct reg_tracker_t
{
    // map cannot store an array directly, so wrap it in a class
    struct reg_values_t
    {
        ldr_value_info_t regs[P3+1]; // values for registers R0 to R60 for a specific ea
    };

    typedef std::map<ea_t, reg_values_t> reg_values_cache_t;

    // we save both valid and invalid values into in the cache.
    reg_values_cache_t regcache;

    // recursive functions; they can call each other, so we limit the nesting level
    bool do_find_op_value(const insn_t &insn, const op_t &x, ldr_value_info_t *lvi, int nest_level);
    bool do_find_ldr_value(const insn_t &insn, ea_t ea, int reg, ldr_value_info_t *p_lvi, int nest_level);
    bool do_calc_complex_value(const insn_t &insn, const op_t &x, ldr_value_info_t *lvi, int nest_level);

    bool is_call_insn(const insn_t &insn) const;

    reg_tracker_t() {}
};

bool reg_tracker_t::is_call_insn(const insn_t &insn) const
{
    switch ( insn.itype )
    {
        case MEMEDA_call:
            return true;
    }
    return false;
}

bool idaapi oops_is_call_insn(const insn_t &insn)
{
    reg_tracker_t tr;
    return tr.is_call_insn(insn);
}

bool reg_tracker_t::do_find_op_value(const insn_t &insn,
        const op_t &x,
        ldr_value_info_t *lvi,
        int nest_level)
{
    switch ( x.type )
    {
        case o_idpspec0:
        case o_reg:
            // msg("[%#x] do_find_op_value %d\n", insn.ea, x.n);
            return do_find_ldr_value(insn, insn.ea, x.reg, lvi, nest_level);
        case o_imm:
            if ( lvi != NULL )
            {
                lvi->value = x.value & 0xFFFFFFFF;
                lvi->set_const();
                lvi->set_valid(true);
                lvi->insn_eas.push_back(insn.ea);
            }
            return true;
        case o_displ:
        case o_phrase:
            {
                ldr_value_info_t val2;
                if ( do_calc_complex_value(insn, x, &val2, nest_level+1) && val2.is_valid() )
                {
                    if ( lvi != NULL )
                    {
                        *lvi = val2;
                        if ( lvi->is_valid() )
                            lvi->insn_eas.push_back(insn.ea);
                    }
                    return true;
                }
            }
            break;
        case o_mem:
            if ( lvi != NULL )
            {
                ea_t value = x.addr;
                ea_t val_ea = BADADDR;
                if ( insn.itype == MEMEDA_load )
                {
                    val_ea = value;
                    value = BADADDR;
                    if ( is_loaded(val_ea) )
                    {
                        switch (insn.Op2.dtype)
                        {
                            // HINT: load Rd, byte ptr [xx]
                            case dt_byte:
                                value = (ea_t)get_byte(val_ea);
                                break;
                                // HINT: load Rd, word ptr [xx]
                            case dt_word:
                                value = (ea_t)get_word(val_ea);
                                break;
                                // HINT: load Rd, dword ptr [xx]
                            case dt_dword:
                                value =  get_dword(val_ea);
                                break;
                            default:
                                value = get_dword(val_ea);
                                break;
                        }
                        lvi->set_const();
                        lvi->set_valid(true);
                        lvi->insn_eas.push_back(insn.ea);
                    }
                }
                lvi->val_ea = uint32(val_ea);
                lvi->value  = uint32(value);
            }
            return true;
    }
    return false;
}

bool reg_tracker_t::do_calc_complex_value(const insn_t &insn, const op_t &x, ldr_value_info_t *lvi, int nest_level)
{
    ldr_value_info_t val1;
    ea_t val_ea = BADADDR;
    uint32_t value = BADADDR;
    bool ok = false;
    if ( do_find_ldr_value(insn, insn.ea, x.reg, &val1, nest_level+1) )
    {
        ldr_value_info_t val2;
        if ( x.type == o_displ )
        {
            ok = true;
            val2.value = (int32)x.addr;
        }
        if ( !ok )
            return false;
        val_ea = val1.value + val2.value;

        switch (insn.Op2.dtype)
        {
            // HINT: load Rd, byte ptr [xx], zero extended
            case dt_byte:
                value = (uint32_t)get_byte(val_ea);
                break;
                // HINT: load Rd, word ptr [xx], zero extended
            case dt_word:
                value = (uint32_t)get_word(val_ea);
                break;
                // HINT: load Rd, dword ptr [xx]
            case dt_dword:
                value =  get_dword(val_ea);
                break;
            default:
                value = get_dword(val_ea);
                break;
        }
    }
    if ( ok && lvi != NULL )
    {
        lvi->value = uint32(value);
        if ( value != BADADDR )
            lvi->set_valid(true);
        lvi->val_ea = uint32(val_ea);
        lvi->n = x.n;
    }
    return ok;
}

static bool spoils(const insn_t &insn, int reg)
{
    switch ( insn.itype )
    {
        case MEMEDA_allocframe:
            if (reg == SP || reg == FP)
                return true;
        case MEMEDA_deallocframe:
            if (reg == SP || reg == FP || reg == LR)
                return true;
        // not sure reg is modified or not after call
        case MEMEDA_call:
            return false;
    }

    uint32 feature = insn.get_canon_feature();
    if ( feature != 0 )
    {
        if ( feature & CF_CHG1 && insn.Op1.is_reg(reg) )
            return true;
        if ( feature & CF_CHG2 && insn.Op2.is_reg(reg) )
            return true;
        if ( feature & CF_CHG3 && insn.Op3.is_reg(reg) )
            return true;
        if ( feature & CF_CHG4 && insn.Op4.is_reg(reg) )
            return true;
    }
    return false;
}

static inline uint32_t my_strcmp(const char *s1, const char *s2, size_t size)
{
    size_t i;
    const char *p = s1;
    const char *q = s2;
    if (!p && !q)
        return 1;
    else if (!p)
        return 0;
    else if (!q)
        return 2;

    for (i = 0; *p != '\x00' && *q != '\x00' && i < size; ++i, p++, q++)
    {
        if (*p < *q)
            return 0;
        else if (*p > *q)
            return 2;
    }

    if (i == size)
        return 1;

    if (*p == '\x00' && *q == '\x00')
        return 1;
    else if (*p != '\x00')
        return 2;
    else
        return 0;
}

//----------------------------------------------------------------------
bool reg_tracker_t::do_find_ldr_value(const insn_t &insn, ea_t ea, int reg, ldr_value_info_t *p_lvi, int nest_level)
{
    if ( nest_level > 200 )
        return false;
    bool ok = false;
    ldr_value_info_t lvi;
    do
    {
        if ( reg >= SA || reg < 0 )
        {
            // not handled
            break;
        }

        // check if it's in the cache
        reg_values_cache_t::iterator regs_it = regcache.find(ea);
        if ( regs_it != regcache.end() )
        {
            const ldr_value_info_t &cached = regs_it->second.regs[reg];
            if ( cached.is_known() )
            {
                ok = lvi.is_valid();
                if ( ok )
                    lvi = cached;
                break;
            }
        }

        const insn_t *pinsn = &insn;
        insn_t curr_insn;
        while ( !ok )
        {
            flags_t F = get_flags(pinsn->ea);
            // try to get immediate prev instruction
            if ( has_xref(F) || !is_flow(F) )
            {
                // count xrefs to the current instruction
                xrefblk_t xb;
                int numxrefs = 0;
                ea_t xref_from = BADADDR;
                for ( bool ok2 = xb.first_to(pinsn->ea, XREF_ALL);
                        ok2 && numxrefs < 2;
                        ok2 = xb.next_to() )
                {
                    if ( xb.iscode && xb.from < pinsn->ea ) // count only xrefs from above
                    {
                        // call xref => bad
                        if ( xb.type == fl_CN || xb.type == fl_CF )
                        {
                            numxrefs = 0;
                            break;
                        }
                        xref_from = xb.from;
                        numxrefs++;
                    }
                }
                // if we have a single xref, use it
                if ( numxrefs != 1 || xref_from == BADADDR || decode_insn(&curr_insn, xref_from) == 0 )
                    break;

            }
            else
            {
                if ( decode_prev_insn(&curr_insn, pinsn->ea) == BADADDR )
                    break;
            }
            pinsn = &curr_insn;

            // msg("insn: %#x  pinsn: %#x\n", insn.ea, pinsn->ea);

            if ( pinsn->Op1.is_reg(reg) || (pinsn->Op1.type == o_idpspec0 && pinsn->Op1.reg == reg) )
            {
                switch ( pinsn->itype )
                {
                    case MEMEDA_load:
                        if ( pinsn->Op2.type == o_mem )
                        {
                            lvi.val_ea = pinsn->Op2.addr;
                            if ( is_loaded(lvi.val_ea) )
                            {
                                ea_t val_ea = lvi.val_ea;
                                switch (insn.Op2.dtype)
                                {
                                    // HINT: load Rd, byte ptr [xx]
                                    case dt_byte:
                                        lvi.value = (uint32_t)get_byte(val_ea);
                                        break;
                                        // HINT: load Rd, word ptr [xx]
                                    case dt_word:
                                        lvi.value = (uint32_t)get_word(val_ea);
                                        break;
                                        // HINT: load Rd, dword ptr [xx]
                                    case dt_dword:
                                        lvi.value =  get_dword(val_ea);
                                        break;
                                    default:
                                        lvi.value = get_dword(val_ea);
                                        break;
                                }
                                lvi.set_const();
                                ok = true;
                            }
                        }
                        else if ( pinsn->Op2.type == o_displ || pinsn->Op2.type == o_phrase )
                        {
                            ok = do_calc_complex_value(*pinsn, pinsn->Op2, &lvi, nest_level+1) && lvi.is_valid();
                        }
                        if ( ok )
                            lvi.insn_eas.push_back(pinsn->ea);
                        break;
                    // HINT: mov Rd, Rs
                    case MEMEDA_mov:
                    case MEMEDA_exchange:
                        ok = do_find_op_value(*pinsn, pinsn->Op2, &lvi, nest_level+1);
                        break;
                    // HINT: li Rd, Imm
                    case MEMEDA_li:
                        {
                            if (pinsn->Op2.type == o_imm)
                            {
                                ok = true;
                                lvi.value = pinsn->Op2.value;
                                lvi.set_const();
                                lvi.insn_eas.push_back(pinsn->ea);
                            }
                        }
                        break;
                    case MEMEDA_add:
                    case MEMEDA_sub:
                    case MEMEDA_div:
                    case MEMEDA_nor:
                    case MEMEDA_cmp:
                    case MEMEDA_lexcmp:
                        {
                            ldr_value_info_t v1;
                            ldr_value_info_t v2;
                            const op_t *op1 = &pinsn->Op2;
                            const op_t *op2 = &pinsn->Op3;
                            if ( pinsn->itype == MEMEDA_div)
                            {
                                op1++; // points to pinsn->Op3
                                op2++; // points to pinsn->Op4
                            }
                            if ( !do_find_op_value(*pinsn, *op1, &v1, nest_level+1) )
                                break;
                            if ( !do_find_op_value(*pinsn, *op2, &v2, nest_level+1) )
                                break;
                            switch ( pinsn->itype )
                            {
                                // HINT: add Rd, Rs, Rt
                                case MEMEDA_add:
                                    lvi.value = v1.value + v2.value;
                                    break;
                                // HINT: sub Rd, Rs, Rt
                                case MEMEDA_sub:
                                    lvi.value = v1.value - v2.value;
                                    break;
                                // HINT: div Rd, Rm, Rs, Rt
                                case MEMEDA_div:
                                    // FAULT here during CTF, Sorry. :(
                                    lvi.value = v1.value / v2.value;
                                    break;
                                // HINT: nor Rd, Rs, Rt
                                case MEMEDA_nor:
                                    lvi.value = ~(v1.value | v2.value);
                                    break;
                                // HINT: cmp Px, Rs, Rt
                                case MEMEDA_cmp:
                                    {
                                        sval_t s_op1 = (sval_t)(v1.value);
                                        sval_t s_op2 = (sval_t)(v2.value);
                                        const op_t *px_op = &pinsn->Op1;
                                        switch (px_op->specflag1)
                                        {
                                            case cLT:
                                                lvi.value = (s_op1 < s_op2)? 1: 0;
                                                break;
                                            case cEQ:
                                                lvi.value = (s_op1 == s_op2)? 1: 0;
                                                break;
                                            case cGT:
                                                lvi.value = (s_op1 > s_op2)? 1: 0;
                                                break;
                                        }
                                    }
                                    break;
                                // HINT: lexcmp Px, Rs, Rt
                                case MEMEDA_lexcmp:
                                    {
                                        #define MAX_INT_LEN (0x100)
                                        char s_op1[MAX_INT_LEN] = {0};
                                        char s_op2[MAX_INT_LEN] = {0};
                                        qsnprintf(s_op1, MAX_INT_LEN-1, "%d", v1.value);
                                        qsnprintf(s_op2, MAX_INT_LEN-1, "%d", v2.value);
                                        uint32_t ret = my_strcmp(s_op1, s_op2, sizeof(s_op1)-1);

                                        // msg("[%#x] strcmp: %s %s => %d\n", pinsn->ea, s_op1, s_op2, ret);

                                        const op_t *px_op = &pinsn->Op1;
                                        switch (px_op->specflag1)
                                        {
                                            case cLT:
                                                lvi.value = (ret == 0)? 1: 0;
                                                break;
                                            case cEQ:
                                                lvi.value = (ret == 1)? 1: 0;
                                                break;
                                            case cGT:
                                                lvi.value = (ret == 2)? 1: 0;
                                                break;
                                        }
                                    }
                                    break;
                            }
                            ok = true;
                            if ( v1.is_const() && v2.is_const() )
                                lvi.set_const();
                            lvi.insn_eas.push_back(pinsn->ea);
                        }
                        break;
                }
            }

            if ( pinsn->Op2.is_reg(reg) )
            {
                switch (pinsn->itype)
                {
                    // HINT: div Rd, Rm, Rs, Rt
                    case MEMEDA_div:
                        {
                            ldr_value_info_t v1;
                            ldr_value_info_t v2;
                            const op_t *op1 = &pinsn->Op3;
                            const op_t *op2 = &pinsn->Op4;

                            if ( !do_find_op_value(*pinsn, *op1, &v1, nest_level+1) )
                                break;
                            if ( !do_find_op_value(*pinsn, *op2, &v2, nest_level+1) )
                                break;

                            // FAULT here during CTF, Sorry... :(
                            lvi.value = v1.value % v2.value;

                            ok = true;
                            if ( v1.is_const() && v2.is_const() )
                                lvi.set_const();
                            lvi.insn_eas.push_back(pinsn->ea);
                        }
                        break;
                    // HINT: exchange Rd, Rs
                    case MEMEDA_exchange:
                        {
                            ok = do_find_op_value(*pinsn, pinsn->Op1, &lvi, nest_level+1);
                        }
                        break;
                }
            }

            if ( spoils(*pinsn, reg) )
                break;
        }
#ifdef __EA64__
        lvi.value &= 0xFFFFFFFF;
#endif
        lvi.set_valid(ok);
        regcache[ea].regs[reg] = lvi;
    }
    while ( false );

    if ( ok && p_lvi != NULL )
        *p_lvi = lvi;
    return ok;
}

//----------------------------------------------------------------------
static bool find_op_value_ex(const insn_t &insn, const op_t &x, ldr_value_info_t *lvi, bool /*check_fbase_reg*/)
{
    reg_tracker_t tr;
    return tr.do_find_op_value(insn, x, lvi, 0);
}

//----------------------------------------------------------------------
// find the value loaded into reg
// static bool find_ldr_value_ex(const insn_t &insn, ea_t ea, int reg, ldr_value_info_t *lvi, bool /*check_fbase_reg*/)
// {
//     reg_tracker_t tr;
//     return tr.do_find_ldr_value(insn, ea, reg, lvi, 0);
// }

//----------------------------------------------------------------------
static bool find_op_value(const insn_t &insn, const op_t &x, uval_t *p_val, ea_t *p_val_ea=NULL, bool check_fbase_reg=true, bool *was_const_load=NULL)
{
    ldr_value_info_t tmp;
    if ( find_op_value_ex(insn, x, &tmp, check_fbase_reg) )
    {
        if ( p_val != NULL )
            *p_val = tmp.value;
        if ( p_val_ea != NULL )
            *p_val_ea = tmp.val_ea;
        if ( was_const_load != NULL )
            *was_const_load = tmp.is_const();
        return true;
    }
    return false;
}

//----------------------------------------------------------------------
// Trace the value of the SP and create an SP change point if the current
// instruction modifies the SP.
static sval_t calc_sp_delta(const insn_t &insn)
{
    // corrected manually
    switch ( insn.itype )
    {
        case MEMEDA_add:
        case MEMEDA_sub:
            if ( insn.Op1.is_reg(SP) && insn.Op2.is_reg(SP) )
            {
                // add sp, sp, r1
                uval_t spofs;
                if ( find_op_value(insn, insn.Op3, &spofs, NULL, false) && (spofs & 3) == 0 )
                    // HINT: sub Rd, Rs, Rt
                    return insn.itype == MEMEDA_sub ? -spofs : spofs;
            }
            break;

        // HINT: allocframe imm
        case MEMEDA_allocframe:
            {
                uval_t delta = insn.Op1.value + 8;
                return -delta;
            }
            break;

        // HINT: deallocframe
        case MEMEDA_deallocframe:
            {
                func_t *pfn = get_func(insn.ea);
                if (pfn == NULL)
                    return 0;
                //asize_t frame_size = get_frame_size(pfn);
                sval_t delta = get_spd(pfn, insn.ea);
                // msg("deallocframe size: %d\n", delta);
                return -delta;
            }
            break;

        default:
            break;
    }
    return 0;
}

//----------------------------------------------------------------------
// Add a SP change point. We assume that SP is always divisible by 4
inline void add_stkpnt(const insn_t &insn, func_t *pfn, sval_t v)
{
    add_auto_stkpnt(pfn, insn.ea+insn.size, v);
}

//----------------------------------------------------------------------
// Trace the value of the SP and create an SP change point if the current
// instruction modifies the SP.
static void trace_sp(const insn_t &insn)
{
    func_t *pfn = get_func(insn.ea);
    if ( pfn == NULL )
        return;                     // no function -> we don't care about SP

    sval_t delta = calc_sp_delta(insn);
    // msg("[%#x] get_spd: %d\n", insn.ea, get_spd(pfn, insn.ea));
    if ( delta != 0 )
    {
        // nodeidx_t cur_delta = helper
        add_stkpnt(insn, pfn, delta);
    }
}

//----------------------------------------------------------------------
static void handle_operand(const insn_t &insn, const op_t & op, bool loading)
{
    switch ( op.type )
    {
        case o_reg:
            break;
        case o_imm:
            {
                set_immd(insn.ea);
                flags_t F = get_flags(insn.ea);
                if ( op_adds_xrefs(F, op.n) )
                {
                    insn.add_off_drefs(op, dr_O, OOFS_IFSIGN);
                }
                break;
            }
        case o_mem:
            {
                ea_t ea = op.addr;
                insn.create_op_data(ea, op);         // create the data item of the correct size
                insn.add_dref(ea, op.offb, loading ? dr_R : dr_W);
                break;
            }
        case o_near:
            {
                bool create = true;
                switch (insn.itype)
                {
                    // HINT: loop label, Rs
                    case MEMEDA_loop:
                        create = false;
                        break;
                    // HINT: endloop label
                    case MEMEDA_endloop:
                        {
                            nodeidx_t count = helper.altval_ea(insn.Op1.addr, LOOP_TAG);
                            // msg("[%#x] endloop count is %d\n", insn.ea, count);
                            if (count == 1)
                                create = false;
                        }
                        break;
                }
                if (create)
                {
                    int iscall = has_insn_feature(insn.itype, CF_CALL);
                    insn.add_cref(op.addr, op.offb, iscall ? fl_CN : fl_JN);
                }
            }
            break;
        // switch Rs, default, jmp_table
        case o_idpspec1:
            {
                if (insn.itype != MEMEDA_switch)
                    goto END;
                switch_info_t si;
                if (!(get_switch_info(&si, insn.ea) > 0))
                {
                    ea_t jmp_table = insn.Op3.addr;
                    uint32_t ncases = get_dword(jmp_table) ^ 0x46544330;
                    if (ncases > 128)
                        goto END;

                    si.flags |= SWI_J32 | SWI_SIGNED | SWI_ELBASE;
                    si.jumps = jmp_table+4;
                    si.startea = insn.ea;
                    si.defjump = insn.Op2.addr;
                    si.set_expr(insn.Op1.reg, dt_dword);
                    si.set_jtable_element_size(4);
                    si.set_shift(0);
                    si.ncases = ncases;
                    si.lowcase = 0;
                    si.elbase = insn.ea+4;

                    set_switch_info(insn.ea, si);
                    create_switch_table(insn.ea, si);
                    create_switch_xrefs(insn.ea, si);
                }
            }
        END:
            break;
    }
}

static bool is_rodata(ea_t ea)
{
    if ( !is_loaded(ea) )
        return false;

    const char *const *names = NULL;
    int ncnt = 1;
    segment_t *seg = getseg(ea);
    if ( seg != NULL )
    {
        qstring segname;
        if ( get_segm_name(&segname, seg) > 0 )
        {
            for ( size_t i = 0; i < ncnt; i++ )
                if ( segname == ".rodata" )
                    return true;
        }
    }

    if ( segtype(ea) == SEG_CODE )
        return true;

    seg = getseg(ea);
    if ( seg != NULL && (seg->perm & (SEGPERM_WRITE|SEGPERM_READ)) == SEGPERM_READ )
        return true;

    return false;
}

//----------------------------------------------------------------------
// Emulate an instruction
int idaapi emu(const insn_t &insn)
{
    // msg(" [emu]: %#x %s\n", insn.ea, Instructions[insn.itype].name);

    uint32 Feature = insn.get_canon_feature();

    if ( Feature & CF_USE1 )
      handle_operand(insn, insn.Op1, true);
    if ( Feature & CF_USE2 )
      handle_operand(insn, insn.Op2, true);
    if ( Feature & CF_USE3 )
      handle_operand(insn, insn.Op3, true);
    if ( Feature & CF_USE4 )
      handle_operand(insn, insn.Op4, true);

    if ( Feature & CF_CHG1 )
      handle_operand(insn, insn.Op1, false);
    if ( Feature & CF_CHG2 )
      handle_operand(insn, insn.Op2, false);
    if ( Feature & CF_CHG3 )
      handle_operand(insn, insn.Op3, false);
    if ( Feature & CF_CHG4 )
      handle_operand(insn, insn.Op4, false);

    switch (insn.itype)
    {
        // HINT: store Rd, [xx]
        case MEMEDA_store:
            {
                uval_t mem_addr = 0;
                op_t x = insn.Op2;
                if (x.type == o_mem)
                {
                    mem_addr = x.addr;
                }
                else
                {
                    x.type = o_reg;
                    if (!find_op_value(insn, x, &mem_addr, NULL, false))
                        break;
                }
                if (insn.Op2.type == o_displ)
                    mem_addr += (int32)(insn.Op2.addr);

                // msg("[%#x] store mem_addr: %#x\n", insn.ea, mem_addr);
                if (is_rodata(mem_addr))
                {
                    char buf[0x100];
                    qsnprintf(buf, 0x100, "[%#08x] read only", mem_addr);
                    set_cmt(insn.ea, buf, true);
                }
            }
        // HINT: loop label, Rs
        case MEMEDA_loop:
            {
                uval_t loop_count = 0;
                find_op_value(insn, insn.Op2, &loop_count, NULL, false);
                helper.altset_ea(insn.Op1.addr, loop_count, LOOP_TAG);
            }
            break;
    }

    bool uncond_jmp = false;
    switch (insn.itype)
    {

        // HINT: jmp label
        case MEMEDA_jmp:
            uncond_jmp = true;
            break;
        // HINT: jmpcond Px, label
        case MEMEDA_jmpcond:
            {
                uval_t px = 0;
                if ( find_op_value(insn, insn.Op1, &px, NULL, false) && px == 1 )
                {
                    uncond_jmp = true;
                }
            }
            break;
    }

    bool flow = ((Feature & CF_STOP) == 0) && (!uncond_jmp);
    if (flow)
    {
        add_cref(insn.ea, insn.ea+insn.size, fl_F);
    }

    // trace the stack pointer if:
    //   - it is the second analysis pass
    //   - the stack pointer tracing is allowed
    if ( may_trace_sp() )
    {
        if ( flow )
            trace_sp(insn);           // trace modification of SP register
        else
            recalc_spd(insn.ea);       // recalculate SP register for the next insn
    }

    return 1;                     // actually the return value is unimportant, but let's it be so
}
