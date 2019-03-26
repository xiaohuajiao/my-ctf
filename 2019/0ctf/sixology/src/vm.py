#!/usr/bin/env python
# encoding: utf-8

import argparse
import logging
import os
import struct

from ctypes import c_int16

logger = logging.getLogger("vm")
console = logging.StreamHandler()
logger.setLevel(logging.WARNING)
logger.addHandler(console)

SP = 31
FP = 30
LR = 29

def u16(a):
    return struct.unpack("<H", a)[0]

def u32(a):
    return struct.unpack("<I", a)[0]

def us32(a):
    return struct.unpack("<i", a)[0]


def u64(a):
    return struct.unpack("<Q", a)[0]

NameToOpcodes = {
    "allocframe": 2,
    "store": 3,
    "exchange": 4,
    "deallocframe": 5,
    "loop": 7,
    "add": 8,
    "li": 11,
    "nor": 12,
    "sub": 14,
    "mov": 16,
    "call": 17,
    "jmp": 19,
    "cmp": 20,
    "endloop": 23,
    "div": 24,
    "switch": 26,
    "lexcmp": 27,
    "ret": 29,
    "jmpcond": 30,
    "load": 31,
}

OpcodesToNames = {}
for k, v in NameToOpcodes.items():
    OpcodesToNames[v] = k

def get_bits(v, start, bits):
    return (v >> start) & ((1 << bits)-1)

def lexcmp(a, b):
    s_a = str(a)
    s_b = str(b)
    if s_a == s_b:
        return 0
    elif s_a > s_b:
        return 1
    else:
        return -1

class VM:
    def __init__(self, code, base=0):
        self.code = code
        self.base = base
        self.pc = self.base
        self.stack = []
        self.regs = [0] * 32
        self.mem = [0] * 0x10000

        for i in xrange(len(self.code)):
            self.mem[i] = ord(self.code[i])

        self.regs[SP] = len(self.mem)

        self.loops = {}

        self.Preg = [0] * 4

    def dword(self):
        return self.read_dword(self.pc-self.base)

    def qword(self):
        tmp = self.read(self.pc-self.base, 8)
        return (tmp[7] << 56) | (tmp[6] << 48) | (tmp[5] << 40) | (tmp[4] << 32) \
                | (tmp[3] << 24) | (tmp[2] << 16) | (tmp[1] << 8) | tmp[0]

    def rd(self):
        return get_bits(self.dword(), 27, 5)

    def rs(self):
        return get_bits(self.dword(), 22, 5)

    def rt(self):
        return get_bits(self.dword(), 17, 5)

    def read(self, addr, size):
        assert 0 <= addr < len(self.mem)
        assert addr+size <= len(self.mem)
        return self.mem[addr:addr+size]
    def read_byte(self, addr):
        return self.read(addr, 1)[0]
    def read_word(self, addr):
        r = (self.read(addr, 2))
        return (r[1] << 8) | r[0]
    def read_dword(self, addr):
        r = (self.read(addr, 4))
        return (r[3] << 24) | (r[2] << 16) | (r[1] << 8) | r[0]

    def write(self, addr, size, value):
        assert 0 <= addr < len(self.mem)
        assert addr+size <= len(self.mem)
        t = value
        for i in range(size):
            self.mem[addr+i] = t & 0xff
            t >>= 8
    def write_byte(self, addr, value):
        self.write(addr, 1, value)
    def write_word(self, addr, value):
        self.write(addr, 2, value)
    def write_dword(self, addr, value):
        self.write(addr, 4, value)

    def ins_add(self):
        rd = self.rd()
        rs = self.rs()
        rt = self.rt()

        v_rs = self.regs[rs]
        v_rt = self.regs[rt]

        logger.info("[%#x] r%d(%#x) = r%d(%#x) + r%d(%#x)" % (self.pc, rd, v_rs+v_rt, rs, v_rs, rt, v_rt))
        self.regs[rd] = self.regs[rs] + self.regs[rt]
        self.pc += 4

    def ins_sub(self):
        rd = self.rd()
        rs = self.rs()
        rt = self.rt()

        v_rs = self.regs[rs]
        v_rt = self.regs[rt]

        logger.info("[%#x] r%d(%#x) = r%d(%#x) - r%d(%#x)" % (self.pc, rd, v_rs+v_rt, rs, v_rs, rt, v_rt))
        self.regs[rd] = self.regs[rs] - self.regs[rt]
        self.pc += 4

    def ins_div(self):
        rd = self.rd()
        rs = self.rs()
        rt = self.rt()
        rm = get_bits(self.dword(), 2, 5)

        v_rs = self.regs[rs]
        v_rt = self.regs[rt]

        logger.info("[%#x] r%d(%#x), r%d(%#x) = r%d(%#x) / r%d(%#x)" % (self.pc, rd, v_rs/v_rt, rm, v_rs%v_rt, rs, v_rs, rt, v_rt))

        v_rd = self.regs[rs] / self.regs[rt]
        v_rm = self.regs[rs] % self.regs[rt]
        self.regs[rd] = v_rd
        self.regs[rm] = v_rm
        self.pc += 4

    def ins_li(self):
        rd = self.rd()
        imm = (self.qword() >> 32) ^ u32("0CTF")

        logger.info("[%#x] r%d(%#x) = %#x" % (self.pc, rd, self.regs[rd], imm))
        self.regs[rd] = imm
        self.pc += 8

        if rd == 29:
            a = self.regs[26]
            b = self.regs[29]
            print "%#x ^ %#x = %#x" % (a, b, a^b),
        elif rd == 30:
            print " => %#x" % self.regs[28]

    def ins_mov(self):
        rd = self.rd()
        rs = self.rs()
        v_rd = self.regs[rd]
        v_rs = self.regs[rs]

        logger.info("[%#x] r%d(old: %#x) = r%d(%#x)" % (self.pc, rd, v_rd, rs, v_rs))

        self.regs[rd] = v_rs
        self.pc += 4

    def ins_exchange(self):
        rd = self.rd()
        rs = self.rs()
        v_rd = self.regs[rd]
        v_rs = self.regs[rs]

        logger.info("[%#x] exchange r%d(%#x => %#x) <==> r%d(%#x => %#x)" % (self.pc, rd, v_rd, v_rs, rs, v_rs, v_rd))

        self.regs[rd] = v_rs
        self.regs[rs] =  v_rd

        self.pc += 4

    def ins_jmp(self):
        ins = self.dword()
        offset = 0
        offset |= get_bits(ins, 0, 12)
        offset |= get_bits(ins, 17, 2) << 12
        offset <<= 2

        target = self.pc+4+c_int16(offset).value
        logger.info("[%#x] jmp %#x" % (self.pc, target))
        self.pc = target

    def ins_switch(self):
        ins = self.dword()
        default_off = get_bits(ins, 0, 12) << 2
        jtable_off = get_bits(ins, 17, 12) << 2

        rs = get_bits(ins, 29, 3)

        default = self.pc+4+c_int16(default_off).value
        jtable = self.pc+4+c_int16(jtable_off).value

        jtable_cnt = u32(self.code[jtable:jtable+4]) ^ 0x46544330
        table = [(self.pc+4+us32(self.code[jtable+4+i*4:jtable+8+i*4])) for i in xrange(jtable_cnt)]
        # print table

        logger.info("[%#x] switch default: %#x %s" % (self.pc, default, str(table)))
        target = default
        if self.regs[rs] < jtable_cnt:
            target = table[self.regs[rs]]
        self.pc = target

    def ins_call(self):
        ins = self.dword()
        offset = 0
        offset |= get_bits(ins, 0, 12)
        offset |= get_bits(ins, 17, 2) << 12
        offset <<= 2

        target = self.pc+4+c_int16(offset).value
        logger.info("[%#x] call %#x" % (self.pc, target))
        self.regs[LR] = self.pc+4
        self.pc = target

        print "n: %d   k: %d" % (self.regs[0], self.regs[1])

    def ins_nor(self):
        rd = self.rd()
        rs = self.rs()
        rt = self.rt()

        v_rs = self.regs[rs]
        v_rt = self.regs[rt]

        logger.info("[%#x] r%d(%#x) = ~(r%d(%#x) | r%d(%#x))" % (self.pc, rd, ~(v_rs|v_rt), rs, v_rs, rt, v_rt))
        self.regs[rd] = ~(self.regs[rs] | self.regs[rt])
        self.pc += 4

    def ins_ret(self):
        lr = self.regs[LR]

        logger.info("[%#x] ret %#x" % (self.pc, lr))
        self.pc = lr

        for i in xrange(0x20):
            item = ''.join(map(chr, self.mem[0x2019+i*4:0x2019+i*4+4]))
            print u32(item),
        print
        print self.regs[0]
        print '-' * 0x40

    def ins_load(self):
        ins = self.dword()

        rd = self.rd()
        src_type = get_bits(ins, 17, 2)
        src = None
        fmt = ""
        if src_type == 1:
            # load Rd, [Rs]
            rs = self.rs()
            src = self.regs[rs]
            fmt = "r%d(%#x)" % (rs, src)
        elif src_type == 2:
            # load Rd, [Rs]
            rs = self.rs()
            imm = get_bits(ins, 0, 12)
            src = self.regs[rs] + imm
            fmt = "r%d(%#x)+%#x" % (rs, self.regs[rs], imm)
        elif src_type == 3:
            # load Rd, [imm]
            src = get_bits(ins, 0, 12)
            fmt = "%#x" % src
        assert src is not None

        width = 1 << (get_bits(ins, 19, 2))
        value = None
        width_fmt = None
        if width == 1:
            value = self.read_byte(src)
            width_fmt = "byte ptr"
        elif width == 2:
            value = self.read_word(src)
            width_fmt = "word ptr"
        elif width == 4:
            value = self.read_dword(src)
            width_fmt = "dword ptr"
        assert value is not None

        logger.info("[%#x] load r%d(%#x), %s [%s](%#x)" % (self.pc, rd, self.regs[rd], width_fmt, fmt, value))

        self.regs[rd] = value
        self.pc += 4

    def ins_store(self):
        ins = self.dword()

        rd = self.rd()
        value = self.regs[rd]
        src_type = get_bits(ins, 17, 2)
        src = None
        fmt = ""
        if src_type == 1:
            # store Rd, [Rs]
            rs = self.rs()
            src = self.regs[rs]
            fmt = "r%d(%#x)" % (rs, src)
        elif src_type == 2:
            # store Rd, [Rs]
            rs = self.rs()
            imm = get_bits(ins, 0, 12)
            src = self.regs[rs] + imm
            fmt = "r%d(%#x)+%#x" % (rs, self.regs[rs], imm)
        elif src_type == 3:
            # store Rd, [imm]
            src = get_bits(ins, 0, 12)
            fmt = "%#x" % imm
        assert src is not None

        width = 1 << (get_bits(ins, 19, 2))
        width_fmt = None
        if width == 1:
            self.write_byte(src, value)
            width_fmt = "byte ptr"
        elif width == 2:
            self.write_word(src, value)
            width_fmt = "word ptr"
        elif width == 4:
            self.write_dword(src, value)
            width_fmt = "dword ptr"

        logger.info("[%#x] store r%d(%#x), %s [%s]" % (self.pc, rd, self.regs[rd], width_fmt, fmt))

        self.pc += 4

    def ins_allocframe(self):
        self.regs[SP] -= 8
        self.write_dword(self.regs[SP]+4, self.regs[LR])
        self.write_dword(self.regs[SP], self.regs[FP])
        self.regs[FP] = self.regs[SP]
        ins = self.dword()
        imm = 0
        imm |= get_bits(ins, 0, 12)
        imm = (imm << 12) | get_bits(ins, 20, 12)
        assert self.regs[SP] >= imm
        self.regs[SP] -= imm

        logger.info("[%#x] allocframe (%#x)" % (self.pc, imm))
        self.pc += 4

    def ins_deallocframe(self):
        ea = self.regs[FP]
        self.regs[LR] = self.read_dword(ea+4)
        self.regs[FP] = self.read_dword(ea)
        self.regs[SP] = ea + 8
        logger.info("[%#x] deallocframe" % self.pc)
        self.pc += 4

    def ins_jmpcond(self):
        ins = self.dword()

        offset = 0
        offset |= get_bits(ins, 0, 12)
        offset |= get_bits(ins, 17, 2) << 12
        offset <<= 2

        target = self.pc + 4 + c_int16(offset).value
        px = get_bits(ins, 30, 2)
        cond = self.Preg[px]

        logger.info("[%#x] jmpcond P%d(%d) %#x" % (self.pc, px, cond, target))

        if cond:
            self.pc = target
        else:
            self.pc += 4

    def ins_lexcmp(self):
        ins = self.dword()
        cond = get_bits(ins, 27, 2)
        px = get_bits(ins, 30, 2)
        rs = self.rs()
        rt = self.rt()

        v_rs = self.regs[rs]
        v_rt = self.regs[rt]

        fmt = None
        if cond == 0:
            # lt
            self.Preg[px] = 1 if lexcmp(v_rs, v_rt) == -1 else 0
            fmt = "lt"
        elif cond == 1:
            # eq
            self.Preg[px] = 1 if lexcmp(v_rs, v_rt) == 0 else 0
            fmt = "eq"
        elif cond == 2:
            # gt
            self.Preg[px] = 1 if lexcmp(v_rs, v_rt) == 1 else 0
            fmt = "gt"

        logger.info("[%#x] lexcmp.%s P%d(%d) r%d(%#x) r%d(%#x)" % (self.pc, fmt, px, self.Preg[px], rs, v_rs, rt, v_rt))
        self.pc += 4

    def ins_cmp(self):
        ins = self.dword()
        cond = get_bits(ins, 27, 2)
        px = get_bits(ins, 30, 2)
        rs = self.rs()
        rt = self.rt()

        v_rs = self.regs[rs]
        v_rt = self.regs[rt]

        fmt = None
        if cond == 0:
            # lt
            self.Preg[px] = 1 if v_rs < v_rt else 0
            fmt = "lt"
        elif cond == 1:
            # eq
            self.Preg[px] = 1 if v_rs == v_rt else 0
            fmt = "eq"
        elif cond == 2:
            # gt
            self.Preg[px] = 1 if v_rs > v_rt else 0
            fmt = "gt"

        logger.info("[%#x] cmp.%s P%d(%d) r%d(%#x) r%d(%#x)" % (self.pc, fmt, px, self.Preg[px], rs, v_rs, rt, v_rt))
        self.pc += 4

    def ins_loop(self):
        ins = self.dword()
        offset = get_bits(ins, 0, 12)
        offset |= get_bits(ins, 17, 2) << 12
        offset <<= 2

        rs = self.rs()
        count = self.regs[rs]

        sa = self.pc+4+c_int16(offset).value
        self.loops[sa] = count

        logger.info("[%#x] loop %#x, r%d(%#x)" % (self.pc, sa, rs, count))

        self.pc += 4

    def ins_endloop(self):
        ins = self.dword()
        offset = get_bits(ins, 17, 14)
        offset <<= 2

        sa = self.pc + 4 + c_int16(offset).value
        lc = self.loops[sa]

        logger.info("[%#x] endloop => %#x" % (self.pc, sa if lc > 1 else self.pc+4))
        if lc > 1:
            self.pc = sa
            self.loops[sa] -= 1
        else:
            self.pc += 4

    def run(self):
        while (self.pc-self.base) < len(self.code):
            ins = self.dword()
            opcode = get_bits(ins, 12, 5)
            try:
                # print struct.pack("<I", ins).encode("hex")
                opcode_name = OpcodesToNames[opcode]
                # print opcode_name
                eval("self.ins_%s()" % opcode_name)
            except Exception as e:
                import traceback
                traceback.print_exc()
                logger.error("[X] Exception occur when run ins: %s".format(opcode_name))
                break

        flag = ''.join(map(chr, self.mem[0x666:0x666+80]))
        print flag
        print flag.encode("hex")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=str, help="Code file")
    parser.add_argument("-b", "--base", type=int, default=0, help="Asm base address")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        logger.error("[X] file '%s' not found".format(args.file))
        exit(-1)
    with open(args.file, 'rb') as fd:
        code = fd.read()
        vm = VM(code, args.base)
        vm.run()
