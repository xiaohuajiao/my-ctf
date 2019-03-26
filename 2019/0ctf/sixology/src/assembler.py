#!/usr/bin/env python
# encoding: utf-8

import argparse
import logging
import os
import random
import struct
import sys

OPCODE_BIT_OFFSET = 12
OPCODES = {
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

Conds = {
        "lt": 0,
        "eq": 1,
        "gt": 2,
}

MAX_BITS = 32

REGS = {}
for i in xrange(32):
    REGS["r%d"%i] = i
REGS["sp"] = 31
REGS["fp"] = 30
REGS["lr"] = 29


CREGS = {}
for i in xrange(4):
    CREGS["p%d" % i] = i

def p32(a):
    assert a >= 0 and a < (1 << 32)
    return struct.pack("<I", a & 0xffffffff)

def p64(a):
    return struct.pack("<Q", a)

def random_bits(bits):
    return random.randint(0, ((1 << MAX_BITS)-1)) & ((1 << bits) - 1)

def split(ins):
    i = ins.strip(" ")
    assert (len(i) > 0)
    tmp = filter(lambda x: len(x)>0, i.split(" ", 1))
    opcode = tmp[0].lower()
    if len(tmp) == 1:
        return opcode, []
    assert len(tmp) > 1
    operands = list(map(lambda x: x.strip(), tmp[1].split(",", 3)))
    return opcode, operands

def out_bins(a, bits=32):
    b = bin(a)[2:]
    b = b.rjust(bits, "0")
    print b

def ins(func):
    def wrap(*args):
        r = func(*args)
        # out_bins(r)
        pack = p64 if any([i in func.__name__
                            for i in ["li"]
                            ]) else p32
        result = pack(r)
        # print result.encode("hex")
        return result
    return wrap

def encode_2regs(opcode, operands):
    assert (opcode < 32)
    assert (len(operands) == 2)
    assert (all(map(lambda x: x in REGS, operands)))

    rd, rs = [REGS[r] for r in operands]
    result = 0
    result |= rd << 27
    result |= rs << 22
    result |= opcode << OPCODE_BIT_OFFSET
    result |= random_bits(12)
    result |= random_bits(5) << 17

    return result


def encode_3regs(opcode, operands):
    assert (opcode < 32)
    assert (len(operands) == 3)
    assert (all(map(lambda x: x in REGS, operands)))

    rd, rs, rt = [REGS[r] for r in operands]
    result = 0
    result |= rd << 27
    result |= rs << 22
    result |= rt << 17
    result |= opcode << OPCODE_BIT_OFFSET
    result |= random_bits(12)

    return result

def encode_4regs(opcode, operands):
    assert (opcode < 32)
    assert (len(operands) == 4)
    assert (all(map(lambda x: x in REGS, operands)))

    rd, rm, rs, rt = [REGS[r] for r in operands]
    result = 0
    result |= rd << 27
    result |= rs << 22
    result |= rt << 17
    result |= opcode << OPCODE_BIT_OFFSET
    result |= rm << 2
    result |= random_bits(2)
    result |= random_bits(5) << 7
    return result

def encode_no_operands(opcode):
    assert (opcode < 32)
    result = 0
    result |= opcode << OPCODE_BIT_OFFSET
    result |= random_bits(OPCODE_BIT_OFFSET)
    result |= random_bits(15) << 17
    return result

@ins
def encode_allocframe(operands):
    assert (len(operands) == 1)

    imm = eval(operands[0])
    result = 0
    result |= OPCODES["allocframe"] << OPCODE_BIT_OFFSET
    result |= (imm >> 12 & 0xfff)
    result |= (imm & 0xfff) << 20
    result |= random_bits(3) << 17
    return result

@ins
def encode_deallocframe(operands=[]):
    return encode_no_operands(OPCODES["deallocframe"])

@ins
def encode_ret(operands=[]):
    return encode_no_operands(OPCODES["ret"])

@ins
def encode_mov(operands=[]):
    return encode_2regs(OPCODES["mov"], operands)

@ins
def encode_exchange(operands=[]):
    return encode_2regs(OPCODES["exchange"], operands)

@ins
def encode_add(operands):
    assert (len(operands) == 3)
    return encode_3regs(OPCODES["add"], operands)

@ins
def encode_sub(operands):
    assert (len(operands) == 3)
    return encode_3regs(OPCODES["sub"], operands)

@ins
def encode_nor(operands):
    assert (len(operands) == 3)
    return encode_3regs(OPCODES["nor"], operands)

@ins
def encode_div(operands):
    assert (len(operands) == 4)
    return encode_4regs(OPCODES["div"], operands)

@ins
def encode_li(operands):
    assert (len(operands) == 2)
    imm = (eval(operands[1]) ^ struct.unpack("<I", "0CTF")[0]) & 0xffffffff

    result = 0
    result |= OPCODES["li"] << OPCODE_BIT_OFFSET
    result |= REGS[operands[0]] << 27
    result |= imm << 32
    result |= random_bits(10) << 17
    result |= random_bits(12)
    return result

@ins
def encode_loop(operands):
    assert (len(operands) == 2)
    assert (operands[1] in REGS)
    offset = operands[0]
    result = 0
    result |= OPCODES["loop"] << OPCODE_BIT_OFFSET
    result |= offset & 0xfff
    result |= ((offset >> 12) & 0x3) << 17
    result |= random_bits(3) << 19
    result |= REGS[operands[1]] << 22
    result |= random_bits(5) << 27
    return result

@ins
def encode_endloop(operands=[]):
    assert (len(operands) == 1)
    result = 0
    result |= OPCODES["endloop"] << OPCODE_BIT_OFFSET
    offset = operands[0]
    result |= (offset & 0x3fff) << 17
    result |= random_bits(12)
    result |= random_bits(1) << 31
    return result

@ins
def encode_jmp(operands):
    assert (len(operands) == 1)
    offset = operands[0]
    result = 0
    result |= OPCODES["jmp"] << OPCODE_BIT_OFFSET
    result |= offset & 0xfff
    result |= ((offset >> 12) & 0x3) << 17
    result |= random_bits(13) << 19
    return result

@ins
def encode_call(operands):
    assert (len(operands) == 1)
    offset = operands[0]
    result = 0
    result |= OPCODES["call"] << OPCODE_BIT_OFFSET
    result |= offset & 0xfff
    result |= ((offset >> 12) & 0x3) << 17
    result |= random_bits(13) << 19
    return result

@ins
def encode_loadRi(operands):
    # load Rd, [Rs+imm]
    assert (len(operands) == 4)
    width = operands[0]
    rd = operands[1]
    rs = operands[2]
    assert  rd in REGS and rs in REGS

    imm = operands[3]
    result = 0
    result |= OPCODES["load"] << OPCODE_BIT_OFFSET
    result |= REGS[rd] << 27
    result |= REGS[rs] << 22
    result |= imm & 0xfff
    result |= (2) << 17
    result |= (width & 3) << 19
    result |= random_bits(1) << 21
    return result

@ins
def encode_loadR(operands):
    # load Rd, [Rs]
    assert (len(operands) == 3)
    width = operands[0]
    rd = operands[1]
    rs = operands[2]
    assert  rd in REGS and rs in REGS
    result = 0
    result |= OPCODES["load"] << OPCODE_BIT_OFFSET
    result |= REGS[rd] << 27
    result |= REGS[rs] << 22
    result |= (1) << 17
    result |= (width & 0x3) << 19
    result |= random_bits(1) << 21
    result |= random_bits(12)
    return result

@ins
def encode_loadI(operands):
    # load Rd, [imm]
    assert (len(operands) == 3)
    width = operands[0]
    rd = operands[1]
    imm = operands[2]
    assert (rd in REGS) and 0 <= imm < ((1<<32)-1)
    result = 0
    result |= OPCODES["load"] << OPCODE_BIT_OFFSET
    result |= REGS[rd] << 27
    result |= imm & 0xfff
    result |= (3) << 17
    result |= (width  & 3) << 19
    result |= random_bits(6) << 21
    return result

@ins
def encode_storeRi(operands):
    # store Rd, [Rs+imm]
    assert (len(operands) == 4)
    width = operands[0]
    rd = operands[1]
    rs = operands[2]
    assert  rd in REGS and rs in REGS
    imm = operands[3]
    result = 0
    result |= OPCODES["store"] << OPCODE_BIT_OFFSET
    result |= REGS[rd] << 27
    result |= REGS[rs] << 22
    result |= imm & 0xfff
    result |= (2) << 17
    result |= (width & 3) << 19
    result |= random_bits(1) << 21
    return result

@ins
def encode_storeR(operands):
    # store Rd, [Rs]
    assert (len(operands) == 3)
    width = operands[0]
    rd = operands[1]
    rs = operands[2]
    assert  rd in REGS and rs in REGS
    result = 0
    result |= OPCODES["store"] << OPCODE_BIT_OFFSET
    result |= REGS[rd] << 27
    result |= REGS[rs] << 22
    result |= (1) << 17
    result |= (width & 3) << 19
    result |= random_bits(1) << 21
    result |= random_bits(12)
    return result

@ins
def encode_storeI(operands):
    # store Rd, [imm]
    assert (len(operands) == 3)
    width = operands[0]
    rd = operands[1]
    assert  rd in REGS
    imm = operands[2]
    result = 0
    result |= OPCODES["store"] << OPCODE_BIT_OFFSET
    result |= REGS[rd] << 27
    result |= imm & 0xfff
    result |= (3) << 17
    result |= (width & 3) << 19
    result |= random_bits(6) << 21
    return result

def _encode_cmp(opcode, operands):
    assert (len(operands) == 4)
    creg = operands[1]
    rs = operands[2]
    rt = operands[3]
    assert (creg in CREGS and rs in REGS and rt in REGS)
    global Conds
    result = 0
    result |= Conds[operands[0]] << 27
    result |= CREGS[operands[1]] << 30
    result |= REGS[operands[2]] << 22
    result |= REGS[operands[3]] << 17
    result |= OPCODES[opcode] << OPCODE_BIT_OFFSET
    result |= random_bits(12)
    return result

@ins
def encode_cmp(operands):
    return _encode_cmp("cmp", operands)

@ins
def encode_lexcmp(operands):
    return _encode_cmp("lexcmp", operands)

@ins
def encode_jmpcond(operands):
    # print operands
    assert (len(operands) == 2)
    assert operands[0] in CREGS
    offset = operands[1]
    result = 0
    result |= OPCODES["jmpcond"] << OPCODE_BIT_OFFSET
    result |= CREGS[operands[0]] << 30
    result |= (offset & 0xfff)
    result |= ((offset >> 12) & 0x3) << 17
    result |= random_bits(11) << 19
    return result

@ins
def encode_switch(operands):
    assert (len(operands) == 3)
    assert operands[0] in REGS and REGS[operands[0]] < 8
    offset = operands[1]
    jtable = operands[2]
    result = 0
    result |= OPCODES["switch"] << OPCODE_BIT_OFFSET
    result |= REGS[operands[0]] << 29
    result |= offset & 0xfff
    result |= (jtable & 0xfff) << 17
    return result


def assemble_ins(opcode, operands):
    handlers = {
        "allocframe": encode_allocframe,
        "deallocframe": encode_deallocframe,
        "loop": encode_loop,
        "add": encode_add,
        "nor": encode_nor,
        "sub": encode_sub,
        "call": encode_call,
        "jmp": encode_jmp,
        "cmp": encode_cmp,
        "endloop": encode_endloop,
        "ret": encode_ret,
        "div": encode_div,
        "switch": encode_switch,
        "lexcmp": encode_lexcmp,
        "li": encode_li,
        "mov": encode_mov,
        "exchange": encode_exchange,
    }

    # print opcode

    code = None
    if opcode.startswith("cmp"):
        opc, cond = opcode.split(".")
        operands.insert(0, cond)
        code = encode_cmp(operands)

    elif opcode.startswith("lexcmp"):
        opc, cond = opcode.split(".")
        operands.insert(0, cond)
        code = encode_lexcmp(operands)

    elif opcode == "jmpcond":
        code = encode_jmpcond(operands)

    elif opcode == "store" or opcode == "load":
        memop = operands[1]

        width = 2
        if memop.startswith("byte ptr"):
            width = 0
            memop = memop[8:].strip()
        elif memop.startswith("word ptr"):
            width = 1
            memop = memop[8:].strip()
        elif memop.startswith("dword ptr"):
            width = 2
            memop = memop[9:].strip()

        assert len(memop) > 2 and memop[0] == "[" and memop[-1] == "]"
        if memop.count("r") == 1:
            if memop.count("+") == 0:
                # load/store Rd, [Rs]
                ops = []
                ops.append(width)
                ops.append(operands[0])
                ops.append(memop[1:-1])
                code = eval("encode_%sR(ops)" % opcode)

            elif memop.count("+") == 1:
                # load/store Rd, [Rs+imm]
                memops_ = memop[1:-1].split("+")
                assert (len(memops_) == 2)
                ops = []
                ops.append(width)
                ops.append(operands[0])
                ops.append(memops_[0])
                ops.append(eval(memops_[1]))
                code = eval("encode_%sRi(ops)" % opcode)

        else:
            # load/store Rd, xx ptr [imm]
            imm = eval(memop[1:-1])
            assert isinstance(imm, int)
            ops = [width, operands[0], imm]
            code = eval("encode_%sI(ops)" % opcode)

    else:
        assert opcode in OPCODES and opcode in handlers
        # print operands
        code = handlers[opcode](operands)

    return code

def get_label(opcode, operands):
    if opcode in ["loop", "jmp", "call", "endloop"]:
        return operands[0]
    elif opcode in ["jmpcond"]:
        return operands[1]
    elif opcode in ["switch"]:
        return operands[1:3]
    return None

def resolve_label(opcode, operands, labels, label, addr):
    #print operands
    #print label
    assert (isinstance(label, str) and label in labels) or all([l in labels for l in label])
    if opcode in ["loop", "jmp", "call", "endloop"]:
        operands[0] = ((labels[label] - addr - ins_length(opcode)) >> 2) & 0xffffffff
    elif opcode in ["jmpcond"]:
        operands[1] = ((labels[label] - addr - ins_length(opcode)) >> 2) & 0xffffffff
    elif opcode in ["switch"]:
        operands[1] = ((labels[label[0]] - addr - ins_length(opcode)) >> 2) & 0xffffffff
        operands[2] = ((labels[label[1]] - addr - ins_length(opcode)) >> 2) & 0xffffffff
    #print operands


def ins_length(opcode):
    if opcode == "li":
        return 8
    return 4

def merge(data):
    a = sorted(data.items(), key=lambda x: x[0])
    i = 0
    while i < len(a)-1:
        if a[i][0] + len(a[i][1]) > a[i+1][0]:
            print "%#x with length %#x overlap with %#x" % (a[i][0], len(a[i][1]), a[i+1][0])
            exit(-1)
        i += 1

    result = ""
    for addr, content in a:
        if len(result) < addr:
            result = result.ljust(addr, "\x00")
        result += content
    return result

def resolve_jmptable(labels, tables):
    # print labels
    for addr, item in tables.items():
        jtable, table = item
        for i in xrange(len(table)):
            label = table[i]
            if not label in labels:
                print "%s label not found definition" % label
                exit(-1)
            table[i] = (labels[label] - (addr+4)) & 0xffffffff

def assemble(asm, base=0):
    labels = {}
    addr = base
    to_resolve = []
    code = ""
    data = {}
    jmp_tables = {}

    for _line in asm.split("\n"):
        line = _line.strip(" ")
        # print line
        if len(line) == 0:
            continue
        if line.startswith("#"):
            continue
        if ":" in line:
            label = line[:line.find(":")]
            if label in labels:
                logging.error("[X] Existed label {}".format(label))
                exit(-1)
            labels[label] = addr
            continue
        if line.startswith("db."):
            d = line[3:]
            print "*"*20, d
            data_addr, content = d.split("=")
            data_addr = eval(data_addr)
            content = ''.join(map(lambda x: chr(eval(x.strip())), filter(lambda x: len(x) > 0, content.split(" "))))
            data[data_addr] = content
            continue

        opcode, operands = split(line)
        label = get_label(opcode, operands)
        if opcode in ["switch"]:
            assert len(operands) == 4
            assert operands[3][0] == '[' and operands[3][-1] == ']'
            table = map(lambda x: x.strip(), operands[3][1:-1].split(","))
            jmp_tables[addr] = [operands[2], table]
            operands = operands[:-1]

        if not label is None:
            print "label: %s (%s)" % (label, line)
            l = ins_length(opcode)
            if isinstance(label, str) and label in labels:
                resolve_label(opcode, operands, labels, label, addr)
            else:
                to_resolve.append((label, opcode, operands, addr))
                code += "\x00" * l
                addr += l
                continue

        ins_code = assemble_ins(opcode, operands)
        addr += len(ins_code)
        code += ins_code

    for ins_addr in jmp_tables:
        table_label, table = jmp_tables[ins_addr]
        print "*"* 20, table_label, table
        table_code = '\x00' * (4 * (len(table) + 1))
        labels[table_label] = len(code)
        code += table_code

    resolve_jmptable(labels, jmp_tables)
    print jmp_tables
    for ins_addr in jmp_tables:
        table_label, table = jmp_tables[ins_addr]
        table_addr = labels[table_label]
        table_code = p32(len(table) ^ 0x46544330)
        print table
        table_code += ''.join([p32(table[i]) for i in xrange(len(table))])
        code = code[:table_addr] + table_code + code[table_addr+len(table_code):]

    for item in to_resolve:
        label, opcode, operands, ins_addr = item
        print "resolve %#x: %s" % (ins_addr, opcode)
        if (isinstance(label, str) and  (not label in labels)) \
                and (isinstance(label, list) and any([l not in labels for l in label])):
            logging.error("[X] label '{}' not found".format(label))
            exit(-1)
        resolve_label(opcode, operands, labels, label, ins_addr)
        ins_code = assemble_ins(opcode, operands)
        code = code[:ins_addr] + ins_code + code[ins_addr+len(ins_code):]

    print "Code: %s" % code.encode("hex")

    data[0] = code
    # print data
    print hex(len(code))
    result = merge(data)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=str, help="Assembly file")
    parser.add_argument("-b", "--base", type=int, default=0, help="Asm base address")
    parser.add_argument("-o", "--output", type=str, default="b.out", help="Asm output")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        logging.error("[X] file '%s' not found".format(args.file))
        exit(-1)
    with open(args.file, 'r') as fd:
        asm = fd.read()
        code = assemble(asm, args.base)
        with open(args.output, 'wb') as fd:
            fd.write(code)
