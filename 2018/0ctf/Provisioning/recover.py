# -*- coding: utf-8 -*-

from idaapi import *
from idc import *
import struct

u32 = lambda x: struct.unpack("<I", x)[0]

BASE = 0x3ffe8000
# rebase program
def rebase():
    rebase_program(BASE - get_imagebase(), MSF_FIXONCE)
    return BASE

# find functions
def disasm_funcs(start_ea, end_ea):
    MakeUnknown(start_ea, end_ea-start_ea, DOUNK_SIMPLE)
    print "%#x ~ %x" % (start_ea, end_ea)
    ea = start_ea
    while ea < end_ea:
        if not isUnknown(GetFlags(ea)):
            ea += ItemSize(ea)
            continue

        # if ea is not align to 4, do alignment first
        if ea % 4 != 0:
            ea = (ea / 4 + 1) * 4

        if not isUnknown(GetFlags(ea)):
            ea += ItemSize(ea)
            continue

        dword = Dword(ea)
        # default observation
        # for each function, there is a const table before the prologue
        if dword & 0xff000000 in [0x40000000, 0x3f000000]:
            MakeData(ea, FF_DWRD, 4, 0)
            ea += 4
        else:
            # try to make code
            ret = MakeCode(ea)
            if ret == 0:
                # make Code failed, set this dword to data
                MakeData(ea, FF_DWRD, 4, 0)
                ea += 4
            else:
                # try to find if it is correct disassemble result
                tmp_start = ea
                tmp_ea = ea
                last_ins = ""
                while True:
                    # one MakeCode operation may not analyze until the non-code part
                    while isCode(GetFlags(tmp_ea)):
                        last_ins = GetMnem(tmp_ea)
                        tmp_ea += ItemSize(tmp_ea)
                    if last_ins.startswith("ret"):
                        break
                    ret = MakeCode(tmp_ea)
                    if ret == 0:
                        break
                tmp_end = tmp_ea

                # check if last_ins is return or jump instruction
                if any(map(last_ins.startswith, ["ret", "j"])):
                    # yes, it is a complete function
                    MakeFunction(tmp_start, BADADDR)
                    ea = tmp_end
                else:
                    # false positive of MakeCode, rollback and make it to data
                    MakeUnknown(tmp_start, tmp_end-tmp_start, DOUNK_SIMPLE)
                    MakeData(ea, FF_DWRD, 4, 0)
                    ea += 4



def main():
    base = rebase()

    start_ea = base + 0x258000
    end_ea = base + 0x27a0b0
    disasm_funcs(start_ea, end_ea)

    start_ea = base + 0x118000
    end_ea = base + 0x11db2e
    disasm_funcs(start_ea, end_ea)


if __name__ == "__main__":
    autoWait()
    main()
