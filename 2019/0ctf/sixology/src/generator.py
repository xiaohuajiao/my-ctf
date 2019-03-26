#!/usr/bin/env python
# encoding: utf-8

import struct
import argparse
from random import randint

flag = "flag{H1gHLigH7_Th3_Cu1tuRe_0f_CN_4nD_wen_TI_OpEN_fl0w3R_Together!}"
#flag = "flag{test}"

N_BASE = 0xb80
K_BASE = 0xca0
TMP_BASE = 0x888
FLAG_BASE = 0x666
KEY_BASE = 0xa00
OFF_BASE = 0xa50

DEBUG = False
#DEBUG = True

def p32(a):
    return struct.pack("<I", a)

def find_k(n, k):
    rest = k - 1

    cur = 1
    while (rest != 0):
        step = 0
        first = cur
        last = cur+1
        while first <= n:
            step += min(n+1, last) - first
            first *= 10
            last *= 10

        if step <= rest:
            cur += 1
            rest -= step
        else:
            cur *= 10
            rest -= 1
    return cur

def rand_n():
    up = 0
    low = 0
    if DEBUG:
        up = 20
        low = 5
    else:
        low = 0xf0000000
        up = 0xffffffff
    return randint(low, up)

def rand_k(n):
    up = 0
    low = 0
    if DEBUG:
        up = n-3
        low = 1
    else:
        low = 0x80000
        up = (n & 0xfffffff) - 0x123
    return randint(low, up)

def init():
    global flag
    code = ""
    ns = []
    ks = []
    results = []
    for i in xrange(len(flag)):
        n = rand_n()
        k = rand_k(n)
        assert k < n

        ns.append(n)
        ks.append(k)
        results.append(find_k(n, k))

    code += "db. %#x=" % N_BASE
    for n in ns:
        code += ' '.join(map(lambda x: "%d" % ord(x), p32(n)))
        code += ' '
    code += "\ndb. %#x=" % K_BASE
    for k in ks:
        code += ' '.join(map(lambda x: "%d" % ord(x), p32(k)))
        code += ' '

    return ns, ks, results, code


def mainloop():
    global flag
    code = """
li r5, 0
li r4, 4
li r7, {flag_length}
li r8, {N_base}
li r9, {K_base}
li r16, {TMP_base}
loop Mainloop, r7
Mainloop:
    add r3, r8, r5
    load r0, dword ptr [r3]
    add r3, r9, r5
    load r1, dword ptr [r3]
    call Count
    add r3, r16, r5
    store r0, dword ptr[r3]
    add r5, r5, r4
endloop Mainloop
    """.format(flag_length=len(flag), N_base=N_BASE, K_base=K_BASE, TMP_base=TMP_BASE)
    return code

def xor(rd, rs, rt, idx=0):
    code = """
nor r0, {rs}, {rs}
nor r1, {rt}, {rt}
nor r0, r0, r1
nor r1, {rs}, {rt}
nor {rd}, r0, r1
    """.format(rd=rd, rs=rs, rt=rt)

    code2 = """
nor r0, {rs}, {rt}
nor r1, {rs}, r0
nor r2, {rt}, r0
nor r3, r1, r2
nor {rd}, r3, r3
    """.format(rd=rd, rs=rs, rt=rt)
    return [code, code2][idx]

def and_(rd, rs, rt):
    code = """
nor r0, {rs}, {rs}
nor r1, {rt}, {rt}
nor {rd}, r0, r1
    """.format(rd=rd, rs=rs, rt=rt)
    return code

def mul_4(rd, rs, idx=0):
    code0 = """
add {rd}, {rs}, {rs}
add {rd}, {rd}, {rd}
    """.format(rd=rd, rs=rs)
    code1 = """
add {rd}, {rs}, {rs}
add {rd}, {rd}, {rs}
add {rd}, {rd}, {rs}
    """.format(rd=rd, rs=rs)
    code2 = """
add {rd}, {rs}, {rs}
add r12, {rs}, {rs}
add {rd}, {rd}, r12
    """.format(rd=rd, rs=rs)
    return [code0, code1, code2][idx]

def print_flag(results):
    global flag
    ff = map(ord, flag)

    code = """
li r7, {flag_length}
li r13, 1
li r16, 3
li r17, {OFF}
li r18, {KEY}
li r19, {TMP}
li r20, {FLAG}
li r21, 0x100
    """.format(flag_length=len(flag), TMP=TMP_BASE, FLAG=FLAG_BASE, OFF=OFF_BASE, KEY=KEY_BASE)
    code += xor("r10", "r10", "r10", 1)
    code += """
loop PRINT, r7
PRINT:
    add r11, r18, r10
    load r29, byte ptr [r11]
    {and_}
    switch r5, DEFAULT, JTABLE, [DEC0, DEC1, DEC2]

DEC0:
    {mul4_0}
    add r11, r19, r11
    load r22, dword ptr [r11]
    div r25, r26, r22, r21
    {xor0}
    add r11, r17, r10
    load r30, byte ptr [r11]
    add r28, r28, r30
    add r11, r20, r10
    store r28, byte ptr [r11]
    jmp PRINT_END

DEC1:
    {mul4_1}
    add r11, r19, r11
    load r22, dword ptr [r11]
    div r25, r26, r22, r21
    {xor1}
    add r11, r17, r10
    load r30, byte ptr [r11]
    add r28, r28, r30
    add r11, r20, r10
    store r28, byte ptr [r11]
    jmp PRINT_END

DEC2:
    {mul4_2}
    add r11, r19, r11
    load r22, dword ptr [r11]
    div r25, r26, r22, r21
    {xor0}
    add r11, r17, r10
    load r30, byte ptr [r11]
    sub r28, r28, r30
    add r11, r20, r10
    store r28, byte ptr [r11]
    jmp PRINT_END

DEFAULT:
    {mul4_0}
    add r11, r19, r11
    load r22, dword ptr [r11]
    div r25, r26, r22, r21
    {xor1}
    add r11, r17, r10
    load r30, byte ptr [r11]
    sub r28, r28, r30
    add r11, r20, r10
    store r28, byte ptr [r11]
    jmp PRINT_END

PRINT_END:
add r10, r10, r13
endloop PRINT
ret
    """.format(and_=and_("r5", "r29", "r16"),
               xor0=xor("r28", "r26", "r29", 0),
               xor1=xor("r28", "r26", "r29", 1),
               mul4_0=mul_4("r11", "r10", 0),
               mul4_1=mul_4("r11", "r10", 1),
               mul4_2=mul_4("r11", "r10", 2)
               )

    keys = []
    offs = []
    for i in xrange(len(results)):
        res = results[i]
        while True:
            key = randint(0, 255)
            tmp = (res & 0xff) ^ key
            op = key & 3
            if op < 2 and ff[i] < tmp:
                continue
            if op >= 2 and ff[i] > tmp:
                continue
            break

        offset = 0
        if ff[i] < tmp:
            offset = tmp - ff[i]
        else:
            offset = ff[i] - tmp

        keys.append(key)
        offs.append(offset)

    code += """
db. {KEY}={keys}
db. {OFF}={offs}
    """.format(KEY=KEY_BASE, OFF=OFF_BASE,
               keys=' '.join(map(str, keys)),
               offs=' '.join(map(lambda x: str(x & 0xff), offs)))
               #offs=' '.join(map(lambda x: str(ord(x)), ''.join(map(p32, offs)))))
    return code

def sort():
    code = """
Count:
    allocframe 0x100
    mov r10, r0
    mov r11, r1
    li r25, 0x2019
    li r23, 0
    li r24, 0
    li r19, 4
    li r18, 1
    loop Init, r0
    Init:
        add r6, r23, r1
        div r14, r15, r6, r0
        add r15, r15, r18
        add r17, r25, r24
        store r15, dword ptr [r17]
        add r23, r23, r18
        add r24, r24, r19
    endloop Init

    li r15, 1
    li r23, 1
    sub r2, r0, r15
    loop First, r2
    First:
        li r24, 0
        li r22, 0
        sub r3, r0, r23
        loop Second, r3
        Second:
            add r26, r25, r22
            load r12, dword ptr [r26]
            add r27, r26, r19
            load r13, dword ptr [r27]
            lexcmp.lt p0, r12, r13
            jmpcond p0, NOEXCHG
            exchange r12, r13
            store r12, dword ptr [r26]
            store r13, dword ptr [r27]
            NOEXCHG:
            add r24, r24, r15
            add r22, r22, r19
        endloop Second
        add r23, r23, r15
    endloop First

    li r24, 0
    cmp.eq p1, r1, r15
    jmpcond p1, FINISH
    sub r2, r1, r15
    loop Result, r2
    Result:
        add r24, r24, r19
    endloop Result

    FINISH:
    add r26, r25, r24
    load r0, dword ptr [r26]
    deallocframe
    ret
    """
    return code

if __name__ == "__main__":
    ns, ks, results, code = init()
    with open("log.txt", 'w') as fd:
        fd.write("-" * 40 + ' n ' + '-' * 40 + '\n')
        for n in ns:
            fd.write("%d\n" % n)
        fd.write("-" * 40 + ' k ' + '-' * 40 + '\n')
        for k in ks:
            fd.write("%d\n" % k)
        fd.write("-" * 40 + ' r ' + '-' * 40 + '\n')
        for r in results:
            fd.write("%d\n" % r)
    code += mainloop()
    code += print_flag(results)
    code += "\njmp END\n"
    code += sort()
    code += """
END:
    mov r0, r20
    """
    print code
    with open("sixology.s", 'w') as fd:
        fd.write(code)
