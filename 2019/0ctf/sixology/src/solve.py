# -*- coding: utf-8 -*-

import struct

# flag{H1gHLigH7_Th3_Cu1tuRe_0f_CN_4nD_wen_TI_OpEN_fl0w3R_Together!}

def u32(a):
    return struct.unpack("<I", a)[0]

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

def init():
    ns = []
    ks = []

    data = open("binary", 'rb').read()
    flag_length = 66
    n_base = 0xb80
    ns = [u32(data[n_base+i*4:n_base+i*4+4]) for i in xrange(flag_length)]
    k_base = 0xca0
    ks = [u32(data[k_base+i*4:k_base+i*4+4]) for i in xrange(flag_length)]
    key_base = 0xa00
    keys = map(ord, data[key_base:key_base+flag_length])
    off_base = 0xa50
    offs = map(ord, data[off_base:off_base+flag_length])
    return ns, ks, keys, offs

def decode(ns, ks, keys, offs):
    flag = ""
    for i in xrange(len(ns)):
        tmp = find_k(ns[i], ks[i])
        t = (tmp & 0xff) ^ keys[i]
        op = keys[i] & 3
        if op < 2:
            flag += chr(t+offs[i])
        else:
            flag += chr((t-offs[i]) & 0xff)
    return flag

ns, ks, keys, offs = init()
print decode(ns, ks, keys, offs)
