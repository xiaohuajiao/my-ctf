#!/usr/bin/env python
# encoding: utf-8

import os
import sys

FLAG = "flag{01d_H34p_ov3rfl0w_st1ll_in_2019_WASM_and_let's_enj0y_the_1st_year_of_WASI}"
FAKE_FLAG = "flag{" + 'X' * (len(FLAG)-6) + "}"
assert len(FLAG) == len(FAKE_FLAG)
key = os.urandom(len(FLAG))
key = "58ed5567f0cc8df81e690990bb105f88d84f4a53ab3d8b33259d508caaa21310c16c346d9f449a2bc80bd8d3a06b27ca794de4ad6a9e1b524b45e436f628259ae529ed2230e561c49b00ac28413705".decode("hex")

def generate_dec_code(flag):
    global key
    assert len(key) == len(flag)

    cipher_flag = ''.join([("\\x%02x" % (ord(flag[i]) ^ ord(key[i]))) for i in xrange(len(flag))])

    key_code = ""
    for i in xrange(len(key)):
        key_code += "    key[%d] = %#02x; \\\n" % (i, ord(key[i]))

    c_code = """
#ifndef STEP2_H
#define STEP2_H

#include <stdint.h>

uint8_t cipher_flag[] = "{flag}";

#define DEC_FLAG2(flag) do {{ \\
    uint8_t key[{length}] = {{0}}; \\
{key_code}    for (uint32_t i = 0; i < {length}; ++i) {{ \\
        flag[i] = cipher_flag[i] ^ key[i]; \\
    }} \\
}} while (0)
#endif
    """.format(flag=cipher_flag, length=len(flag), key_code=key_code)

    open("step2.h", 'w').write(c_code)

def patch_to_release(flag, fake_flag, filename):
    assert len(flag) == len(fake_flag)
    data = open(filename, 'rb').read()
    cipher_flag = ''.join([chr(ord(key[i]) ^ ord(flag[i])) for i in xrange(len(flag))])
    cipher_fake_flag = ''.join([chr(ord(key[i]) ^ ord(fake_flag[i])) for i in xrange(len(flag))])

    print "cipher_flag count:", data.count(cipher_flag)
    assert data.count(cipher_flag) == 1
    pos = data.find(cipher_flag)
    new_data = data[:pos] + cipher_fake_flag + data[pos+len(cipher_fake_flag):]

    open("%s.release" % filename, 'wb').write(new_data)

if __name__ == "__main__":
    print len(FLAG)
    print key.encode("hex")
    if len(sys.argv) == 1:
        generate_dec_code(FLAG)
    elif len(sys.argv) == 2:
        patch_to_release(FLAG, FAKE_FLAG, sys.argv[1])
