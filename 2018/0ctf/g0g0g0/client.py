# -*- coding: utf-8 -*-

from pwn import remote, context
from hashlib import sha256
import string

context.log_level = "debug"

dic = string.ascii_letters+string.digits

r = remote("202.120.7.206", 13337)

line = r.recvline(1)
print line

r.recvuntil("):")

source, target = line.strip("\n").split(" == ")
source = source.split("+")[1].strip(")")
print source
target = target.decode("hex")
print target.encode("hex")

rst = ""
for i in dic:
    for j in dic:
        for k in dic:
            for n in dic:
                item = i + j + k + n
                if sha256(item+source).digest() == target:
                    rst = item

r.send(rst)

r.recvuntil("Input 3 numbers\n")

r.send(open("answer10").read())

r.interactive()
