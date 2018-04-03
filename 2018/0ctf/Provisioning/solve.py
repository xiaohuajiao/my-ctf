#!/usr/bin/env python
# encoding: utf-8

import sys

from scapy.all import *

recvbuf = [0] * 0x100
recvbuf_len = 0

def crc(buf, length):
    return 0

def decode(buf):
    global recvbuf
    global recvbuf_len
    for i in xrange(2, 10, 2):
        if not buf[i] - 1 +  buf[i+1] - 1 == 0xf:
            return

    # print "try to decode: ", buf[:10]
    idx = ((buf[4]-1) << 4) | ((buf[2]-1) & 0xf)
    content = ((buf[8]-1) << 4) | ((buf[6]-1) & 0xf)

    print "buf[%#x] = %#x" % (idx, content)

    if idx <= 0x59:
        if recvbuf[idx] != content:
            recvbuf[idx] = content
            if recvbuf_len < idx:
                recvbuf_len = idx
            return 4
        else:
            if recvbuf_len < 3:
                recvbuf[idx] = content
                if recvbuf_len < idx:
                    recvbuf_len = idx
                return 4
            else:
                if crc(recvbuf, recvbuf_len) == recvbuf[recvbuf_len]:
                    return 0
                return 63
    else:
        return -1

onbyte = [0] * 100
onbyte_idx = 0
status = 1

def analyze(length):
    global status
    global onbyte, onbyte_idx
    if length > 0x10:
        return
    if status == 1:
        if length == 0:
            status = 2
            onbyte_idx = 1
            onbyte[0] = 0
            return
    elif status == 2:
        if length != 0:
            status = 1
            onbyte_idx = 0
        elif length == 0:
            onbyte[onbyte_idx] = 0
            onbyte_idx += 1
            status = 4
    elif status == 4:
        if length != 0:
            onbyte[onbyte_idx] = length
            onbyte_idx += 1
        elif length == 0:
            status = 2
            onbyte_idx = 1
            onbyte[0] = 0

    if onbyte_idx > 9:
        ret = decode(onbyte)
        status = 1
        onbyte_idx = 0

def main():
    from IPython import embed
    pp = rdpcap(sys.argv[1])
    rst  = []
    cs = []
    for p in pp:
        if p.type == 2 and p.subtype == 0 and p[Dot11].addr2 == "dc:ef:09:d0:5a:f1":
            data = str(p[Dot11])
            if ord(data[1]) & 2 == 2:
                rst.append(data)
                cs.append(len(data)-80)

    for i in cs:
        analyze(i)
    # embed()
    print ''.join(map(chr, recvbuf))

main()
