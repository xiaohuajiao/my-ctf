# -*- coding: utf-8 -*-

from generate_step2 import FLAG

server = "wasabi"
release = server + ".release"

a = open(server, "rb").read()
b = open(release, 'rb').read()

start = 0x617c1
end = start + len(FLAG)

cnt = 0
assert len(a) == len(b)
for i in xrange(len(a)):
    if a[i] != b[i]:
        #print hex(i)
        assert start <= i <= end
        cnt += 1

if cnt > 0:
    print "!!!!!!!!!!! GOOD  !!!!!!!!!!!!!!!"
