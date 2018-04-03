#!/usr/bin/env python
# encoding: utf-8

from sage.all import *

N = 10

c1 = 4 * (N**2) + 12 * N - 3
c2 = 32 * (N+3)

E = EllipticCurve([0, c1, 0, c2, 0])

def get_abc(P):
    x = P[0]
    y = P[1]
    a = (8 * (N+3) - x + y) / (2 * (4 - x) * (N + 3))
    b = (8 * (N+3) - x - y) / (2 * (4 - x) * (N + 3))
    c = (-4 * (N+3) - (N+2) * x) / ((4 - x) * (N + 3))

    da = denominator(a)
    db = denominator(b)
    dc = denominator(c)
    l = lcm(da,lcm(db,dc))
    return [a*l, b*l, c*l]

def find_positive_int():
    result = E.integral_x_coords_in_interval(-1000, 1000)

    print result

    for x in result:
        if x != 0:
            y_ = var('y')
            ys = list(solve([y_**2 == x**3 + c1 * x**2 + c2 * x], y_))
            y = int(ys[0].right())

            P = E(x, y)
            for i in xrange(1, 200):
                nP = i * P
                if nP[0] == 4:
                    continue
                a, b, c = get_abc(nP)
                if a > 0 and b > 0 and c > 0 and verify(a, b, c):
                    print "-----------------------  Found it ---------------------"
                    print a, b, c
                    # print i * P

def verify(a, b, c):
    t1 = a / (b + c)
    t2 = b / (a + c)
    t3 = c / (a + b)

    return (t1 + t2 + t3) == N

find_positive_int()
