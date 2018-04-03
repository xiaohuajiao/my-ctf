# -*- coding: utf-8 -*-

import string
import signal
import sys
import random
from hashlib import sha256

WAITING_TIME = 60
FLAG_FILE = "/home/gogogo/flag"

N = 10

DEBUG = False

def proof_of_work():
    proof = ''.join([random.choice(string.ascii_letters+string.digits) for _ in xrange(20)])
    digest = sha256(proof).hexdigest()
    sys.stdout.write("sha256(XXXX+%s) == %s\n" % (proof[4:],digest))
    sys.stdout.write('Give me XXXX ([A-Za-z0-9]{4}, please do not ends with "\\n"):')
    sys.stdout.flush()
    x = sys.stdin.read(4)
    if len(x) != 4 or sha256(x+proof[4:]).hexdigest() != digest: 
        exit(0)
    return

def main():
    try:
        signal.alarm(WAITING_TIME)
        proof_of_work()

        user_answer = []

        sys.stdout.write("Input 3 numbers\n")
        sys.stdout.flush()

        # read user input and validate it
        for i in xrange(3):
            data = long(raw_input())
            if data <= 0:
                sys.stdout.write("Only Positive integer\n")
                sys.stdout.flush()
                return
            if data.bit_length() > 640:
                sys.stdout.write("Integer too large\n")
                sys.stdout.flush()
                return

            user_answer.append(data)

        a, b, c = user_answer

        # do check
        result = "Wrong! Try again!!"
        if isinstance(a, long) \
                and isinstance(b, long) \
                and isinstance(c, long) \
                and (a * (a+c) * (a+b) + b * (b+c) * (a+b) + c * (a+c) * (b+c)) == (N * (a+b) * (a+c) * (b+c)):
            fd = open(FLAG_FILE)
            flag = fd.read()
            fd.close()
            result = "Correct! flag is %s" % flag

        sys.stdout.write(result + '\n')
        sys.stdout.flush()

    except:
        pass



if __name__ == "__main__":
    main()
