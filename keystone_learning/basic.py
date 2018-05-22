#!/usr/bin/python

from keystone import *

# separate assembly instructions by ; or \n
CODE = '''
inc ecx;
dec edx
'''

try:
    # Initialize engine in X86-32bit mode
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, count = ks.asm(CODE)
    print("%s = %s (number of statements: %u)" %(CODE, encoding, count))
except KsError as e:
    print("ERROR: %s" %e)

