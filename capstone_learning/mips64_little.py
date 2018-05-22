#!/usr/bin/env python
# -*- coding: utf-8 -*-

from capstone import *

CODE = "\x56\x34\x21\x34\xc2\x17\x01\x00"

md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN)
for i in md.disasm(CODE, 0x1000):
    print("%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
