#!/usr/bin/env python
# -*- coding: utf-8 -*-
from capstone import *

CODE = "\x55\x48\x8b\x05\xb8\x13\x00\x00"

md = Cs(CS_ARCH_X86, CS_MODE_64)
for (address, size, mnemonic, op_str) in md.disasm_lite(CODE, 0x1000):
    print("0x%x:\t%s\t%s" %(address, mnemonic, op_str))
