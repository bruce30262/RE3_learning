#!/usr/bin/env python
# -*- coding: utf-8 -*-

from capstone import *
from capstone.arm import *

CODE = "\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3"

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)

"""
If we want information such as implicit registers read/written or semantic groups
we need to explicitly turn this option on
"""
md.detail = True

for i in md.disasm(CODE, 0x1000):
    if i.id in (ARM_INS_BL, ARM_INS_CMP):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

        if len(i.regs_read) > 0:
            print("\tImplicit registers read: "),
            for r in i.regs_read:
                print("%s " %i.reg_name(r)),
            print

        if len(i.groups) > 0:
            print("\tThis instruction belongs to groups:"),
            for g in i.groups:
                print("%u" %g),
            print
