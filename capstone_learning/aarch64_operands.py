#!/usr/bin/env python
# -*- coding: utf-8 -*-

from capstone import *
from capstone.arm64 import *

CODE = "\xe1\x0b\x40\xb9\x20\x04\x81\xda\x20\x08\x02\x8b"

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

for insn in md.disasm(CODE, 0x38):
    print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))

    if len(insn.operands) > 0:
        print("\tNumber of operands: %u" %len(insn.operands))
        c = -1
        for i in insn.operands:
            c += 1
            if i.type == ARM64_OP_REG:
                print("\t\toperands[%u].type: REG = %s" %(c, insn.reg_name(i.value.reg)))
            if i.type == ARM64_OP_IMM:
                print("\t\toperands[%u].type: IMM = 0x%x" %(c, i.value.imm))
            if i.type == ARM64_OP_CIMM:
                print("\t\toperands[%u].type: C-IMM = %u" %(c, i.value.imm))
            if i.type == ARM64_OP_FP:
                print("\t\toperands[%u].type: FP = %f" %(c, i.value.fp))
            if i.type == ARM64_OP_MEM:
                print("\t\toperands[%u].type: MEM" %c)
                if i.value.mem.base != 0:
                    print("\t\t\toperands[%u].mem.base: REG = %s" \
                        %(c, insn.reg_name(i.value.mem.base)))
                if i.value.mem.index != 0:
                    print("\t\t\toperands[%u].mem.index: REG = %s" \
                        %(c, insn.reg_name(i.value.mem.index)))
                if i.value.mem.disp != 0:
                    print("\t\t\toperands[%u].mem.disp: 0x%x" \
                        %(c, i.value.mem.disp))

            if i.shift.type != ARM64_SFT_INVALID and i.shift.value:
             print("\t\t\tShift: type = %u, value = %u" \
                    %(i.shift.type, i.shift.value))

            if i.ext != ARM64_EXT_INVALID:
             print("\t\t\tExt: %u" %i.ext)

    if insn.writeback:
        print("\tWrite-back: True")
    if not insn.cc in [ARM64_CC_AL, ARM64_CC_INVALID]:
        print("\tCode condition: %u" %insn.cc)
    if insn.update_flags:
        print("\tUpdate-flags: True")
