#!/usr/bin/env python
# -*- coding: utf-8 -*-

from capstone import *
from unicorn import *
from unicorn.arm_const import *
import struct
import sys

code = ""
with open("./task4", "rb") as f:
    code = f.read()

def u32(data):
    return struct.unpack("I", data)[0]
    
def p32(num):
    return struct.pack("I", num)

cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
BASE = 0x10000
STACK   = 0x7000000
ccc_start = 0x104d0
ccc_end = 0x10580
stack = []
dp = dict()
def hook_code(mu, address, size, user_data):
    global stack, dp
    
    if address == 0x105a8: # printf
        r1 = mu.reg_read(UC_ARM_REG_R1)
        print "ans:", r1
        exit(0)

    if address == ccc_start:
        r0 = mu.reg_read(UC_ARM_REG_R0)
        if r0 in dp:
            mu.reg_write(UC_ARM_REG_R0, dp[r0])
            mu.reg_write(UC_ARM_REG_PC, ccc_end)
        stack.append(r0)

    if address == ccc_end:
        arg0 = stack.pop()
        if arg0 not in dp:
            ans = mu.reg_read(UC_ARM_REG_R0)
            dp[arg0] = ans

try:
    # create
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    # map code memory
    mu.mem_map(BASE, 1024*1024)
    mu.mem_write(BASE, code)
    # map stack. ESP start from the middle of the stack
    mu.mem_map(STACK, 1024*1024)
    mu.reg_write(UC_ARM_REG_SP, STACK+(1024*1024)/2)
    # add hook
    mu.hook_add(UC_HOOK_CODE, hook_code)
    # start emulation
    mu.emu_start(0x10584, 0x105BC) # main start ~ end
except UcError as e:
    print("ERROR: %s" % e)
