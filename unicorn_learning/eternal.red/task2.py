#!/usr/bin/env python
# -*- coding: utf-8 -*-

from capstone import *
from unicorn import *
from unicorn.x86_const import *
shellcode = "\xe8\xff\xff\xff\xff\xc0\x5d\x6a\x05\x5b\x29\xdd\x83\xc5\x4e\x89\xe9\x6a\x02\x03\x0c\x24\x5b\x31\xd2\x66\xba\x12\x00\x8b\x39\xc1\xe7\x10\xc1\xef\x10\x81\xe9\xfe\xff\xff\xff\x8b\x45\x00\xc1\xe0\x10\xc1\xe8\x10\x89\xc3\x09\xfb\x21\xf8\xf7\xd0\x21\xd8\x66\x89\x45\x00\x83\xc5\x02\x4a\x85\xd2\x0f\x85\xcf\xff\xff\xff\xec\x37\x75\x5d\x7a\x05\x28\xed\x24\xed\x24\xed\x0b\x88\x7f\xeb\x50\x98\x38\xf9\x5c\x96\x2b\x96\x70\xfe\xc6\xff\xc6\xff\x9f\x32\x1f\x58\x1e\x00\xd3\x80"

ADDRESS = 0x1000000
STACK   = 0x7000000

cs = Cs(CS_ARCH_X86, CS_MODE_32)

def hook_code(mu, address, size, user_data):
    tmp = mu.mem_read(address, size)
    for i in cs.disasm(tmp, address):
        addr, op, opr = i.address, i.mnemonic, i.op_str
        print("{:#x}: {} {}".format(addr, op, opr))
    
    if tmp == "\xcd\x80":
        print("\nCaught int 0x80")
        eax = mu.reg_read(UC_X86_REG_EAX)
        ebx = mu.reg_read(UC_X86_REG_EBX)
        ecx = mu.reg_read(UC_X86_REG_ECX)
        edx = mu.reg_read(UC_X86_REG_EDX)
        print("EAX:{:#x}\nEBX:{:#x}\nECX:{:#x}\nEDX:{:#x}".format(eax, ebx, ecx, edx))
        print(mu.mem_read(ebx, 20).split("\x00")[0])
        print(oct(ecx))

try:
    # create
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    # map code memory
    mu.mem_map(ADDRESS, 1024*1024)
    mu.mem_write(ADDRESS, shellcode)
    # map stack. ESP start from the middle of the stack
    mu.mem_map(STACK, 1024*1024)
    mu.reg_write(UC_X86_REG_ESP, STACK+(1024*1024)/2)
    # add hook
    mu.hook_add(UC_HOOK_CODE, hook_code)
    # start emulation
    mu.emu_start(ADDRESS, ADDRESS+len(shellcode))
except UcError as e:
    print("ERROR: %s" % e)
