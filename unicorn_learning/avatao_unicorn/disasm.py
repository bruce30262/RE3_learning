from capstone import *
 
CODE = b"\x48\x41\x81\xF9\xBE\x1F\x00\x00\x75\xF6"

md = Cs(CS_ARCH_X86, CS_MODE_32)
for i in md.disasm(CODE, 0):
    print("%s\t%s" %(i.mnemonic, i.op_str))
