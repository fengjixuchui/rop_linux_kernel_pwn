#!/usr/bin/env python
#coding:utf-8

rax = 0xffffffffa0002340
with open('xchg_eax_esp_addr.txt') as f:
    for line in f:
        data = line.split(':')
        addr = int(data[0].strip(),16)
        if addr % 8 ==0:
            #这里是负数，因此要转换为无符号数
            index = (addr-rax + 2**64)/8
            print('gadgets:{}'.format(line))
            print('gadgets addr:{}'.format(hex(addr)))
            print('array index:{}'.format(index))
            stack_new = addr & 0xffffffff
            print('stack new addr:{}'.format(hex(stack_new)))

            break
