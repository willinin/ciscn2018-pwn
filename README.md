# ciscn2018-pwn

划划水吧，在假装很认真地做毕设（打游戏），看了2题，magic还行，就是`_IO_FILE`结构体的操作。调式偏移要吐了。

house_of_grey比较有趣，能够读写任意文件的时候，读/proc/self/maps,写/proc/self/mem。
但这里没有任意写，也搞了个seccomp,于是利用栈溢出+rop。坑点在于clone函数后子进程栈的随机化。
我们大概每次能读20*100000 约等于0x200000个字节，但栈空间的随机范围在0xf000000-0xff00000。
理论上讲都是是8分之一的成功率，但是这种事情经常是20次只成功一次，看脸吧。

后面的题毕业后补吧！！

