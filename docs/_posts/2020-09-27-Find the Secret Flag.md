---
title: "Find the Secret Flag"
style: border
color: primary
comments: true
description: hackthebox reverse engineering challenge
tags: RE
---
079

Hi there, today, we will go over our first reverse engineering challenge.

What is reverse engineering? It is basically going through a program and analyzing it to understand the process
or even manipulate it at the binary level.

In CTFs, you are required to capture the flag (```CTF```) within the program.

This tutorial will show you how reverse engineering works in CTFs.

You can find the challenge at https://www.hackthebox.eu/home/challenges/Reversing

**I can post this write-up because the challenge is retired, or less I will be banned from the server. To solve this challenge by yourself, you have to become a VIP member of hackthebox.eu**.

First we unzip the zip file and we get a binary(executable) file ```secret_flag.bin```.

We add executable privilege in Linux by
 ```
 chmod +x secret_flag.bin
 ```
Then we analyze it. We use various tools to analyze a program such as Ghidra, IDA, Radare2, GDB. Today, we will use IDA.

As soon as we load the code, we see this:
![First disassembled code](https://raw.githubusercontent.com/079035/079035.github.io/master/images/find%20the%20secret%20flag/1.PNG) (start)

This is an assembly code.
Any code that has been written in any language is compiled into assembly code.
For example, ```mov rdx, rsp``` moves the value of rsp to rdx and ```push rax``` pushes the value of rax into the stack.
If you don't know what these instructions mean, I recommend taking online courses about assembly language and registers.

Back to the code, we see that the code is calling ```___libc_start_main``` at the end.
We follow the code and we arrive at the main function:

![main](https://raw.githubusercontent.com/079035/079035.github.io/master/images/find%20the%20secret%20flag/2.PNG) (main)

We scroll down and see the following code:
![subroutine 1](https://raw.githubusercontent.com/079035/079035.github.io/master/images/find%20the%20secret%20flag/3.PNG) (subroutine 1)

I don't see anything interesting thing here, and since the diverged code eventually merges in loc_40098A, let's move on where it's calling sub_4009AA.
![sub_4009AA](https://raw.githubusercontent.com/079035/079035.github.io/master/images/find%20the%20secret%20flag/4.PNG) (sub_4009AA)

We find that it is calling ```_fopen``` to open ```/tmp/secret``` file with ```rb```(read as binary) privileges.
At this point, I can tell that the program was coded with C or C++, because fopen is from C.

Successfully opening the file at ```/tmp/secret``` will allow the code to flow to ```loc_4009D6```.
I wrote arbitrary data into the file ```/tmp/secret```.

After multiple trials, I found out that the value of EAX after call to ```fread``` represents number of bytes read from the file.

Anyway, after reading ```secret```, the sub routine calls ```_strcmp``` and compares two strings: s2, and s1.
s2 points at **"VerySuperSeKretKey"** and s1 is the content of ```secret```.
![strcmp](https://raw.githubusercontent.com/079035/079035.github.io/master/images/find%20the%20secret%20flag/6.PNG) (loc_4009D6)

A successful comparison between strings, meaning if two strings are not equal, we are directed to loc_400A2D.
Because ```jnz short loc_400A2D``` requires ZF to be zero(not equal).(http://faydoc.tripod.com/cpu/jnz.htm)
![loc_400A2D](https://raw.githubusercontent.com/079035/079035.github.io/master/images/find%20the%20secret%20flag/5.PNG) (loc_400A2D)

We see these four code blocks that compare each 4 byte from ```secret```. It's now clear that the file has to
contain four chars that are **0DEh, 0ADh, oBEH, and 0EFh**.

To insert hex data into a file, we use ```hexeditor```.

![hexeditor](https://raw.githubusercontent.com/079035/079035.github.io/master/images/find%20the%20secret%20flag/8.PNG) (hex patch)

Successfully going through the four code blocks, it assigns EAX a value of 1 and returns back to the main function.
With ```eax``` being 1, it EIP flows into the following code block:

![main after sub_4009AA](https://raw.githubusercontent.com/079035/079035.github.io/master/images/find%20the%20secret%20flag/9.png) (back to main after calling sub_4009AA)

Then it calls ```sub_400A5B```.
![sub_400A5B](https://raw.githubusercontent.com/079035/079035.github.io/master/images/find%20the%20secret%20flag/10.PNG)
![sub_400A5B Continued](https://raw.githubusercontent.com/079035/079035.github.io/master/images/find%20the%20secret%20flag/11.PNG) (Overveiw of sub_400A5B)

We notice that the subroutine is calling ```printf```.
We go back to terminal and see if it prints anything.
![terminal view](https://raw.githubusercontent.com/079035/079035.github.io/master/images/find%20the%20secret%20flag/12.PNG)

Ok... so it prints something but I'm not sure what it means, and every time I run the program, it is giving me different values.
![print result](https://raw.githubusercontent.com/079035/079035.github.io/master/images/find%20the%20secret%20flag/13.PNG)

I couldn't find any piece of code that generates these strings, so I switched to text view with a surprise.
![text view - 400AFE](https://raw.githubusercontent.com/079035/079035.github.io/master/images/find%20the%20secret%20flag/14.PNG) (text view)

I found this piece of red code that has never been "called".
We can conclude that this is a "hidden procedure" as it includes a strange string at the beginning of the block.

Since I want the code to flow into 400AFE, I patched the return instruction at 400AFC and 400AFD into two NOPs(90 in opcode) so it won't return to the main but instead will flow into the hidden procedure.
![patched code](https://raw.githubusercontent.com/079035/079035.github.io/master/images/find%20the%20secret%20flag/15.PNG)

Then, I patched the call instruction to ```sub_400A58``` into ```call sub_400AFE```, so instead of going into ```sub_400A58```, it will go directly into ```sub_400AFE```.

![patched call to 400AFE](https://raw.githubusercontent.com/079035/079035.github.io/master/images/find%20the%20secret%20flag/16.PNG)

This is the overview of the hidden procedure:
![sub_400AFE - 1](https://raw.githubusercontent.com/079035/079035.github.io/master/images/find%20the%20secret%20flag/17.PNG)
![sub_400AFE - 2](https://raw.githubusercontent.com/079035/079035.github.io/master/images/find%20the%20secret%20flag/19.PNG)

We are interested in the second image.

We are going to name ```loc_400B7B``` as block 1, block right below as 2, ```loc_400B58``` as 3, and ```loc_400B95``` as 4.

This is a cycle.
* _Block1_ checks for a specific char inside a string, although not sure what char it is comparing to.
* _Block2_ checks how many chars have been processed and ends the cycle after ```17h```(23 in decimal) chars.
* _Block3_ does [XOR](https://stackoverflow.com/questions/14526584/what-does-the-xor-operator-do#:~:text=XOR%20is%20a%20binary%20operation,corresponding%20bits%20of%20a%20number) operation on ```[rbp+var_8]``` or on each value of ```#<=;7<=*\a+,=>967ii`\ayy\a%``` against some XOR key and prints the new char.
* _Block4_ prints "--hit any key" and reads a char with by calling ```scanf``` and ends the program regardless of the input value.

So the entire circle seems like it is manipulating some string using XOR and displaying the result on the screen.

Let's save the changes of the binaries and execute it again.
![Patched program](https://raw.githubusercontent.com/079035/079035.github.io/master/images/find%20the%20secret%20flag/20.PNG)

It seems like the string is consisted with continuous negative numbers in hexadecimal form.
Let's first patch the program to print in char form "%c" rather than "%x" so maybe we can read it.
![patched](https://raw.githubusercontent.com/079035/079035.github.io/master/images/find%20the%20secret%20flag/21.PNG) ("%x" -> "%c")

![ascii result](https://raw.githubusercontent.com/079035/079035.github.io/master/images/find%20the%20secret%20flag/22.PNG)

Never mind.

Moving on to XOR. Since we don't know the key, we are going to do some XOR brute forcing.
We could do it by hand, putting each alphabet into the key, but there is a better way at cyberchef: [XOR Brute Force](https://gchq.github.io/CyberChef/#recipe=XOR_Brute_Force(1,100,0,'Standard',false,true,false,''))
![XOR brute force](https://raw.githubusercontent.com/079035/079035.github.io/master/images/find%20the%20secret%20flag/23.PNG)

We find that key 78(hex) or "x"(ascii) gives us something interesting. ```[DECODER$.STEFANO...$...$.]```
But it is still partly unreadable. The characteristic of the XOR is that there's a possibility that more than one char might return another readable string and is usually the upper case(or lower) of that letter.

Using 58 or "X" as key gives us ```Key = 58: {decoder.9stefano118.9!!.9}```

Still incomplete.
This is probably because the cyberchef is taking ```\a``` as two different chars rather than an escape character.
So we will patch directly into the code:

![XOR patch](https://raw.githubusercontent.com/079035/079035.github.io/master/images/find%20the%20secret%20flag/25.PNG) (xor al, 58h)

I put nop after the XOR instruction to match the size of the instruction.

After patching it, we get the Flag.
![Flag](https://raw.githubusercontent.com/079035/079035.github.io/master/images/find%20the%20secret%20flag/26.PNG)

You can ask questions on discord.

Thank you,

079
