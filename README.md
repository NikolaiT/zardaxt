## Passive TCP/IP Fingerprinting

This is a passive TCP/IP fingerprinting tool. Run this on your server and find out what operating systems your clients are *really* using. This tool considers only the fields and options from the very first incoming SYN packet of the 
TCP 3-Way Handshake. Nothing else is considered.

Why?

+ [p0f](https://github.com/p0f/p0f) is dead. It's database is too old. Also: C is a bit overkill and hard to quickly hack in.
+ [satori.py](https://github.com/xnih/satori) is extremely buggy and hard to use (albeit the ideas behind the *code* are awesome)
+ The actual statistics behind TCP/IP fingerprinting are more important than the tool itself. Therefore it makes sense to rewrite it.

[What is TCP/IP fingerprinting?](https://en.wikipedia.org/wiki/TCP/IP_stack_fingerprinting)

### Introduction

Several fields such as TCP Options or TCP Window Size 
or IP Fragment Flag depend heavily on the OS type and version.

Detecting operating systems by analyizing the first incoming SYN packet is surely no exact science, but it's better than nothing.

Some code and inspiration has been taken from: https://github.com/xnih/satori

However, the codebase of github.com/xnih/satori was quite frankly 
a huge mess (randomly failing code segments and capturing all Errors: Not good, no no no).

This project does not attempt to be exact, it should give some hints what might be the OS of the 
incoming TCP/IP stream.

### What fields are used for TCP/IP fingerprinting?

Inspiration by 

1. Wikipedia [TCP/IP fingerprinting article](https://en.wikipedia.org/wiki/TCP/IP_stack_fingerprinting)
2. [Satori.py](https://github.com/xnih/satori)
3. Other TCP/IP fingerprinting [tool](https://github.com/agirishkumar/passive-os-detection/tree/master/OS-Fingerprinting)

Entropy taken from the [IP header](https://en.wikipedia.org/wiki/IPv4):

+ Initial TTL of the IP frame. Different OS use a differnt initial TTL. 
+ Don't Fragment (DF) flag. Some OS set the DF bit in the IP header, others don't	
+ More Fragments (MF)

Entropy taken from the [TCP header](https://en.wikipedia.org/wiki/Transmission_Control_Protocol):

+ Initial packet size. May differ between different OSes	
+ Initial Window size. Differentiate implementations based on default Window Size in TCP	
+ TCP Flags
+ ACK field.
+ URP field
+ Max segment size
+ Window scaling value. Not all operating systems use this option	
+ All TCP Options. Bears a lot of information.
+ TCP Options order. Also the order of the TCP options is taken into account.

### Installation & Usage

First clone the repo:

```bash
git clone https://github.com/NikolaiT/zardaxt

cd zardaxt
```

Setup with `pipenv`.

```
pipenv shell

pipenv install
```

And run it

```bash
python tcp_fingerprint.py -i eth0
```

Or run in the background on your server

```bash
py=/root/.local/share/virtualenvs/satori-v7E0JF0G/bin/python
nohup $py tcp_fingerprint.py -i eth0 > fp.out 2> fp.err < /dev/null &
```