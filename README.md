## Passive TCP/IP Fingerprinting

This is a passive TCP/IP fingerprinting tool. Run this on your server and find out what operating systems your clients are *really* using.

Why?

+ [p0f](https://github.com/p0f/p0f) is dead. It's database is too old. Also: C is a bit overkill and hard to quickly hack.
+ [satori.py](https://github.com/xnih/satori) is extremely buggy and hard to use (albeit the ideas behind the *code* are awesome)
+ The actual statistics behind TCP/IP fingerprinting are more important than the tool itself. Therefore it makes sense to rewrite it.

[What is TCP/IP fingerprinting?](https://en.wikipedia.org/wiki/TCP/IP_stack_fingerprinting)

### Introduction

Several fields such as TCP Options or TCP Window Size 
or IP Fragment Flag depend heavily on the OS type and version.

This is surely no exact science, but it's better than nothing.

Some code has been taken from: https://github.com/xnih/satori
However, the codebase of github.com/xnih/satori was quite frankly 
a huge mess (randomly failing code segments and capturing the Errors, not good).

This project does not attempt to be exact, it should give some hints what might be the OS of the 
incoming TCP/IP stream.

### What fields are used for TCP/IP fingerprinting?

+ Initial packet size 
+ Initial TTL
+ Window size 
+ Max segment size 
+ Window scaling value
+ "don't fragment" flag
+ "sackOK" flag
+ "nop" flag

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

### Resources

[Read this.](https://github.com/agirishkumar/passive-os-detection/tree/master/OS-Fingerprinting)