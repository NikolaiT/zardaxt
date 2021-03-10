## Passive TCP/IP Fingerprinting

Passive TCP/IP fingerprinting tool. Run this on your server and find out what operating systems your clients are *really* using.

Why?

+ [p0f](https://github.com/p0f/p0f) is dead. It's database is too old. Also: C is a bit overkill and hard to quickly hack in.
+ [satori.py](https://github.com/xnih/satori) is extremely buggy and hard to use (albeit the ideas behind the 'code' are awesome)

TCP/IP fingerprinting is super old. Let's revive it.

### Project Goals?

Simple TCP/IP fingerprinting. This project does not attempt to be exact, it 
should give some hints what might be the OS.

In the coming weeks (Until April 2021), I will provide a small database of 
maybe 7 different major Operating Systems and a collection of at least 20 fingerprints for
each OS. 

This allows to make a heurist statement about what OS might be behind the incoming TCP/IP connection. 

### More Info

Allows to fingerprint an incoming TCP/IP connection.

Several fields such as TCP Options or TCP Window Size 
or IP Fragment Flag depend heavily on the OS type and version.

This tool attempts to fingerprint OS's based on TCP/IP fingerprints.

This is surely no exact science, but it's better than nothing.

Some code has been taken from: https://github.com/xnih/satori
However, the codebase of github.com/xnih/satori was quite frankly 
a huge mess (randomly failing code segments and capturing the Errors, not good).

### How to run

```bash
py=/root/.local/share/virtualenvs/satori-v7E0JF0G/bin/python
nohup $py tcp_fingerprint.py -i eth0 > tcp_fingerprint.out 2> tcp_fingerprint.err < /dev/null &
```