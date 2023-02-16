# Passive TCP/IP Fingerprinting 🚀

[Live Demo](https://tcpip.incolumitas.com/classify?by_ip=1)

Zardaxt.py is a passive TCP/IP fingerprinting tool. Run Zardaxt.py on your server to find out what operating systems your clients are *really* using. This tool considers the header fields and options from the very first incoming SYN packet of the TCP 3-Way Handshake.

**Why the rewrite?**

+ [p0f](https://github.com/p0f/p0f) is dead. [p0f's](https://github.com/p0f/p0f) database is too old and C is a bit overkill and hard to quickly hack in.
+ [satori.py](https://github.com/xnih/satori) is extremely buggy and hard to use (albeit the ideas behind the *code* are awesome). Actually, some code and inspiration used in zardaxt has been taken from [satori.py](https://github.com/xnih/satori).
+ The actual statistics/traffic samples behind TCP/IP fingerprinting are more important than the tool itself. Therefore it makes sense to rewrite it.

**What can I do with this tool?**

This tool may be used to correlate an incoming TCP/IP connection with a operating system class. For example, It can be used to detect proxies, if the proxy operating system (mostly Linux) differs from the operating system taken from the User-Agent.

If the key `os_mismatch` is true, then the TCP/IP inferred OS is different from the User-Agent OS.

## Demo

+ [Live Demo & Blog Article](https://incolumitas.com/2021/03/13/tcp-ip-fingerprinting-for-vpn-and-proxy-detection/)
+ [API page](https://incolumitas.com/pages/TCP-IP-Fingerprint/)

## Installation & Usage

**Important:** I tested this only on my Ubuntu 20.04 server. Installation currently does not work on my MacBook Pro for example.

First clone the repo:

```bash
# clone repo
git clone https://github.com/NikolaiT/zardaxt
# move into directory
cd zardaxt
```

Setup with `pipenv`. You can also use `pew`.

Note: For newer Python 3 versions (Such as Python 3.10), you will have to install `pcapy-ng` (See: <https://pypi.org/project/pcapy-ng/>) instead of `pcapy`.

```bash
# create a virtual environment
pipenv shell --python python3
# install packages
pipenv install pypacker pcapy-ng untangle requests
```

Now you need to create an environment file called `tcpip_fp.env` with the following variable:

```bash
# tcpip_fp.env
API_KEY='abcd1234' # set your API key here
```

You can create the file `tcpip_fp.env` with this command:

```bash
echo "API_KEY='abcd1234'" > tcpip_fp.env
```

Now run Zardaxt.py:

```bash
# load tcpip_fp.env file
set -a
source tcpip_fp.env
set +a

python tcp_fingerprint.py -i eth0
```

Or run in the background on your server

```bash
# load tcpip_fp.env file
set -a
source tcpip_fp.env
set +a

nohup python tcp_fingerprint.py -i eth0 > fp.out 2> fp.err < /dev/null &
```

## API Support

When you run `tcp_fingerprint.py`, the program automatically launches a simple web API that you can query. A http server is bound to `0.0.0.0:8249`. You can query it on `http://0.0.0.0:8249/classify`.

If you want to query the TCP/IP fingerprint only for the client IP address, use

```shell
curl http://0.0.0.0:8249/classify
```

If you want to query all fingerprints in the API database, you have to specify the API key:

```shell
curl http://0.0.0.0:8249/classify?key=abcd1234
```

If you want to query/lookup a specific IP address (Example: 103.14.251.215), you will have to specify the IP address and the API key:

```shell
curl http://0.0.0.0:8249/classify?key=abcd1234&ip=103.14.251.215
```

## What header fields are used for TCP/IP fingerprinting?

Several fields such as TCP Options or TCP Window Size or IP Fragment Flag depend heavily on the OS type and version. Detecting operating systems by analyzing the first incoming SYN packet is surely no exact science, but it's better than nothing.

### Entropy from the [IP header](https://en.wikipedia.org/wiki/IPv4)

+ `IP.ihl (4 bits)` - **Internet Header Length (IHL)** - The IPv4 header is variable in size due to the optional 14th field (Options). The IHL field contains the size of the IPv4 header. The minimum value for this field is 5 (20 bytes) and the maximum value is 15 (60 bytes). If the IP Options field correlates with the the underlying OS (which I don't think it does normally), the `IP.ihl` is relevant.
+ `IP.len (16 bits)` - **Total Length** - This 16-bit field defines the entire packet size in bytes, including header and data. The minimum size is 20 bytes (header without data) and the maximum is 65,535 bytes. `IP.len` is likely relevant for the TCP/IP fingerprint.
+ `IP.id (16 bits)` - **Identification** - This field is an identification field and is primarily used for uniquely identifying the group of fragments of a single IP datagram. However, the `IP.id` field is used for other purposes and it seems that [its behavior is OS dependent](https://perso.telecom-paristech.fr/drossi/paper/rossi17ipid.pdf): "We find that that the majority
of hosts adopts a constant IP-IDs (39%) or local counter (34%), that
the fraction of global counters (18%) significantly diminished, that a non
marginal number of hosts have an odd behavior (7%) and that random
IP-IDs are still an exception (2%)."
+ `IP.flags (3 bits)` - **Flags** - Don't fragment (DF) and more fragments (MF) flags, bit 0 is always 0. In the flags field of the IPv4 header, there are three bits for control flags. The "don't fragment" (DF) bit plays a central role in Path Maximum Transmission Unit Discovery (PMTUD) because it determines whether or not a packet is allowed to be [fragmented](https://www.cisco.com/c/en/us/support/docs/ip/generic-routing-encapsulation-gre/25885-pmtud-ipfrag.html). Some OS set the DF flag in the IP header, others don't.
+ `IP.ttl (8 bits)` - **Time to live (TTL)** - An eight-bit time to live field limits a datagram's lifetime to prevent network failure in the event of a routing loop. The TTL indicates how long a IP packet is allowed to circulate in the Internet. Each hop (such as a router) decrements the TTL field by one. The maximum TTL value is 255, the maximum value of a single octet (8 bits). A recommended initial value is 64, but some operating systems customize this value. Hence it's relevancy for TCP/IP fingerprinting.
+ `IP.protocol (8 bits)` - **Protocol** - This field defines the protocol used in the data portion of the IP datagram. IANA maintains a list of IP protocol numbers as directed by RFC 790. It does not seem to be that relevant for TCP/IP fingerprinting, since it is mostly TCP (6).
+ `IP.sum (16 bits)` - **Header checksum** - The 16-bit IPv4 header checksum field is used for error-checking of the header. When a packet arrives at a router, the router calculates the checksum of the header and compares it to the checksum field. If the values do not match, the router discards the packet. Errors in the data field must be handled by the encapsulated protocol. Both UDP and TCP have separate checksums that apply to their data. Probably has no use for TCP/IP fingerprinting.

### Entropy from the [TCP header](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)

+ `TCP.sequence_number (32 bits)` - **Sequence Number** -  If the SYN flag is set (1), then this is the initial sequence number. It might be the case that different operating systems use different initial sequence numbers, but the initial sequence number is most likely randomly chosen. Therefore this field is most likely of no particular help regarding fingerprinting.
+ `TCP.acknowledgment_number (32 bits)` - **Acknowledgment Number** -  If the ACK flag is set then the value of this field is the next sequence number that the sender of the ACK is expecting. *Should* be zero if the SYN flag is set.
+ `TCP.data_offset (4 bits)` - **Data Offset** - This is the size of the TCP header in 32-bit words with a minimum size of 5 words and a maximum size of 15 words. Therefore, the maximum TCP header size size is 60 bytes (with 40 bytes of options data). The TCP header size thus depends on how much options are present at the end of the header. This is correlating with the OS, since the TCP options correlate with the TCP/IP fingerprint.
+ `TCP.flags (9 bits)` - **Flags** -  This header field contains 9 one-bit flags for TCP protocol controlling purposes. The initial SYN packet has mostly a flags value of 2 (which means that only the SYN flag is set). However, I have also observed flags values of 194 (2^1 + 2^6 + 2^7), which means that the SYN, ECE and CWR flags are set to one. If the SYN flag is set, ECE means that the client is [ECN](https://en.wikipedia.org/wiki/Explicit_Congestion_Notification) capable. Congestion window reduced (CWR) means that the sending host received a TCP segment with the ECE flag set and had responded in congestion control mechanism.
+ `TCP.window_size (16 bits)` - **Window Size** -  Initial window size. The idea is that different operating systems use a different initial window size in the initial TCP SYN packet.
+ `TCP.checksum (16 bits)` - **Checksum** -  The 16-bit checksum field is used for error-checking of the TCP header, the payload and an IP pseudo-header. The pseudo-header consists of the source IP address, the destination IP address, the protocol number for the TCP protocol (6) and the length of the TCP headers and payload (in bytes).
+ `TCP.urgent_pointer (16 bits)` - **Urgent Pointer** -  If the URG flag is set, then this 16-bit field is an offset from the sequence number indicating the last urgent data byte. It *should* be zero in initial SYN packets.
+ `TCP.options (Variable 0-320 bits)` - **Options** -   All TCP Options. The length of this field is determined by the data offset field. Contains a lot of information, but most importantly: The Maximum Segment Size (MSS), the Window scale value. Because the TCP options data is variable in size, it is the most important source of entropy to distinguish operating systems. The order of the TCP options is also taken into account.

### Sources

1. Mostly Wikipedia [TCP/IP fingerprinting article](https://en.wikipedia.org/wiki/TCP/IP_stack_fingerprinting)
2. A lot of inspiration from [satori.py](https://github.com/xnih/satori)
3. Another TCP/IP fingerprinting [tool](https://github.com/agirishkumar/passive-os-detection/tree/master/OS-Fingerprinting)

## TCP Timestamp Mechanism

Furthermore, in order to interpolate the [host uptime via TCP timestamps](https://floatingoctothorpe.uk/2018/detecting-uptime-from-tcp-timestamps.html), the [TCP timestamp](https://www.rfc-editor.org/rfc/rfc1323#section-4) from a couple of consecutive TCP segments can be taken.

Source: <https://www.networkdatapedia.com/post/2018/10/08/how-tcp-works-the-timestamp-option>

**What is a TCP Timestamp?**

The timestamps option in TCP enables the endpoints to keep a current measurement of the roundtrip time (RTT) of the network between them. This value helps each TCP stack to set and adjust its retransmission timer. There are other benefits, but RTT measurement is the major one.

**How it works.**

Each end of the connection derives a 4-byte increasing value. This value is unique to each side and has no real numerical significance. The opposite end does not care what the value is, it will simply echo it back to the original sender. The original sender can then measure the timing between the packet(s) that were sent and received with this unique value.

The value used by each end will be increased as the connection goes along. Many TCP implementations will add the measured network RTT value (in milliseconds) to the 4-byte timestamp and use this new number for the next segment to be sent.

**Put differently:**

If both hosts support the TCP Timestamp mechanism, the initiating host will send a TCP timestamp value and the receiving host will echo this value, while at the same time sending it's own timestamp value. This allows both hosts to infer the RTT of the connection.

After the timestamp value was echoed to the host, it will add the RTT to the first value as next value of the TCP timestamp mechanism.

What is interesting from a fingerprinting perspective is not the actual RTT (maybe only to infer the type of network, or whether the RTT is stable), but more the following things:

1. How does the client choose to increase the timestamp value? Does the client increase the timestamp by the measure RTT? `timestamp_increase_type`
2. What is the frequency of the timestamp value? Is it 100hz, 250hz, or 1000hz? `timestamp_frequency`

Theory: <https://www.rfc-editor.org/rfc/rfc1323>
