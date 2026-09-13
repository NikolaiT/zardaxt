# Zardaxt – passive TCP/IP fingerprinting

+ [Live demo](https://proxydetect.live/tcpip.html)
+ [Blog article](https://incolumitas.com/2021/03/13/tcp-ip-fingerprinting-for-vpn-and-proxy-detection/)

Zardaxt runs on a server and looks at the very first packet of every incoming
TCP connection, the SYN. Several of its header fields – TCP options and their
order, window size and scale, MSS, TTL, the IP id, ECN flags – depend on the
operating system that sent it. From that Zardaxt answers two questions about a
client:

1. **Which operating system sent this SYN?** Scored against a database of
   known fingerprints (`database/newCleaned.json`), answered as an average
   similarity per OS (`avg_score_os_class`).
2. **Was the SYN sent by the machine the browser claims to be?** Given the
   client's `User-Agent`, a gradient-boosting model (`models/tcpip_mismatch.joblib`)
   estimates the probability that a *relay* – an HTTP or SOCKS proxy – made
   the TCP connection on the browser's behalf. This is the signal the
   [proxydetect.live](https://proxydetect.live) engine uses as its `tcpip_fp`
   test. Tunnel VPNs are not caught by it: the client's own stack talks
   through the tunnel.

Why a rewrite? [p0f](https://github.com/p0f/p0f) is dead and its database old;
[satori.py](https://github.com/xnih/satori) was the inspiration but hard to
use. The traffic samples behind the fingerprints matter more than the tool.

## Layout

```
src/zardaxt.py       capture loop (pcapy + dpkt), keeps the SYN fingerprints per source IP in memory
src/api.py           HTTP API on :8249
src/fingerprint.py   OS scoring against the database, the relay model, the User-Agent -> OS mapping,
                     and the model's feature layout (shared with the trainer)
src/tcp_options.py   TCP option decoding into the "M1460,S,T,N,W7," string
src/log.py           log/zardaxt.log and log/zardaxt.err
src/dune_client.py   usage counters shipped to dune
database/            newCleaned.json (the OS database) and prepare.js that builds it
models/              tcpip_mismatch.joblib (the relay model)
zardaxt.json         config for a local run; zardaxt-server.json is the deployed one
restart.sh           (re)start on a box – cron runs it every 6 hours
deploy.sh            rsync + restart on one box:  ./deploy.sh env/de.env
downloadAndPrepare.sh pull labelled fingerprints from the engines and rebuild the database
```

## Running

```bash
pip3 install pew
pew new zardaxt
pew in zardaxt pip install -r requirements.txt   # dpkt, pcapy-ng, netifaces, scikit-learn, ...
pew in zardaxt python src/zardaxt.py zardaxt.json  # needs root for the capture
```

Config keys: `api_server_ip`, `api_server_port`, `api_key` (required),
`interface` (default: the default gateway's), `pcap_filter` (default `tcp`),
`clear_dict_after` (forget all fingerprints after this many IPs, default 5000).

## API

```bash
# the caller's own connection (X-Real-IP is honoured behind nginx)
curl "http://127.0.0.1:8249/classify"
curl "http://127.0.0.1:8249/classify?detail=1"           # raw fingerprint, per-OS scores, relay verdict
# any IP in memory, judged against a given User-Agent (the engine does this)
curl "http://127.0.0.1:8249/classify?key=K&ip=1.2.3.4&detail=1&ua=Mozilla/5.0%20(Windows%20NT%2010.0)"
curl "http://127.0.0.1:8249/all?key=K"                   # every fingerprint in memory
curl "http://127.0.0.1:8249/stats?key=K"
```

`/classify` answers with `os_mismatch`, `avg_score_os_class` and, when a
User-Agent is known and the model is loaded, `relay`:

```json
"relay": { "probability": 0.9496, "threshold": 0.8, "flagged": true, "ua_os": "Windows" }
```

`os_mismatch` is `relay.flagged` when the model answered, otherwise the older
comparison of OS classes from the database scores.

Behind nginx, proxy `location /` to `http://localhost:8249` and set
`X-Real-IP $remote_addr`; the proxydetect engines do this through their
`hostProxies` for `tcpip.incolumitas.com`.

## Data and training

Both the database and the model are built from sessions of the proxydetect
engines, where every connection also went through the engine's other tests
(latency, WebRTC, timezone, ...). Those tests provide the labels:

+ sessions every test called clean – the SYN is the visitor's own – and
  enumerated VPN tunnels without a relay signature (clamped MSS, own stack);
+ sessions the tests called proxies – the SYN is the relay's, the User-Agent
  the browser's.

```bash
./downloadAndPrepare.sh
# = rsync data/sessions/ from both boxes + the classifier bundles
#   -> proxyDetector/server/scripts/exportFingerprints.js   (direct-stack sessions only)
#   -> database/prepare.js                                  (dedupe per OS -> newCleaned.json)
cd ../flows/classifier && python3 tcpip_mismatch.py train --days 60
# -> ../../zardaxt/models/tcpip_mismatch.joblib, with a held-out report
```

Numbers from the 2026-09-13 build, held out from training (2,965 clean, 381
VPN, 27,976 relay sessions), at the deployed threshold 0.8:

| | flags clean users | flags VPN-tunnel users | catches relays | relays from other sites than the main customer |
|---|---|---|---|---|
| database scoring + OS-class rule (before) | ~0% by construction | 58% | 98.6% | – |
| relay model | 0.1% | 4.2% | 95.8% | 82% |

The database approach could not be improved by more data: rebuilt from clean
sessions only it *lost* relay recall (78%), because the old database had
learned relays by accident – it was built from unfiltered sessions, so its
"Android" entries are largely Linux relay stacks. The full evaluation is in
`flows/classifier/EVALUATION.md`. Caveats: the labels come from the other
tests, and 95% of the relay samples are one customer's traffic. Linux desktop
users are rare in the clean data (164 sessions), so a Linux desktop behind
no proxy is the most likely false positive.

### What carries the signal

A 2023 factor analysis on the fields (ratio of correct-OS frequency; 0.36 =
no predictive value, three OS classes Unix / Apple / Windows):

```
tcp_options 0.991   ip_total_length 0.954   tcp_off 0.954   tcp_window_scaling 0.773
ip_id 0.706   ip_ttl 0.56   tcp_window_size 0.549   tcp_timestamp 0.548   tcp_mss 0.405
tcp_flags 0.377   ip_tos 0.369   ip_df 0.362
```

The 2026 data adds two that the averaging database underused: ECN flags on
the SYN (`tcp_flags` 194) are set by 74% of iOS and 56% of macOS stacks but
1% of Windows, and a zero IP id by 98% of iOS and 81% of macOS but 1.5% of
Windows.

## What header fields are used for TCP/IP fingerprinting?

Several fields such as TCP Options or TCP Window Size or IP Fragment Flag depend heavily on the OS type and version. Detecting operating systems by analyzing the first incoming SYN packet is surely no exact science, but it's better than nothing.

### Entropy from the [IP header](https://en.wikipedia.org/wiki/IPv4)

+ `IP.ihl (4 bits)` - **Internet Header Length (IHL)** - The IPv4 header is variable in size due to the optional 14th field (Options). The IHL field contains the size of the IPv4 header. The minimum value for this field is 5 (20 bytes) and the maximum value is 15 (60 bytes). If the IP options field correlates with the the underlying OS (which I don't think is necessarily the case), the `IP.ihl` is relevant.
+ `IP.len (16 bits)` - **Total Length** - This 16-bit field defines the entire packet size in bytes, including header and data. The minimum size is 20 bytes (header without data) and the maximum is 65,535 bytes. `IP.len` is likely relevant for the TCP/IP fingerprint.
+ `IP.id (16 bits)` - **Identification** - This field is an identification field and is primarily used for uniquely identifying the group of fragments of a single IP datagram. However, the `IP.id` field is used for other purposes and it seems that [its behavior is OS dependent](https://perso.telecom-paristech.fr/drossi/paper/rossi17ipid.pdf): "We find that that the majority
of hosts adopts a constant IP-IDs (39%) or local counter (34%), that
the fraction of global counters (18%) significantly diminished, that a non
marginal number of hosts have an odd behavior (7%) and that random
IP-IDs are still an exception (2%)."
+ `IP.flags (3 bits)` - **Flags** - Don't fragment (DF) and more fragments (MF) flags, bit 0 (RF) is always 0. In the flags field of the IPv4 header, there are three bits for control flags. The "don't fragment" (DF) bit plays a central role in Path Maximum Transmission Unit Discovery (PMTUD) because it determines whether or not a packet is allowed to be [fragmented](https://www.cisco.com/c/en/us/support/docs/ip/generic-routing-encapsulation-gre/25885-pmtud-ipfrag.html). Some OS set the DF flag in the IP header, others don't.
+ `IP.ttl (8 bits)` - **Time to live (TTL)** - An eight-bit time to live field limits a datagram's lifetime to prevent network failure in the event of a routing loop. The TTL indicates how long an IP packet is allowed to circulate in the Internet. Each hop (such as a router) decrements the TTL field by one. The maximum TTL value is 255, the maximum value of a single octet (8 bits). A recommended initial value is 64, but some operating systems customize this value. Hence its relevance for TCP/IP fingerprinting.
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
