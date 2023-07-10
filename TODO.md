# TODO

Fix this:

```text
Traceback (most recent call last):
  File "/root/zardaxt/zardaxt.py", line 197, in main
    process_packet(ts, header_len, cap_len, ip_pkt, ip_version)
  File "/root/zardaxt/zardaxt.py", line 74, in process_packet
    is_syn = tcp_pkt.flags & TH_SYN
AttributeError: 'bytes' object has no attribute 'flags'

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/root/zardaxt/zardaxt.py", line 207, in <module>
    main()
  File "/root/zardaxt/zardaxt.py", line 199, in main
    log("main() crashed with error: {} and stack: {}".format(
  File "/root/zardaxt/zardaxt_logging.py", line 12, in log
    with open('log/zardaxt.err', 'a') as logfile:
OSError: [Errno 28] No space left on device: 'log/zardaxt.err'
```

```text
[2023-07-10 18:02:11.626988] - ERROR - api - main() crashed with error: 'bytes' object has no attribute 'flags' and stack: Traceback (most recent call last):
  File "/root/zardaxt/zardaxt.py", line 197, in main
    process_packet(ts, header_len, cap_len, ip_pkt, ip_version)
  File "/root/zardaxt/zardaxt.py", line 74, in process_packet
    is_syn = tcp_pkt.flags & TH_SYN
AttributeError: 'bytes' object has no attribute 'flags'
```
