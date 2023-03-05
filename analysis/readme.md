# Analysis Questions

1. What header fields should be used for the TCP/IP fingerprint?
2. What header fields do correlate with the operating systems: `Android`, `Linux`, `Mac OS`, `Windows` and `iOS` most?
3. What header fields are not necessary?

All relevant variables:

```python
fields = ['ip_checksum', 'ip_df', 'ip_hdr_length',
          'ip_id', 'ip_mf', 'ip_off', 'ip_protocol', 'ip_rf', 'ip_tos',
          'ip_total_length', 'ip_ttl', 'ip_version', 'tcp_ack', 'tcp_checksum',
          'tcp_flags', 'tcp_header_length', 'tcp_mss', 'tcp_off', 'tcp_options',
          'tcp_seq', 'tcp_timestamp', 'tcp_timestamp_echo_reply', 'tcp_urp',
          'tcp_window_scaling', 'tcp_window_size']
```

How do best measure what header field has the most entropy for the TCP/IP fingerprint?

The data is clustered into 5 clusters for each OS.

80% of the data is used for training, 20% of the data is used for verification.

Then the idea is to rank all the above fields by importance. Which field brings the most entropy in regards to TCP/IP fingerprinting?

How is this ranking created?

1. Reference Miss Rate: The reference miss rate is computed for all 5 clusters with all variables switched on.
2. Switch Miss Rate: For each variable, the variable is removed from the computation of the score. The number of false positives is noted.
3. Based on all the switch miss rates, a ranking is made which variable has had the most influence on the overall score. Put differently: The
  removal of what variable caused the miss rate to increase the most?
