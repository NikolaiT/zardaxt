# Analysis Questions

1. What header fields should be used for the TCP/IP fingerprint?
2. What header fields do correlate most with the five operating systems: `Android`, `Linux`, `Mac OS`, `Windows` and `iOS` most?
3. What header fields do correlate most with the three base operating systems: `Unix-Like`, `Apple-Like`, `Windows`?
4. What header fields are not necessary for the TCP/IP fingerprint?

What we want is to have some kind of analysis that gives us a ranking what variable
carries the most entropy for TCP/IP fingerprinting.

All relevant variables:

```python
['ip_checksum', 'ip_df', 'ip_hdr_length',
'ip_id', 'ip_mf', 'ip_off', 'ip_protocol', 'ip_rf', 'ip_tos',
'ip_total_length', 'ip_ttl', 'ip_version', 'tcp_ack', 'tcp_checksum',
'tcp_flags', 'tcp_header_length', 'tcp_mss', 'tcp_off', 'tcp_options',
'tcp_seq', 'tcp_timestamp', 'tcp_timestamp_echo_reply', 'tcp_urp',
'tcp_window_scaling', 'tcp_window_size']
```

How do best measure what header field has the most entropy for the TCP/IP fingerprint?

The data is clustered into 5 clusters for each OS: `Android`, `Linux`, `Mac OS`, `Windows` and `iOS`
Alternatively: `Unix-Like`, `Apple-Like`, `Windows`

80% of the data is used for training, 20% of the data is used for verification.

Then the idea is to rank all the above variables by importance. Which variable brings the most entropy in regards to TCP/IP fingerprinting? Put differently: What variable has the most prediction power? What variable correlates the most with the operating system?

The variable (factor) importance algorithm is as follows:

1. For each variable, we create a histogram of all instances of this variable grouped by the OS. We create the histogram with the 80% training data.
2. In a second step, we use the testing data. We iterate over all variables. For each variable, we lookup the frequency of this instance in the histogram. We also look for the frequency of this variable in all other histograms. The ratio between `r = freq_correct / freq_all_sum` is stored. At the end, the average `r` is returned for each variable. The higher the average `r` is, the greater the predictive power of this variable to predict the OS.
3. However, there is a special case. For header fields such as `ip_checksum`, `tcp_checksum` or `tcp_seq` the variables have maximum entropy. Those header fields are either random by nature or are random as a consequent (since they are checksums). With enough large samples sizes, the variables would be equally distributed (uniform distribution). This is not the case with our test data, therefore we have to exclude those variables from analysis.

## Results

Those are the variable rankings for all 5 OS: `Android`, `Linux`, `Mac OS`, `Windows` and `iOS`

> `0.2` means variable has no predictive value

```text
tcp_options 0.807
ip_total_length 0.57
tcp_off 0.57
tcp_window_scaling 0.546
tcp_window_size 0.393
ip_ttl 0.385
ip_id 0.382
tcp_timestamp 0.364
tcp_timestamp_echo_reply 0.364
tcp_mss 0.275
ip_tos 0.214
tcp_flags 0.21
ip_df 0.2
ip_hdr_length 0.2
ip_mf 0.2
ip_off 0.2
ip_protocol 0.2
ip_rf 0.2
ip_version 0.2
tcp_ack 0.2
tcp_header_length 0.2
tcp_urp 0.2
```

And those are the results for only three operating system classes: `Unix-Like`, `Apple-Like`, `Windows`

> `0.36` means variable has no predictive value

```
tcp_options 0.991
ip_total_length 0.954
tcp_off 0.954
tcp_window_scaling 0.773
ip_id 0.706
ip_ttl 0.56
tcp_window_size 0.549
tcp_timestamp 0.548
tcp_timestamp_echo_reply 0.548
tcp_mss 0.405
tcp_flags 0.377
ip_tos 0.369
ip_df 0.362
ip_off 0.362
ip_hdr_length 0.361
ip_mf 0.361
ip_protocol 0.361
ip_rf 0.361
ip_version 0.361
tcp_ack 0.361
tcp_header_length 0.361
tcp_urp 0.361
```
