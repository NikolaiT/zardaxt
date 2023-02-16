import dpkt
import socket
from dpkt.tcp import parse_opts
import pcapy
from datetime import timedelta
import time
import sys
import signal
import json
from zardaxt_tcp_options import decode_tcp_options
from zardaxt_utils import TH_SYN, TH_ACK, load_config, compute_near_timestamp_tick
from zardaxt_logging import log
from zardaxt_api import run_api

"""
Author: Nikolai Tschacher
GitHub: https://github.com/NikolaiT/zardaxt
Date: March/April 2021
Update: January 2023

Allows to fingerprint an incoming TCP/IP connection by the initial SYN packet.

Several fields such as TCP Options or TCP Window Size 
or IP fragment flag depend heavily on the OS type and version.

Some code has been taken from: https://github.com/xnih/satori
However, the codebase of github.com/xnih/satori was quite frankly 
a huge mess (randomly failing code segments and capturing the errors, not good).

As of 2023, it is actually a complete rewrite.
"""

# do not modify those variables
interface = None
verbose = False
fingerprints = {}
timestamps = {}
config = None
if len(sys.argv) == 2:
  config = load_config(sys.argv[1])
else:
  config = load_config()

def update_file():
    log('writing fingerprints.json with {} objects...'.format(
        len(fingerprints)), 'zardaxt')
    with open('fingerprints.json', 'w') as fp:
        json.dump(fingerprints, fp, indent=2, sort_keys=False)


def signal_handler(sig, frame):
    update_file()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)  # ctlr + c
signal.signal(signal.SIGTSTP, signal_handler)  # ctlr + z

def process_packet(ts, header_len, cap_len, ip_pkt):
    """
    Processes an IP packet.

    We are only considering TCP segments here. 
    
    It likely makes sense to also make a TCP/IP fingerprint for other 
    TCP-like protocols such as QUIC, which is builds on top of UDP.

    For now, only TCP is considered. In the future, this will be updated.
    """
    tcp_pkt = None
    udp_pkt = None

    if ip_pkt.p == dpkt.ip.IP_PROTO_TCP:
      tcp_pkt = ip_pkt.data

    if ip_pkt.p == dpkt.ip.IP_PROTO_UDP:
      udp_pkt = ip_pkt.data

    # Currently, only TCP is considered for the TCP/IP fingerprint
    if tcp_pkt:
      tcp_options = parse_opts(tcp_pkt.opts)
      [str_opts, timestamp, timestamp_echo_reply, mss, window_scaling] = decode_tcp_options(tcp_options)
      is_syn = tcp_pkt.flags & TH_SYN
      is_ack = tcp_pkt.flags & TH_ACK
      src_ip = socket.inet_ntoa(ip_pkt.src)
      dst_ip = socket.inet_ntoa(ip_pkt.dst)

      if is_syn and not is_ack:
          if not fingerprints.get(src_ip, None):
              fingerprints[src_ip] = []
              
          fingerprints[src_ip].append({
            'ts': ts,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': tcp_pkt.sport,
            'dst_port': tcp_pkt.dport,
            'ip_hdr_length': ip_pkt.hl,
            'ip_version': ip_pkt.v,
            'ip_total_length': ip_pkt.len,
            'ip_id': ip_pkt.id,
            'ip_ttl': ip_pkt.ttl,
            'ip_df': ip_pkt.df,
            'ip_mf': ip_pkt.mf,
            'ip_off': ip_pkt.off,
            'ip_protocol': ip_pkt.p,
            'ip_checksum': ip_pkt.sum,
            'tcp_header_length': len(tcp_pkt),
            'tcp_window_size': tcp_pkt.win,
            'tcp_checksum': tcp_pkt.sum,
            'tcp_flags': tcp_pkt.flags,
            'tcp_ack': tcp_pkt.ack,
            'tcp_seq': tcp_pkt.seq,
            'tcp_urp': tcp_pkt.urp,
            'tcp_options': str_opts,
            'tcp_window_scaling': window_scaling,
            'tcp_timestamp': timestamp,
            'tcp_timestamp_echo_reply': timestamp_echo_reply,
            'tcp_mss': mss
          })

          if config['enable_uptime_interpolation']:
              key = '{}:{}'.format(src_ip, tcp_pkt.sport)
              add_timestamp(key, ts, timestamp,
                          timestamp_echo_reply, tcp_pkt.seq)

          if len(fingerprints) > config['clear_dict_after']:
              log('Clearing fingerprints dict', 'zardaxt')
              fingerprints.clear()
              timestamps.clear()

          if config['store_fingerprints']:
            if len(fingerprints) > 0 and len(fingerprints) % config['write_after'] == 0:
              update_file()

      elif is_ack:
          # Here we take timestamp samples from the client. We only regard timestamps from
          # ACK segments from the client ---> server.

          # RFC 1323 specifies timestamps must be monotonically increasing, and tick between 1 ms and 1 second.
          # The starting value for the timestamp is not explicitly specified, however many network stack implementations
          # use a systems uptime to calculate the timestamp. [https://floatingoctothorpe.uk/2018/detecting-uptime-from-tcp-timestamps.html]

          # Read https://www.rfc-editor.org/rfc/rfc1323#section-4 in order to understand
          # how TCP timestamps work.

          # We only take new timestamp samples, if the timestamp increases, otherwise
          # there is no further information to extract from identical timestamps (I guess
          # this happens because TCP/IP stacks fire out segments with the same TCP timestamp)
          # Most commonly, timestamps are in MS (milliseconds) (which means the frequency is 1000hz), but this is not always the case.

          # If we managed to infer the frequency (hz) of at least two timestamps, we will infer the likely exact
          # frequency and then we compute the uptime. For most modern systems, uptime computation will be wrong:
          # On Linux the TCP timestamp feature can be controlled with the net.ipv4.tcp_timestamp kernel parameter. Normally the option can either be enabled (1) or disabled (0), however more recent kernels also have an option to add a random offset which will effectively hide the systems uptime [https://floatingoctothorpe.uk/2018/detecting-uptime-from-tcp-timestamps.html]
          if config['enable_uptime_interpolation']:
              key = '{}:{}'.format(src_ip, tcp_pkt.sport)
              # this line makes sure that we already got the initial SYN packet
              if timestamp:
                  add_timestamp(key, ts, timestamp,
                              timestamp_echo_reply, tcp_pkt.seq)
                  if key in timestamps:
                      tss = timestamps[key].get('timestamps', [])
                      ticks = timestamps[key].get('clock_ticks', [])
                      if len(tss) >= 2:
                          delta_tcp_ts = tss[-1] - tss[0]
                          delta_clock = ticks[-1] - ticks[0]
                          hertz_observed = delta_tcp_ts / delta_clock
                          hertz = compute_near_timestamp_tick(hertz_observed)
                          timestamps[key]['uptime_interpolation'] = {
                            'hz_observed': hertz_observed,
                            'hz': hertz,
                            'num_timestamps': len(tss),
                          }
                          uptime = None
                          if isinstance(hertz, int):
                              uptime = tss[0] / hertz
                          elif hertz_observed > 0:
                              uptime = tss[0] / hertz_observed

                          if uptime:
                              timestamps[key]['uptime_interpolation']['uptime'] = str(
                                  timedelta(seconds=uptime))


def add_timestamp(key, ts, tcp_timestamp, tcp_timestamp_echo_reply, tcp_seq):
    if not key in timestamps:
        timestamps[key] = {
          'timestamps': [tcp_timestamp],
          'timestamp_echo_replies': [tcp_timestamp_echo_reply],
          'clock_ticks': [ts],
          'seq_nums': [tcp_seq]
        }
    elif len(timestamps[key].get('timestamps', [])) <= 20:
        timestamps[key]['timestamps'].append(tcp_timestamp)
        timestamps[key]['timestamp_echo_replies'].append(
            tcp_timestamp_echo_reply)
        timestamps[key]['clock_ticks'].append(ts)
        timestamps[key]['seq_nums'].append(tcp_seq)
        tss = timestamps[key].get('timestamps', [])
        ticks = timestamps[key].get('clock_ticks', [])
        deltas = []
        if len(tss) > 2:
            for i in range(len(tss) - 1):
                try:
                    rtt = int(tss[i+1]) - int(tss[i])
                    real = ticks[i+1] - ticks[i]
                    deltas.append('rtt={}, clock={}'.format(rtt, real))
                except Exception as err:
                    log('error: {}, tss: {}'.format(str(err), str(tss)),
                        'zardaxt', level='ERROR')

        timestamps[key]['deltas'] = deltas


def main():
    log('listening on interface {}'.format(config['interface']), 'zardaxt')
    # Arguments here are:
    # snaplen (maximum number of bytes to capture per packet)
    max_bytes = 100
    # promiscious mode (1 for true)
    promiscuous = False
    # https://github.com/the-tcpdump-group/libpcap/issues/572
    # The main purpose of timeouts in packet capture mechanisms is to allow the capture mechanism 
    # to buffer up multiple packets, and deliver multiple packets in a single wakeup, rather than one 
    # wakeup per packet, reducing the number of wakeups (which aren't free), 
    # without causing indefinitely-long waits for a packet to be delivered.
    # timeout (in milliseconds)

    # The first argument is the device that we specified in the previous section. 
    # snaplen is an integer which defines the maximum number of bytes to be captured by pcap. 
    # promisc, when set to true, brings the interface into promiscuous mode 
    # (however, even if it is set to false, it is possible under specific cases for the interface 
    # to be in promiscuous mode, anyway). to_ms is the read time out in milliseconds 
    # (a value of 0 means no time out; on at least some platforms, this means that you may wait until a 
    # sufficient number of packets arrive before seeing any packets, so you should use a non-zero timeout). 
    read_timeout = 1
    preader = pcapy.open_live(config['interface'], max_bytes, promiscuous, read_timeout)
    preader.setfilter(config['pcap_filter'])
    while True:
      (header, buf) = preader.next()
      ts = time.perf_counter()
      eth = None
      try:
        eth = dpkt.ethernet.Ethernet(buf)
      except Exception as err:
        continue
      # ignore everything other than IP packets
      if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        continue
      ip_pkt = eth.data
      header_len = header.getlen()
      cap_len = header.getcaplen()
      process_packet(ts, header_len, cap_len, ip_pkt)


if __name__ == '__main__':
  # run the API thread
  run_api(config, fingerprints, timestamps)
  # run pcap loop
  main()
