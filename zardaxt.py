import dpkt
import socket
from dpkt.tcp import parse_opts
import pcapy
from datetime import timedelta
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


def process_packet(ts, header_len, cap_len, ip_pkt, ip_version):
    """
    We are only considering TCP segments here.

    It likely makes sense to also make a TCP/IP fingerprint for other
    TCP-like protocols such as QUIC, which builds on top of UDP.
    """
    tcp_pkt = None

    if ip_pkt.p == dpkt.ip.IP_PROTO_TCP:
        tcp_pkt = ip_pkt.data

    if tcp_pkt:
        is_syn = tcp_pkt.flags & TH_SYN
        is_ack = tcp_pkt.flags & TH_ACK

        addr_fam = socket.AF_INET
        if ip_version == 6:
            addr_fam = socket.AF_INET6

        src_ip = socket.inet_ntop(addr_fam, ip_pkt.src)
        dst_ip = socket.inet_ntop(addr_fam, ip_pkt.dst)

        # The reason we are looking for a TCP segment that has the SYN flag
        # but not the ACK flag is that we are only interested in packets
        # coming from client to server and not the SYN+ACK from server to client.
        if is_syn and not is_ack:
            tcp_options = parse_opts(tcp_pkt.opts)
            [str_opts, timestamp, timestamp_echo_reply, mss,
                window_scaling] = decode_tcp_options(tcp_options)

            ip_len = None
            ip_ttl = None
            if ip_version == 4:
                ip_ttl = ip_pkt.ttl
                ip_len = ip_pkt.len
            elif ip_version == 6:
                ip_len = len(ip_pkt)
                # Hop Limit (8 bits)
                # Replaces the time to live field in IPv4.
                # This value is decremented by one at each forwarding node and the packet is discarded
                # if it becomes 0. However, the destination node should process the packet normally
                # even if received with a hop limit of 0.
                ip_ttl = ip_pkt.hlim

            if not fingerprints.get(src_ip, None):
                fingerprints[src_ip] = []

            fingerprints[src_ip].append({
                'ts': ts,
                'header_len': header_len,
                'cap_len': cap_len,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': tcp_pkt.sport,
                'dst_port': tcp_pkt.dport,
                'ip_hdr_length': ip_pkt.hl if ip_version == 4 else None,
                'ip_version': ip_pkt.v,
                'ip_total_length': ip_len,
                'ip_tos': ip_pkt.tos if ip_version == 4 else None,
                'ip_id': ip_pkt.id if ip_version == 4 else None,
                'ip_ttl': ip_ttl,
                'ip_rf': ip_pkt.rf if ip_version == 4 else None,
                'ip_df': ip_pkt.df if ip_version == 4 else None,
                'ip_mf': ip_pkt.mf if ip_version == 4 else None,
                'ip_off': ip_pkt.off if ip_version == 4 else None,
                'ip_protocol': ip_pkt.p,
                'ip_checksum': ip_pkt.sum if ip_version == 4 else None,
                'ip_plen': ip_pkt.plen if ip_version == 6 else None,
                'ip_nxt': ip_pkt.nxt if ip_version == 6 else None,
                # @TODO: this is likely not what we want (Probably just take tcp_off instead)
                'tcp_header_length': tcp_pkt.__hdr_len__,
                'tcp_off': tcp_pkt.off,
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

            if config.get('enable_uptime_interpolation', False):
                key = '{}:{}'.format(src_ip, tcp_pkt.sport)
                add_timestamp(key, ts, timestamp,
                              timestamp_echo_reply, tcp_pkt.seq)

            if len(fingerprints) > config.get('clear_dict_after', 5000):
                log('Clearing fingerprints dict', 'zardaxt')
                fingerprints.clear()
                timestamps.clear()

            if config.get('store_fingerprints', False):
                if len(fingerprints) > 0 and len(fingerprints) % config.get('write_after', 1000) == 0:
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
            if config.get('enable_uptime_interpolation', False):
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
    log('Listen on interface {}'.format(config['interface']), 'zardaxt')
    # Arguments here are:
    # snaplen (maximum number of bytes to capture per packet)
    # 120 bytes are picked, since the maximum TCP header is 60 bytes and the maximum IP header is also 60 bytes
    # The IPv6 header is always present and is a fixed size of 40 bytes.
    max_bytes = 120
    # promiscuous mode (1 for true)
    promiscuous = 1
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
    preader = pcapy.open_live(
        config['interface'], max_bytes, promiscuous, read_timeout)
    preader.setfilter(config.get('pcap_filter', ''))
    while True:
        (header, buf) = preader.next()
        eth = dpkt.ethernet.Ethernet(buf)
        # ignore everything other than IPv4 or IPv6
        if eth.type == dpkt.ethernet.ETH_TYPE_IP or eth.type == dpkt.ethernet.ETH_TYPE_IP6:
            ip_pkt = eth.data
            header_len = header.getlen()
            cap_len = header.getcaplen()
            ts = header.getts()

            ip_version = 4
            if eth.type == dpkt.ethernet.ETH_TYPE_IP6:
                ip_version = 6

            process_packet(ts, header_len, cap_len, ip_pkt, ip_version)


if __name__ == '__main__':
    # run the API thread
    run_api(config, fingerprints, timestamps)
    # run pcap loop
    main()
