"""Passive TCP/IP fingerprinting from the first SYN of every connection.

    python src/zardaxt.py [config.json]

Author: Nikolai Tschacher, https://github.com/NikolaiT/zardaxt
March 2021, rewritten 2023, restructured 2026.

Captures every incoming SYN on the default interface, records the IP and TCP
header fields that depend on the sender's operating system, keeps them in
memory per source IP, and serves them through api.py.
"""
import json
import signal
import socket
import sys
import traceback
from pathlib import Path

import dpkt
from dpkt.tcp import parse_opts
import netifaces
import pcapy

from api import run_api
from fingerprint import TH_ACK, TH_SYN, load_database
from log import log
from tcp_options import decode_tcp_options

ROOT = Path(__file__).resolve().parent.parent
REQUIRED_CONFIG = ['api_server_ip', 'api_server_port', 'api_key']

# One list of SYN fingerprints per source IP, newest last.
fingerprints = {}


def load_config(path):
    path = Path(path) if path else ROOT / 'zardaxt.json'
    if not path.is_absolute() and not path.exists():
        path = ROOT / path
    with open(path) as f:
        config = json.load(f)
    missing = [k for k in REQUIRED_CONFIG if k not in config]
    if missing:
        raise SystemExit(f'{path}: missing config keys {missing}')
    log(f'loaded config {path}', 'zardaxt')
    return config


def default_interface():
    return netifaces.gateways()['default'][netifaces.AF_INET][1]


def record_syn(ts, header_len, cap_len, ip_pkt, ip_version):
    tcp_pkt = ip_pkt.data
    src_ip = socket.inet_ntop(socket.AF_INET if ip_version == 4 else socket.AF_INET6, ip_pkt.src)
    dst_ip = socket.inet_ntop(socket.AF_INET if ip_version == 4 else socket.AF_INET6, ip_pkt.dst)
    str_opts, timestamp, timestamp_echo_reply, mss, window_scaling = decode_tcp_options(parse_opts(tcp_pkt.opts))
    v4 = ip_version == 4
    fingerprints.setdefault(src_ip, []).append({
        'ts': ts,
        'header_len': header_len,
        'cap_len': cap_len,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': tcp_pkt.sport,
        'dst_port': tcp_pkt.dport,
        'ip_version': ip_pkt.v,
        'ip_hdr_length': ip_pkt.hl if v4 else None,
        'ip_total_length': ip_pkt.len if v4 else len(ip_pkt),
        'ip_tos': ip_pkt.tos if v4 else None,
        'ip_id': ip_pkt.id if v4 else None,
        'ip_ttl': ip_pkt.ttl if v4 else ip_pkt.hlim,  # hop limit plays the TTL's role in v6
        'ip_rf': ip_pkt.rf if v4 else None,
        'ip_df': ip_pkt.df if v4 else None,
        'ip_mf': ip_pkt.mf if v4 else None,
        'ip_off': ip_pkt.off if v4 else None,
        'ip_protocol': ip_pkt.p,
        'ip_checksum': ip_pkt.sum if v4 else None,
        'ip_plen': ip_pkt.plen if not v4 else None,
        'ip_nxt': ip_pkt.nxt if not v4 else None,
        'tcp_header_length': tcp_pkt.__hdr_len__,
        'tcp_off': tcp_pkt.off,
        'tcp_window_size': tcp_pkt.win,
        'tcp_checksum': tcp_pkt.sum,
        'tcp_flags': tcp_pkt.flags,
        'tcp_ack': tcp_pkt.ack,
        'tcp_seq': tcp_pkt.seq,
        'tcp_urp': tcp_pkt.urp,
        'tcp_options': str_opts,
        'tcp_options_ordered': ''.join(t[0] for t in str_opts.split(',') if t),
        'tcp_window_scaling': window_scaling,
        'tcp_timestamp': timestamp,
        'tcp_timestamp_echo_reply': timestamp_echo_reply,
        'tcp_mss': mss,
    })


def capture(config):
    interface = config.get('interface') or default_interface()
    log(f'listening on {interface}', 'zardaxt')
    # 120 bytes cover the largest IP header (60) plus the largest TCP header (60).
    reader = pcapy.open_live(interface, 120, False, 1)
    reader.setfilter(config.get('pcap_filter', 'tcp'))
    clear_after = config.get('clear_dict_after', 5000)

    while True:
        header, buf = reader.next()
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type not in (dpkt.ethernet.ETH_TYPE_IP, dpkt.ethernet.ETH_TYPE_IP6):
            continue
        ip_pkt = eth.data
        tcp_pkt = ip_pkt.data if ip_pkt.p == dpkt.ip.IP_PROTO_TCP else None
        # Truncated or unparsable segments arrive as bytes rather than dpkt.tcp.TCP.
        if tcp_pkt is None or not hasattr(tcp_pkt, 'flags'):
            continue
        # Client -> server SYN only; the SYN ACK is our own stack.
        if tcp_pkt.flags & TH_SYN and not tcp_pkt.flags & TH_ACK:
            record_syn(header.getts(), header.getlen(), header.getcaplen(), ip_pkt,
                       6 if eth.type == dpkt.ethernet.ETH_TYPE_IP6 else 4)
            if len(fingerprints) > clear_after:
                log(f'clearing {len(fingerprints)} fingerprints', 'zardaxt')
                fingerprints.clear()


def main():
    config = load_config(sys.argv[1] if len(sys.argv) > 1 else None)
    load_database()
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    run_api(config, fingerprints)
    try:
        capture(config)
    except Exception as err:
        log(f'capture crashed: {err}\n{traceback.format_exc()}', 'zardaxt', level='ERROR')
        raise


if __name__ == '__main__':
    main()
