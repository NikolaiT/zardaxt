from pypacker.layer12 import ethernet
from pypacker.layer12 import linuxcc
from pypacker.layer3 import ip
from pypacker.layer4 import tcp
from pypacker import pypacker
from datetime import timedelta
import pcapy
import getopt
import time
import sys
import traceback
import signal
import json
from tcp_options import decodeTCPOptions
from tcpip_fp_logging import log
from api import run_api

"""
Author: Nikolai Tschacher
Website: incolumitas.com
Date: March/April 2021
Update: January 2023

Allows to fingerprint an incoming TCP/IP connection by the intial SYN packet.

Several fields such as TCP Options or TCP Window Size 
or IP fragment flag depend heavily on the OS type and version.

Some code has been taken from: https://github.com/xnih/satori
However, the codebase of github.com/xnih/satori was quite frankly 
a huge mess (randomly failing code segments and capturing the errors, not good). 
"""

# global configuration
PCAP_FILTER = 'tcp port 80 or tcp port 443'
storeFingerprints = False
writeAfter = 1000
# after how many fingerprints the data structure should be cleared
# we have to reset in order to prevent memory leaks
clearDictAfter = 5000
enableUptimeInterpolation = False
interface = None
verbose = False
fingerprints = {}
timestamps = {}

def updateFile():
    log('writing fingerprints.json with {} objects...'.format(
        len(fingerprints)), 'tcp_fingerprint')
    with open('fingerprints.json', 'w') as fp:
        json.dump(fingerprints, fp, indent=2, sort_keys=False)


def signal_handler(sig, frame):
    updateFile()
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)  # ctlr + c
signal.signal(signal.SIGTSTP, signal_handler)  # ctlr + z


def tcpProcess(pkt, ts, packetReceived):
    """
    Understand this: https://www.keycdn.com/support/tcp-flags

    from src -> dst, SYN
    from dst -> src, SYN-ACK
    from src -> dst, ACK

    Capture SYN-ACK: 

    tcpdump -ni <device> -c 25 'tcp[tcpflags] & (tcp-ack | tcp-syn) !=0'

    TCP stuff: https://gitlab.com/mike01/pypacker/-/blob/master/pypacker/layer4/tcp.py
    """
    ip4 = pkt.upper_layer
    tcp1 = pkt.upper_layer.upper_layer

    # SYN (1 bit): Synchronize sequence numbers. Only the first packet sent from each
    # end should have this flag set. Some other flags and fields change meaning
    # based on this flag, and some are only valid when it is set, and others when it is clear.

    is_syn = tcp1.flags & tcp.TH_SYN
    is_ack = tcp1.flags & tcp.TH_ACK

    label = ''
    if is_syn and not is_ack:
        label = 'SYN'
    if is_syn and is_ack:
        label = 'SYN+ACK'
    if not is_syn and is_ack:
        label = 'ACK'

    if verbose:
        log("[%s] %d: %s:%s -> %s:%s" % (label, ts, pkt[ip.IP].src_s, pkt[tcp.TCP].sport,
            pkt[ip.IP].dst_s, pkt[tcp.TCP].dport), 'tcp_fingerprint')

    # http://www.iana.org/assignments/ip-parameters/ip-parameters.xml
    [ipVersion, ipHdrLen] = computeIP(ip4.v_hl)

    # https://github.com/mike01/pypacker/blob/master/pypacker/layer3/ip.py
    ip_off = None
    if hasattr(ip4, 'off'):
        ip_off = ip4.off
    elif hasattr(ip4, 'frag_off'):
        ip_off = ip4.frag_off

    [df, mf, offset] = computeIPOffset(ip_off)

    [tcpOpts, tcpTimeStamp, tcpTimeStampEchoReply, mss,
        windowScaling] = decodeTCPOptions(tcp1.opts)

    if verbose:
        log('[{}] IP version={}, header length={}, TTL={}, df={}, mf={}, offset={}'.format(
            ipVersion, ipHdrLen, ip4.ttl, df, mf, offset, label
        ), 'tcp_fingerprint')
        log('[{}]TCP window size={}, flags={}, ack={}, header length={}, urp={}, options={}, time stamp={}, timestamp echo reply = {}, MSS={}'.format(
            tcp1.win, tcp1.flags, tcp1.ack, tcp1.off_x2, tcp1.urp, tcpOpts, tcpTimeStamp, tcpTimeStampEchoReply, mss, label
        ), 'tcp_fingerprint')

    if label == 'SYN':
        src_ip, src_port = pkt[ip.IP].src_s, pkt[tcp.TCP].sport
        # the key is the src_ip and the value is a list of all fingerprints
        # for this src_ip
        if not fingerprints.get(src_ip, None):
            fingerprints[src_ip] = []

        fingerprints[src_ip].append({
            'packet_received': packetReceived,
            'ts': ts,
            'src_ip': pkt[ip.IP].src_s,
            'dst_ip': '{}'.format(pkt[ip.IP].dst_s),
            'src_port': '{}'.format(pkt[tcp.TCP].sport),
            'dst_port': '{}'.format(pkt[tcp.TCP].dport),
            'ip_hdr_length': ipHdrLen,
            'ip_opts': ip4.opts,
            'ip_ttl': ip4.ttl,
            'ip_df': df,
            'ip_mf': mf,
            'ip_frag_off': ip_off,
            'tcp_window_size': tcp1.win,
            'tcp_flags': tcp1.flags,
            'tcp_ack': tcp1.ack,
            'tcp_seq': tcp1.seq,
            'tcp_header_length': tcp1.off_x2,  # tcp_data_offset
            'tcp_urp': tcp1.urp,
            'tcp_options': tcpOpts,
            'tcp_window_scaling': windowScaling,
            'tcp_timestamp': tcpTimeStamp,
            'tcp_timestamp_echo_reply': tcpTimeStampEchoReply,
            'tcp_mss': mss
        })

        # add tcp ts from syn packet
        if enableUptimeInterpolation:
            key = '{}:{}'.format(src_ip, src_port)
            addTimestamp(key, packetReceived, tcpTimeStamp,
                        tcpTimeStampEchoReply, tcp1.seq)

        if len(fingerprints) > clearDictAfter:
            log('Clearing fingerprints dict', 'tcp_fingerprint')
            fingerprints.clear()
            timestamps.clear()

        # update file once in a while
        if storeFingerprints:
            if len(fingerprints) > 0 and len(fingerprints) % writeAfter == 0:
                updateFile()

    elif label == 'ACK':
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
        # Most commonly, timestamps are in MS (millieseconds) (which means the frequency is 1000hz), but this is not always the case.

        # If we managed to infer the frequency (hz) of at least two timestamps, we will infer the likely exact
        # frequency and then we compute the uptime. For most modern systems, uptime computation will be wrong:
        # On Linux the TCP timestamp feature can be controlled with the net.ipv4.tcp_timestamp kernel parameter. Normally the option can either be enabled (1) or disabled (0), however more recent kernels also have an option to add a random offset which will effectively hide the systems uptime [https://floatingoctothorpe.uk/2018/detecting-uptime-from-tcp-timestamps.html]
        if enableUptimeInterpolation:
            key = '{}:{}'.format(pkt[ip.IP].src_s, pkt[tcp.TCP].sport)
            # this line makes sure that we alrady got the initial SYN packet
            if tcpTimeStamp and isInt(tcpTimeStamp):
                addTimestamp(key, packetReceived, tcpTimeStamp,
                            tcpTimeStampEchoReply, tcp1.seq)
                if key in timestamps:
                    tss = timestamps[key].get('timestamps', [])
                    ticks = timestamps[key].get('clock_ticks', [])
                    if len(tss) >= 2 and isInt(tss[-1]) and isInt(tss[0]):
                        delta_tcp_ts = tss[-1] - tss[0]
                        delta_clock = ticks[-1] - ticks[0]
                        hertz_observed = delta_tcp_ts / delta_clock
                        hertz = computeNearTimestampTick(hertz_observed)
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


def addTimestamp(key, packetReceived, tcp_timestamp, tcp_timestamp_echo_reply, tcp_seq):
    if not key in timestamps:
        timestamps[key] = {
            'timestamps': [tcp_timestamp],
            'timestamp_echo_replies': [tcp_timestamp_echo_reply],
            'clock_ticks': [packetReceived],
            'seq_nums': [tcp_seq]
        }
    elif len(timestamps[key].get('timestamps', [])) <= 20:
        timestamps[key]['timestamps'].append(tcp_timestamp)
        timestamps[key]['timestamp_echo_replies'].append(
            tcp_timestamp_echo_reply)
        timestamps[key]['clock_ticks'].append(packetReceived)
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
                        'tcp_fingerprint', level='ERROR')

        timestamps[key]['deltas'] = deltas


def computeIP(info):
    ipVersion = int('0x0' + hex(info)[2], 16)
    ipHdrLen = int('0x0' + hex(info)[3], 16) * 4
    return [ipVersion, ipHdrLen]

def isInt(test):
    try:
        int(test)
        return True
    except ValueError:
        return False


def computeNearTimestampTick(hertz_observed):
    """
    Guess what the TCP timestmap tick must have been from measurements

    Theory: https://www.rfc-editor.org/rfc/rfc1323#section-4

    So far, what I have seen in the wild is 1000hz, 250hz, 100hz and 10hz
    """
    if hertz_observed > 800 and hertz_observed < 1200:
        return 1000

    if hertz_observed > 240 and hertz_observed < 260:
        return 250

    if hertz_observed > 90 and hertz_observed < 110:
        return 100

    if hertz_observed > 5 and hertz_observed < 15:
        return 10

    return 'unknown'


def computeIPOffset(info):
    # need to see if I can find a way to import these from ip.py as they are already defined there.
    # Fragmentation flags (ip_off)
    IP_RF = 0x4   # reserved
    IP_DF = 0x2   # don't fragment
    IP_MF = 0x1   # more fragments (not last frag)

    res = 0
    df = 0
    mf = 0

    flags = (info & 0xE000) >> 13
    offset = (info & ~0xE000)

    if (flags & IP_RF) > 0:
        res = 1
    if (flags & IP_DF) > 0:
        df = 1
    if (flags & IP_MF) > 0:
        mf = 1

    return [df, mf, offset]


def usage():
    print("""
    -i, --interface   interface to listen to; example: -i eth0
    -l, --log         log file to write output to; example -l output.txt (not implemented yet)
    -v, --verbose     verbose logging, mostly just telling you where/what we're doing, not recommended if want to parse output typically
    -n, --writeAfter  after how many SYN packets writing to the file""")


def main():
    # override some warning settings in pypacker.  May need to change this to .CRITICAL in the future, but for now we're trying .ERROR
    # without this when parsing http for example we get "WARNINGS" when packets aren't quite right in the header.
    pypacker.logger.setLevel(pypacker.logging.ERROR)

    log('listening on interface {}'.format(interface), 'tcp_fingerprint')

    try:
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
        read_timeout = 0
        preader = pcapy.open_live(interface, max_bytes, promiscuous, read_timeout)
        preader.setfilter('tcp port 80 or tcp port 443')
    except Exception as e:
        print(e, end='\n', flush=True)
        sys.exit(1)

    while True:
        try:
            (header, buf) = preader.next()
            if header and buf:
                ts = header.getts()[0]
                packetReceived = time.perf_counter()
                pkt = None
                # try to determine what type of packets we have, there is the chance that 0x800
                # may be in the spot we're checking, may want to add better testing in future
                eth = ethernet.Ethernet(buf)
                if hex(eth.type) == '0x800':
                    pkt = eth

                lcc = linuxcc.LinuxCC(buf)
                if hex(lcc.type) == '0x800':
                    pkt = lcc

                if pkt:
                    if (pkt[ethernet.Ethernet, ip.IP, tcp.TCP] is not None):
                        tcpProcess(pkt, ts, packetReceived)

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            error_string = traceback.format_exc()
            log(str(error_string), 'tcp_fingerprint', level='ERROR')


# program entry point
try:
    opts, args = getopt.getopt(sys.argv[1:], "i:v:c:", [
                               'interface=', 'verbose'])
    proceed = False

    for opt, val in opts:
        if opt in ('-i', '--interface'):
            interface = val
            proceed = True
        if opt in ('-v', '--verbose'):
            verbose = True
        if opt in ('-n', '--writeAfter'):
            writeAfter = int(val)

    if (__name__ == '__main__') and proceed:
        # run the API thread
        run_api(fingerprints, timestamps)
        # run PCAP loop
        main()
    else:
        log('Need to provide a pcap to read in or an interface to watch',
            'tcp_fingerprint')
        usage()
except getopt.error:
    usage()
