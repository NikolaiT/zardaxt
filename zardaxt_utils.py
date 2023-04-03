import json
import os
from zardaxt_logging import log
import time

databaseLoaded = False
dbList = []
os_sample_count = {}


def maybe_load_database():
    global databaseLoaded
    global dbList
    if not databaseLoaded:
        # load fingerprints into database
        databaseFile = './database/newCleaned.json'
        with open(databaseFile) as f:
            dbList = json.load(f)
            for el in dbList:
                if el['os'] not in os_sample_count:
                    os_sample_count[el['os']] = 0
                os_sample_count[el['os']] += 1
            log(f'os_sample_count={os_sample_count}', 'zardaxt_utils')

        log('Loaded {} fingerprints from the database'.format(
            len(dbList)), 'zardaxt_utils')
        databaseLoaded = True


maybe_load_database()


def check_config_looks_good(config):
    required_config_keys = ['interface',
                            'api_server_ip', 'api_server_port', 'api_key']
    for key in required_config_keys:
        if key not in config:
            raise Exception('Missing required config key: {}'.format(key))


def load_config(config_path=None):
    actual_path = None
    if config_path and os.path.exists(config_path):
        actual_path = config_path
    else:
        actual_path = './zardaxt.json'
    if os.path.exists(actual_path):
        config = None
        with open(actual_path) as f:
            config = json.load(f)
        log('Loaded config from path {}'.format(
            actual_path), 'zardaxt_utils')
        check_config_looks_good(config)
        return config
    else:
        raise Exception('config_path {} does not exist'.format(actual_path))


def compute_ip_id(ip_id):
    if ip_id == 0:
        return 0
    else:
        return 1


def getTcpTimestamp(tcp_ts):
    return 0 if tcp_ts == "" else 1


def compute_near_ttl(ip_ttl):
    """Interpolate the assumed initial TTL by the TTL we see on our interface.

    Why do we do that? The initial TTL depends on the OS.

    References:
    - https://ostechnix.com/identify-operating-system-ttl-ping/
    - https://superuser.com/questions/1345113/why-there-are-different-default-values-of-ttl-used-by-different-operating-system

    The default initial TTL value for Linux/Unix is 64, and TTL value for Windows is 128.
    In today's age, packets arrive at most of their destinations after no more than 10-15 hops.
    Therefore, we cannot distinguish initial TTL's such as 60 or 64.

    Args:
        ip_ttl (int): the seen TTL on the interface

    Returns:
        int: The assumed initial TTL
    """
    guessed_ttl_start = ip_ttl

    if ip_ttl >= 0 and ip_ttl <= 32:
        guessed_ttl_start = 32
    elif ip_ttl > 32 and ip_ttl <= 64:
        guessed_ttl_start = 64
    elif ip_ttl > 64 and ip_ttl <= 128:
        guessed_ttl_start = 128
    elif ip_ttl > 128:
        guessed_ttl_start = 255

    return guessed_ttl_start


# TCP control flags
TH_FIN = 0x01		# end of data
TH_SYN = 0x02		# synchronize sequence numbers
TH_RST = 0x04		# reset connection
TH_PUSH = 0x08		# push
TH_ACK = 0x10		# acknowledgment number set
TH_URG = 0x20		# urgent pointer set
TH_ECE = 0x40		# ECN echo, RFC 3168
TH_CWR = 0x80		# congestion window reduced


def get_tcp_flags(tcp_pkt):
    tcp_flags = []
    if tcp_pkt.flags & TH_FIN:
        tcp_flags.append('FIN')  # end of data
    if tcp_pkt.flags & TH_RST:
        tcp_flags.append('RST')  # reset connection
    if tcp_pkt.flags & TH_SYN:
        tcp_flags.append('SYN')  # synchronize sequence numbers
    if tcp_pkt.flags & TH_ACK:
        tcp_flags.append('ACK')  # acknowledgment number set
    if tcp_pkt.flags & TH_PUSH:
        tcp_flags.append('PUSH')  # push
    if tcp_pkt.flags & TH_URG:
        tcp_flags.append('URG')  # urgent pointer set
    if tcp_pkt.flags & TH_ECE:
        tcp_flags.append('ECE')  # ECN echo, RFC 3168
    if tcp_pkt.flags & TH_CWR:
        tcp_flags.append('CWR')  # congestion window reduced

    return ' '.join(tcp_flags)


def compute_near_timestamp_tick(hertz_observed):
    """
    Guess what the TCP timestamp tick must have been from measurements

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


def score_fp(fp):
    """The most recent version of TCP/IP fingerprint scoring algorithm.

    Args:
        fp (dict): The fingerprint to score

    Returns:
        avg_os_score: average score of this fingerprint for all OS
    """
    global dbList
    # Hardcoded for performance reasons
    os_scores = {
        'Android': 0,
        'Windows': 0,
        'Mac OS': 0,
        'iOS': 0,
        'Linux': 0
    }
    for entry in dbList:
        score = 0
        os_name = entry['os']
        if entry['ip_id'] == fp['ip_id']:
            score += 1.5
        if entry['ip_tos'] == fp['ip_tos']:
            score += 0.25
        if entry['ip_total_length'] == fp['ip_total_length']:
            score += 2.5
        if entry['ip_ttl'] == fp['ip_ttl']:
            score += 2
        if entry['tcp_off'] == fp['tcp_off']:
            score += 2.5
        if entry['tcp_timestamp_echo_reply'] == fp['tcp_timestamp_echo_reply']:
            score += 2
        if entry['tcp_window_scaling'] == fp['tcp_window_scaling']:
            score += 2
        if entry['tcp_window_size'] == fp['tcp_window_size']:
            score += 2
        if entry['tcp_flags'] == fp['tcp_flags']:
            score += 0.25
        if entry['tcp_mss'] == fp['tcp_mss']:
            score += 1.5
        if entry['tcp_options'] == fp['tcp_options']:
            score += 4
        elif entry['tcp_options_ordered'] == fp['tcp_options_ordered']:
            score += 2.5
        os_scores[os_name] += score

    avg_os_score = {}
    for os_name in os_scores:
        avg_os_score[os_name] = round(
            os_scores[os_name] / os_sample_count[os_name], 2)

    return avg_os_score


def normalize_fp(fp):
    """
    Normalize the fingerprint.
    """
    new_fp = fp.copy()
    new_fp["ip_ttl"] = compute_near_ttl(new_fp["ip_ttl"])
    new_fp["ip_id"] = compute_ip_id(new_fp["ip_id"])
    new_fp["tcp_timestamp"] = getTcpTimestamp(new_fp["tcp_timestamp"])
    new_fp["tcp_timestamp_echo_reply"] = getTcpTimestamp(
        new_fp["tcp_timestamp_echo_reply"])
    return new_fp


def make_os_guess(fp):
    """
    Return the highest scoring TCP/IP fingerprinting match from the database.
    If there is more than one highest scoring match, return all the highest scoring matches.

    As a second guess, output the operating system with the highest, normalized average score.
    """
    norm_fp = normalize_fp(fp)
    avg_os_score = score_fp(norm_fp)
    return {
        'avg_score_os_class': avg_os_score,
        'fp': fp,
        'details': {
            'os_highest_class': max(avg_os_score, key=avg_os_score.get),
            'highest_os_avg': max(avg_os_score.values()),
            'perfect_score': 20.5
        }
    }


def perf():
    # using the TCP/IP fingerprints that didn't add any entropy as a
    # test corpus to check the performance
    some_fps = json.load(open('database/duplicates.json', 'r'))
    some_fps = some_fps
    N = len(some_fps)
    t0 = time.time()
    for fp in some_fps:
        avg_os_score = score_fp(fp)
        # print(fp['os'], avg_os_score)
    t1 = time.time()
    totalMs = round((t1-t0) * 1000, 2)
    perScoreMs = round(totalMs/N, 3)
    print(N, totalMs, perScoreMs)


if __name__ == '__main__':
    perf()
