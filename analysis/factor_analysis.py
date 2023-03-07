import json
import math
import random

all_keys = ['ip_checksum', 'ip_df', 'ip_hdr_length', 'ip_id',
            'ip_mf', 'ip_off', 'ip_protocol', 'ip_rf', 'ip_tos',
            'ip_total_length', 'ip_ttl', 'ip_version', 'tcp_ack', 'tcp_checksum',
            'tcp_flags', 'tcp_header_length', 'tcp_mss', 'tcp_off', 'tcp_options',
            'tcp_seq', 'tcp_timestamp', 'tcp_timestamp_echo_reply', 'tcp_urp',
            'tcp_window_scaling', 'tcp_window_size']
exclude_vars = ['ip_checksum', 'tcp_checksum', 'tcp_seq']


def gos(os_name, reduce_classes=False):
    """
    Unix-Like: Android and Linux
    Apple-Like: iOS and Mac OS

    Args:
        os_name (str): The detailed operating system

    Returns:
        str: The clustered operating system
    """
    if reduce_classes:
        if os_name in ["Android", "Linux"]:
            return 'Unix-Like'
        if os_name in ["Mac OS", "iOS"]:
            return 'Apple-Like'
    return os_name


def get_var_value(var, entry, assume_ttl=False):
    value = entry[var]
    if var == 'ip_id':
        value = compute_ip_id(entry['ip_id'])
    if assume_ttl and var == 'ip_ttl':
        value = compute_near_ttl(entry['ip_ttl'])
    if var == 'tcp_timestamp':
        value = compute_tcp_timestamp(entry['tcp_timestamp'])
    return value


def create_histogram_for_var(training, var):
    histogram = {}
    for entry in training:
        value = get_var_value(var, entry)
        _os = gos(entry['os_name'])
        if not histogram.get(_os):
            histogram[_os] = {}
        if not histogram[_os].get(value, False):
            histogram[_os][value] = 0
        histogram[_os][value] += 1

    return histogram


def compute_tcp_timestamp(tcp_timestamp):
    if isinstance(tcp_timestamp, int) and tcp_timestamp > 0:
        return 1
    elif tcp_timestamp == '':
        return 0
    else:
        raise Exception(
            'Invalid tcp_timestamp value: {}'.format(tcp_timestamp))


def compute_ip_id(ip_id):
    if ip_id == 0:
        return 0
    else:
        return 1


def compute_near_ttl(ip_ttl):
    guessed_ttl_start = ip_ttl

    if ip_ttl > 0 and ip_ttl <= 32:
        guessed_ttl_start = 32
    elif ip_ttl > 32 and ip_ttl <= 64:
        guessed_ttl_start = 64
    elif ip_ttl > 64 and ip_ttl <= 128:
        guessed_ttl_start = 128
    elif ip_ttl > 128:
        guessed_ttl_start = 255

    return guessed_ttl_start


def get_learning_data(data, threshold=.8):
    num_training = math.floor(len(data) * threshold)
    # we have the same amount of data for each class
    # just shuffle, this will be good enough
    # {'Android': 2501, 'Linux': 2501, 'Mac OS': 2501, 'Windows': 2501, 'iOS': 2501}
    random.shuffle(data)
    return data[: num_training], data[num_training:]


def main():
    data = []
    databaseFile = 'data.json'
    with open(databaseFile) as f:
        data = json.load(f)

    training, testing = get_learning_data(data, threshold=0.7)
    scores = {}
    for var in all_keys:
        if var in exclude_vars:
            continue
        # create a histogram for this variable
        hist = create_histogram_for_var(training, var)
        # now create a score with the training data
        score_sum = 0
        num = 0
        for entry in testing:
            _os = gos(entry['os_name'])
            value = get_var_value(var, entry)
            if hist[_os].get(value, False):
                num += 1
                # special case: With some header fields such as
                # ip_checksum, tcp_checksum or tcp_seq, the variables
                # have maximum entropy. Put differently: The instance space is
                # uniformly distributed, regardless of OS. Exclude those variables from analysis.
                freq_correct = hist[_os][value]
                freq_total = 0
                for os_key in hist:
                    if hist[os_key].get(value, False):
                        freq_total += hist[os_key][value]
                score_sum += (freq_correct / freq_total)

        if num:
            score = round(score_sum/num, 3)
            scores[var] = score

    final = list(
        sorted(scores.items(), key=lambda item: item[1], reverse=True))
    for var, score in final:
        print(var, score)


main()
